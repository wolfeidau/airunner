# Plan: Job lifecycle and tenancy redesign (greenfield schema)

[Repository guidance](../AGENT.md)

Revised 2026-10-18 after repository review and primary-source research, then simplified: PostgreSQL is the only job backend, a slim reference model serves as the contract-test oracle, events are retained by job age, and WAL failure handling deletes rather than quarantines. This document specifies future work; it does not implement the feature or reset a database.

## Problem and scope

Jobs need an organization boundary, recoverable leases, separate attempt logs, and bounded retention. A worker crash must permit redelivery without allowing an old worker to mutate the new attempt. Successful completion must follow durable acknowledgement of that attempt's events.

**Repository evidence**, checked during this review:

- [The PostgreSQL store](../internal/store/postgres/job_store.go) writes event TTLs without a retention loop, does not reclaim expired leases, and inserts events without checking the current receipt handle. Event keys contain no attempt. Its live event subscribers are process-local.
- [Migration 1](../internal/store/postgres/migrations/1_initial_schema.sql) indexes `state = 0`, whereas [the proto](../api/job/v1/job.proto) defines SCHEDULED as 1. Jobs and request IDs have no organization scope.
- [The job handlers](../internal/server/job.go) and [event handlers](../internal/server/job_event.go) do not pass authenticated caller identity to the store. Existing JWT/session middleware supplies that identity.
- [The executor](../internal/worker/worker.go) returns at ProcessEnd before later container cleanup events and has no ProcessError dispatch case. [The CLI worker](../cmd/cli/internal/commands/worker.go) closes the publish stream before flushing its WAL, continues after final-response errors, and only logs heartbeat errors.
- [The WAL](../internal/worker/wal/wal.go) opens files by job ID alone. [Its sender](../internal/worker/wal/sender.go) marks records sent after transport Send succeeds, before a server commit acknowledgement.
- [Server startup](../cmd/server/internal/commands/server.go) starts the memory store twice. Session expiry deletion has no scheduled caller.

The original draft's local database audit and earlier investigations are historical inputs, not measurements repeated for this revision.

**Constraints and decisions:**

- The project is undeployed. Rewrite the initial schema without backfill or compatibility migration. Protocol compatibility is not required.
- PostgreSQL is the only job backend. Remove `memorystore.NewJobStore` and the server's memory backend branch, currently the default in [server startup](../cmd/server/internal/commands/server.go); the default becomes `postgres`. Jobs reference organizations and principals by foreign key, so the memory principal, organization, and session stores also leave server wiring; they may remain only as test fakes for tests that never touch jobs, such as [login tests](../internal/login/login_test.go). Local development uses Compose PostgreSQL.
- Retain terminal jobs for 90 days and their events for 30 days after the job finishes, both by default. There is no per-event TTL. Include cancellation.
- Implement at-least-once delivery with at most `max_attempts` lease acquisitions, not exactly-once execution. Explicit command failure is terminal; automatic retries cover expired leases and failed delivery releases. Visibility extensions and dead-letter handling are established queue patterns; see [Amazon SQS visibility timeout guidance](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html). This project adds database fencing and chooses its own attempt policy; SQS defaults and limits do not apply.
- Use bounded unary event publication, attempt-specific WALs, transactional fencing, and database polling for event streams. Decisions and alternatives are recorded below with research provenance.
- Define an independent pure-Go lifecycle reference model and use it as the contract suite's oracle. Keep it internal and test-only.
- Produce the layered specification first, then implement its phases.

## Contracts and verification model

The highest-risk rules cross the store, worker, WAL, and RPC boundaries. State them once as an executable model, then check the PostgreSQL store against that model. This is a focused test investment, not a general workflow framework or a requirement for formal proof.

### 1. Lifecycle reference model

Create a small test-only model in `internal/store/storetest/`. Its inputs are a normalized command, current job state, caller identity, receipt, and explicit acceptance time. Its result is the next state and observable outcome, or a rejection that leaves state unchanged. It has no PostgreSQL, Connect, filesystem, goroutine, or wall-clock dependencies. Pass generated job/receipt identities explicitly so command histories can be replayed.

Model enqueue, acquire, renew, release, expire, cancel, publish, and complete. Keep the model's state limited to what the contract needs: organization and creator, lifecycle state, attempt/max_attempts, lease owner/receipt/deadline, terminal outcome, and committed event prefix. Model cancellation from the start even though its production implementation arrives in phase 6.

Check invariants after every command, including rejected commands:

- Terminal states never reopen; every successful acquisition consumes exactly one new attempt and receipt, and attempts never exceed the limit.
- Only the current leasing principal in the correct organization with a matching receipt and unexpired lease can perform a token mutation. A correctly signed stale token is still unauthorized.
- Expiry and release use the same exhaustion policy. Lease columns exist exactly when state is RUNNING; a rejected mutation changes neither the lease nor the log.
- Completion can name only the committed event prefix. A new attempt starts its own prefix and cannot inherit another attempt's records.

Keep this model independent of production transition helpers and SQL predicates. Test adapters may translate requests/results and normalize nondeterministic IDs, but they must not recompute expected behavior using the implementation under test.

### 2. Event publication contract

Specify the attempt log as a scoped sequence of immutable records. Inputs include the lease identity, record identities/content/ranges, and explicit acceptance time. Outputs distinguish committed acknowledgement, conflict, rejection, and unknown outcome caused by losing the response.

The essential properties are contiguous new appends, identical retries without new effects, conflict on changed content under an existing identity, atomic batches, correct output-range accounting, and completion after the acknowledged prefix. A server commit and the worker learning about that commit are separate events. A lost response changes the worker's knowledge, not the server's committed log.

Include this contract in the reference model. Do not introduce a second production event store or a generic message-delivery abstraction.

### 3. Worker-side failure tests

Test the WAL sender and renewal controller directly, through narrow dependencies: a fake receiver that implements the event contract and an injectable clock. Extend the existing [WAL sender seam](../internal/worker/wal/wal.go) so success means committed acknowledgement. The fake receiver can commit and drop its reply, fail before commit, return a duplicate or wrong-attempt acknowledgement, or answer after the local lease deadline. Assert that pending records advance only on a valid acknowledgement and that an aborted execution never resumes. Corruption, file locking, fsync behavior, and actual process termination still require filesystem/process integration tests.

### Verification layers

1. **Model tests:** hand-written boundary histories plus seeded random command sequences check the lifecycle and log invariants. Include exact-expiry boundaries, repeated release, cancellation during publication, output ranges, changed-content retries, and cross-org/cross-worker operations.
2. **Differential replay:** replay a bounded set of seeded histories (default 200, configurable) against a PostgreSQL testcontainer and compare outcome and state with the model after every step. Save failing seeds as regression cases. When the model and PostgreSQL disagree, review the written contract; neither is automatically correct.
3. **Concurrency:** use controlled barriers to race publish against cancel, completion, release, and reaping. A cancel that completes before a publish begins must prevent that publish; overlapping operations may serialize either way under the acceptance-point rule below.

An optional `FuzzJobContract` target explores the model for longer runs; it is not a phase gate. Passing finite tests provides evidence, not an exhaustive proof.

Separate safety properties (for example, no stale-owner write) from eventual progress. Redelivery and cleanup require advancing time, available storage, scheduled maintenance, and opportunities to execute. Exercise those assumptions explicitly in tests; do not claim unconditional progress under partition, suspension, or permanent storage failure.

## Schema and invariants

Squash migrations 1–3 into [internal/store/postgres/migrations/1_initial_schema.sql](../internal/store/postgres/migrations/1_initial_schema.sql). Create the migration tracking table, organizations, principals including the profile columns from migration 3, sessions, jobs, then job_events in dependency order. Preserve identity/session behavior. Delete migrations 2 and 3 and record only version 1. [The migration runner](../internal/store/postgres/migrations.go) already discovers numbered files; verify fresh application and repeat startup. An old database with version 1 recorded must be reset before using this schema.

**Jobs:**

- Add `org_id UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE`, `created_by UUID NOT NULL REFERENCES principals(principal_id)`, and `leased_by UUID REFERENCES principals(principal_id)`.
- Add `attempt INT NOT NULL DEFAULT 0`, `max_attempts INT NOT NULL`, and `last_event_sequence BIGINT NOT NULL DEFAULT 0`. Enforce `0 <= attempt AND attempt <= max_attempts`, `1 <= max_attempts AND max_attempts <= 100`, and `last_event_sequence >= 0`.
- `state` has no default and must be between 1 and 5, matching the proto. `RUNNING` requires all lease columns (`visibility_until`, `receipt_handle`, `leased_by`) set; all other states require all three NULL. `RUNNING` also requires `attempt > 0`.
- Replace global request uniqueness with `UNIQUE (org_id, request_id)`. Add `request_fingerprint BYTEA NOT NULL`: SHA-256 of the normalized enqueue intent (queue, `job_params`, `execution_config`, and requested max-attempts or "omitted"). Retrying the same request ID with a different fingerprint returns an explicit conflict; do not silently reuse another request's job. Omitted max-attempts remains equivalent to omitted on retry even if server defaults later change.
- Reset `last_event_sequence` to zero when allocating a new attempt. Clear the previous result then; populate a reason on terminal failure from exhausted delivery attempts.
- Every transition updates `updated_at` using server time. Only terminal rows are eligible for job retention. Store methods verify that creator and leasing principals belong to the supplied org; caller IDs are supplied by trusted authentication, never by request fields.

**Job events:**

- Add `attempt INT NOT NULL CHECK (attempt > 0)` and `end_sequence BIGINT NOT NULL`.
- Primary key: `(job_id, attempt, sequence)`; retain the cascading job foreign key. There is no `ttl` column; event retention follows the parent job's age.
- Require `sequence > 0` and `end_sequence >= sequence`. A normal event covers one sequence; an output batch covers `[start_sequence, end_sequence]`, with JobEvent.sequence equal to its start. Validate the range against the output count at the store boundary.
- Store server-stamped attempt in both columns and serialized payload. Worker timestamp and content are immutable once appended to the WAL; missing timestamps are rejected rather than regenerated on retry.

**Indexes:**

- `idx_jobs_dequeue (org_id, queue, created_at, job_id) WHERE state = 1`
- `idx_jobs_lease (visibility_until, job_id) WHERE state = 2`
- `idx_jobs_list (org_id, queue, state, created_at, job_id)`
- `idx_jobs_retention (updated_at, job_id) WHERE state IN (3,4,5)`
- Adjust existing timestamp/type indexes to include attempt where useful; remove the duplicate request-ID index.

Use literal state predicates in dequeue/reaper/retention SQL so generic prepared plans can prove the partial-index predicates. `created_at, job_id` provides deterministic oldest-first ordering among available rows; SKIP LOCKED does not promise strict global FIFO under contention. See [partial indexes](https://www.postgresql.org/docs/current/indexes-partial.html) and [SELECT locking](https://www.postgresql.org/docs/current/sql-select.html).

## Tenancy, authorization, and errors

The server extracts `auth.PrincipalFromContext` and passes `store.Caller{OrgID, PrincipalID}` to every caller-facing JobStore method. Start/Stop and maintenance sweeps are internal operations without a caller. Scope every query, mutation, request-ID lookup, and stream by org; queues are `(org_id, queue)`.

A single job-service authorization interceptor maps generated RPC procedure constants to roles. Implement both unary and streaming handler interception using the repository's Connect v1 APIs, without upgrading Connect as part of this work. Keep JWT/session authentication ahead of authorization. Unknown job-service procedures fail closed; existing non-job services retain their own authorization behavior. Never allow a request to set caller identity.

| RPC | user | worker | admin |
|---|---|---|---|
| EnqueueJob, ListJobs, StreamJobEvents, CancelJob | yes | | yes |
| DequeueJob, UpdateJob, CompleteJob, PublishJobEvents | | yes | yes |

Admin is organization-scoped. A worker role does not confer access to another worker's lease, including when the caller is an admin. Processes sharing one principal are the same authorization identity; use separate worker credentials where worker-to-worker isolation is needed.

**Error precedence:**

1. Missing principal: Unauthenticated. Missing required role: PermissionDenied before store access.
2. Malformed request/token or invalid range: InvalidArgument. Oversized publish request: ResourceExhausted.
3. A direct-ID stream/cancel lookup outside the caller's org returns `ErrJobNotFound` → NotFound, indistinguishable from an absent job. List returns an empty scoped page. Dequeue sees no jobs from that org and continues its normal long poll until cancellation/deadline.
4. For a syntactically valid, correctly signed task token, an absent job, another org, wrong leasing principal, old receipt, terminal state, or expired lease returns `ErrLeaseLost` → FailedPrecondition. Do not expose which check failed. Duplicate payload/intent conflicts use `ErrConflict` → AlreadyExists, distinct from lease loss.
5. Infrastructure and deadline errors retain their appropriate status. Use a shared mapper across job/event handlers; do not map every store error to InvalidArgument or Internal.

**Development identity:** in `--no-auth` mode only, seed fixed development org/principal IDs idempotently in PostgreSQL before accepting requests. A reserved user principal with a nonempty development GitHub ID, NULL fingerprint, and all roles satisfies current schema constraints without a fake signing credential. Create the org with that owner ID, then its principal in one transaction; the existing owner column has no circular FK. Fail startup on conflicting reserved identities. Middleware injects that principal. Authenticated startup does not seed or accept this bypass.

## Lease contract and bounded attempts

```text
Enqueue -> SCHEDULED (attempt=0)
SCHEDULED -> dequeue if attempt < max_attempts -> RUNNING (attempt++, new receipt, caller, lease)
RUNNING -> CompleteJob -> COMPLETED or FAILED
RUNNING -> ReleaseJob or expiry -> SCHEDULED if attempt < max_attempts; otherwise FAILED
SCHEDULED or RUNNING -> CancelJob -> CANCELLED
```

Every lease acquisition consumes an attempt, even when the response cannot be delivered. Never decrement/reuse an attempt or receipt. Release and the reaper apply the same exhaustion rule, and dequeue independently guards the bound. Release after expiry fails fencing; the reaper owns that recovery. All non-RUNNING transitions clear the lease columns. Cancel is idempotent for CANCELLED; COMPLETED/FAILED returns FailedPrecondition without changing the result. No transition out of a terminal state is allowed.

Dequeue may acquire several jobs. If delivery fails, release the failed item and all remaining unsent items using bounded cleanup contexts; already delivered items retain their leases. This prevents undelivered batch items remaining unnecessarily leased.

**Task tokens:** retain the HMAC-signed format containing job ID, queue, and receipt. Organization, attempt, and worker binding come from the locked database row. Remove `UpdateJobRequest.queue`; reserve its old field number/name. Never log raw tokens.

### Atomic fencing and time

All task-token operations (UpdateJob, CompleteJob, ReleaseJob, PublishJobEvents) use one transaction in PostgreSQL:

1. Verify token signature/structure, then acquire the job row with `SELECT ... WHERE org_id = caller.org AND job_id = token.job FOR UPDATE` at READ COMMITTED isolation.
2. After acquiring the lock, sample `clock_timestamp()` once as `operation_time`. Verify receipt, queue, leasing principal, RUNNING state, and `visibility_until > operation_time`. Equality is expired. A missing row gives ErrLeaseLost.
3. Derive the attempt from the locked row and perform the entire mutation, including all event inserts and sequence accounting, in this transaction. Renew to `operation_time + effective_timeout`.
4. Return success only after commit. On any validation/commit failure, acknowledge nothing. No network calls occur while holding the row lock.

Cancel, release, completion, dequeue, and reaping serialize on the same job row. Publication accepted under a valid lease may commit after its wall-clock expiry while holding that lock; cancellation/reclamation cannot commit ahead of it. This is the explicit acceptance point, not a claim that every commit precedes expiry. Bound each store operation, including lock waits and commit, by 5s or the shorter caller deadline; configure PostgreSQL statement/lock timeouts as well.

**Research basis:** row locks are held until transaction end, and `now()` represents transaction start while `clock_timestamp()` samples actual current time. Waiting on a lock must not validate against a stale transaction-start time. See [PostgreSQL row locks](https://www.postgresql.org/docs/current/explicit-locking.html) and [time functions](https://www.postgresql.org/docs/current/functions-datetime.html). The lock scope and acceptance point above are project decisions.

**Reaper:** run an immediate sweep at Start, then every 5s. Select up to 100 expired RUNNING rows ordered by expiry/job ID with `FOR UPDATE SKIP LOCKED`, revalidate expiry under the lock, apply the exhaustion rule, and clear leases. Process at most 10 batches per tick, then yield; remaining work waits for the next tick. Rollback/errors are reported and retried on the next tick. Multiple replicas may sweep safely. Expose expired-lease backlog/oldest-age metrics; five seconds is a polling interval, not a guaranteed redelivery bound under overload or database failure.

## Durable event publication and per-attempt WAL

### Unary batches and acknowledgements

Change the existing PublishJobEvents RPC to unary, keeping its name and request event list. It returns `{attempt, acknowledged_through_sequence}` only after the fenced batch transaction commits. This removes long-lived stream ownership/reconnection and CloseAndReceive from the worker and executor constructor.

**Research basis:** client streaming has one final server response after the request stream closes; individual sends are not application commit acknowledgements. See [Connect streaming](https://connectrpc.com/docs/go/streaming/). Unary batches add request overhead but give each bounded batch one commit acknowledgement with simpler recovery. A bidirectional acknowledgement protocol is deferred until measurements justify it.

- Limit a request to 50 JobEvent records and 1 MiB of uncompressed encoded request data, including its envelope; keep the existing 350 KiB per-event limit. Validate limits before opening the transaction. A single output-batch record counts as one event for this limit; the existing output-item batching remains.
- The WAL sender sends one batch at a time, in sequence order. Split requests on both byte and record limits; never split a serialized output-batch record. Retries reuse identical timestamps, ranges, content, and token. Require `event.attempt` to match the leased attempt; the server independently stamps it from the locked row.
- Under the job lock, new events must extend a contiguous prefix from `last_event_sequence + 1`. Identical existing records are successful no-ops. For each existing key compare normalized protobuf content/range, not just the key; different content is ErrConflict. Invalid gaps or overlapping ranges are InvalidArgument and roll back the entire request.
- Update `last_event_sequence` atomically with inserts. Return the last covered sequence of this request, including output-batch end ranges. Do not emit duplicate notifications for duplicate rows. The sender validates the acknowledged attempt/range before marking those WAL records acknowledged.
- A timeout or lost response leaves records pending. Retry with capped exponential backoff and jitter while the lease budget permits. If the first commit succeeded, an identical retry receives the same acknowledgement. Fence validation still runs on duplicate retries; an expired lease never regains write authority.
- Permanent validation/conflict errors stop publication and fail the attempt; they are not retried indefinitely. Lease-loss errors enter the worker abort path. A crash after server commit but before recording the local acknowledgement may cause a harmless duplicate retry, never skipped pending records.

**Research basis:** idempotent requests need stable caller intent and atomic recording of the identity with its effects. See [AWS Builders' Library: making retries safe](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/). Applying `(job, attempt, sequence)` plus content validation is this project's decision.

### WAL identity, lifecycle, and loss boundary

- Use `<wal-dir>/<job-id>/<attempt>.wal`, and persist `{format_version, job_id, attempt}` in the WAL header. Attempts are never reused, so `(job_id, attempt)` is unique; the worker learns the attempt from `DequeueJobResponse.job.attempt` and needs neither the org ID nor the receipt. Do not embed the bearer token. Reject path/header mismatches and concurrent ownership of the same WAL using a local file lock.
- A new dequeue always creates a new WAL and sequence space starting at 1. Never load another attempt's records into a new token's sender. Record attempt before the fsynced append. The WAL sender must preserve producer event sequences, including output-batch ranges. Unreadable/corrupt pending records fail publication explicitly; never skip them and acknowledge later records.
- On worker-process restart, delete WAL files the worker can lock and that no live execution owns, logging job ID, attempt, and pending record count. Never touch files owned by another live process. Never restart the old command or upload its records with a new lease. In-process retries may continue the same WAL only while that execution still owns a confirmed lease. Legacy job-ID-only files are deleted because they cannot prove attempt identity.
- On confirmed lease loss or local lease-budget exhaustion, cancel execution, stop/join the sender, close the WAL, log the unacknowledged record count, and delete the file. Do not retry the records or complete/release through the stale lease. An optional `--keep-failed-wal=24h` keeps such files for diagnosis instead; the worker prunes expired ones at startup.
- Fully acknowledged WALs are removed only after confirmed completion. If completion's response is lost, keep the file as diagnostic data under the same pruning rule; never re-execute on the strength of that file. Terminal-state fencing still rejects later token mutations.
- This supersedes tokenless orphan uploads proposed in [wal-execution-isolation.md](wal-execution-isolation.md). Mark that document superseded during the documentation phase; no job-ID/source-tag bypass is allowed.

Committed events survive worker loss. Unacknowledged local events can be lost when a lease expires or the worker disk is lost. This is a deliberate boundary: do not promise zero event loss across a worker crash and expired lease. Recovering historical local records after expiry would need a separate authorized, attempt-scoped archival API, outside this plan.

### Execution completion order

Keep lease renewal running through publication and completion:

1. Drain the iterator after ProcessEnd, retaining its exit status; dispatch ProcessError as a recorded event and execution failure. Later iterator/cleanup errors also fail execution. Missing ProcessEnd is a failure.
2. Stop the batcher, flush remaining output to the WAL, and propagate append/fsync/timer-flush failures to the execution outcome instead of logging and continuing. Split oversized output chunks before batching; never silently drop output on a size error.
3. Flush all WAL records through committed unary acknowledgements within the lease and a bounded 30s final-flush budget. The sender owns all publication; no second stream exists.
4. Add `CompleteJobRequest.final_event_sequence`. Complete only after no pending records remain. Under the same fence, the store requires equality with `last_event_sequence`; this includes output-batch ranges. On a permanent recording/publication error, report FAILED using the acknowledged prefix and an explicit diagnostic; do not claim the full log was captured. On transient flush exhaustion with unacknowledged records, stop execution/renewal and let expiry recover the attempt rather than marking it successfully complete. If the final flush fails transiently after the command has exited, the attempt expires and the job is redelivered: this deliberately re-runs a finished command, in exchange for never marking a job complete with unacknowledged events.
5. Stop/join renewal and WAL tasks after completion, or immediately on lease loss. Cleanup must not send another final batch through a revoked lease.

## Event streaming across attempts and replicas

Use the persisted event log as the source for both replay and tailing. Replace process-local fanout delivery with paginated polling (default 500ms, 100 records per query). Local notifications may wake polling early later, but correctness must never depend on them or on LISTEN/NOTIFY.

**Project judgment:** polling is sufficient for this undeployed system and avoids a shared broker and notification recovery protocol. It costs database queries and adds up to one polling interval to normal delivery. Measure active streams, query rate, and tail lag before considering a different transport.

- Add `StreamJobEventsRequest.attempt`: positive selects exactly that attempt; zero resolves once to `max(1, jobs.attempt)` under an org-scoped read. Zero pins the latest started attempt, or waits for the first attempt when no execution has started. It does not silently follow retries. An attempt greater than `max(1, jobs.attempt)` is InvalidArgument.
- Include `resolved_attempt`, `job_state`, and `attempt_closed` in StreamJobEventsResponse, including an initial status response with no event and a final status response. `attempt_closed` describes the selected attempt even if job_state is RUNNING for a later one. Consumers must handle status-only responses. The UI can discover/select the latest attempt through ListJobs and reopen; add `monitor --attempt` for explicit CLI selection.
- `from_sequence` is inclusive; zero starts at the beginning. If it falls inside an output-batch range, send that whole record. Resume at the last delivered covered end + 1 with the resolved positive attempt. `from_timestamp` and event-type filters apply equally to history and tail.
- Fetch ordered committed records and advance the internal scan cursor over filtered records. Never skip records because a channel is full. Use bounded pages and await downstream capacity with cancellation; slow streams may receive DeadlineExceeded after 30s without send progress and reconnect from their cursor.
- Observe job state/attempt before the final drain. An attempt is closed when it has started and the job is no longer RUNNING for that attempt, or when a later attempt exists. Cancellation before the first dequeue also closes its waiting stream. Once closed, fence rules prevent later inserts; drain remaining eligible records, send final status, then close. Do not use ProcessEnd as the stream termination signal.
- Event retention removes a finished job's events as a whole, so a job whose events were purged streams status only; do not fabricate missing records. Jobs deleted during a stream terminate with NotFound.
- Index UI event identity by `job_id-attempt-sequence`. Reset CLI gap tracking and output playback state on a newly selected attempt, and use batch end sequences for cursor movement.

## Heartbeats, partitions, and cancellation

Validate visibility duration in `[30s, 1h]`, with the existing 300s default. Add the effective duration to dequeue/update responses so workers use server-accepted values, not local defaults.

- On dequeue, immediately renew before executing. Each successful renewal establishes a conservative local deadline from the monotonic time captured **before sending that renewal request**, plus the accepted duration minus `max(2s, duration/10)`. A response arriving after that deadline is unusable. Do not initialize the execution budget from response-receipt time.
- Renew every duration/3 with jitter capped at ±25%. Bound each RPC to `min(5s, remaining local budget)`; retry transient failures within that budget with capped backoff. Keep an independent watchdog that aborts at the last confirmed deadline even while a renewal is blocked. A renewal response received after the previous confirmed deadline cannot revive that budget, even if the watchdog was delayed; abort and ignore it. No reply may reverse an abort decision.
- On FailedPrecondition, abort immediately. On repeated network failures or no valid initial renewal, abort by the local deadline, skip completion/release, and delete pending WAL records as described above. Cancel the job execution context, terminate its process group/container, stop/join sender tasks, and force termination after a 5s grace period.
- Use monotonic elapsed time for in-process budgets; serialized database timestamps are for diagnostics. A suspended or stalled process cannot guarantee timely termination. Fencing protects store mutations after resumption, not arbitrary external effects. Commands must use idempotency keys or downstream concurrency controls for effects that must not repeat.
- New CancelJob RPC and `airunner-cli cancel <job-id>` revoke SCHEDULED/RUNNING jobs under the job row lock. A connected worker detects cancellation on its next renewal. Detection bound is at most the maximum jittered interval plus one bounded RPC; shutdown adds up to the termination grace period. Under partition, the confirmed local lease deadline controls shutdown instead.
- Server delivery cleanup calls ReleaseJob with `context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)`, preserves caller identity, and always cancels that cleanup context. Release remains fenced and bounded.

**Research basis:** Go time values support monotonic elapsed-time comparisons, while WithoutCancel removes the parent's cancellation/deadline. See [Go time](https://pkg.go.dev/time#hdr-Monotonic_Clocks) and [Go context](https://pkg.go.dev/context#WithoutCancel). The safety margin, timing bounds, and abort policy are project defaults to validate with failure tests, not a distributed exactly-once guarantee.

## Retention, maintenance, and configuration

Run retention at startup and every hour. Each transaction processes at most 1,000 rows and each sweep at most 10 batches per category, with context cancellation between batches; resume on the next tick. Multiple replicas may sweep with SKIP LOCKED. Acquire job locks before deleting that job's events to keep lock ordering consistent with publication/cascading deletion.

- Delete events of COMPLETED/FAILED/CANCELLED jobs whose `updated_at` is older than the event retention cutoff, using `idx_jobs_retention` to find eligible jobs. Only terminal jobs qualify, so no live writer can need deleted records for retry deduplication. Event retention zero keeps events until the job itself is deleted.
- Delete COMPLETED/FAILED/CANCELLED jobs older than the configured terminal retention cutoff; cascade their events. Never delete SCHEDULED/RUNNING jobs through retention. Reject an event retention longer than job retention.
- Run session cleanup from the server with a bounded, cancellable sweeper. Extend DeleteExpired to take a batch limit and return the count, or give it an equivalent bounded batch implementation; the current unbounded implementation is insufficient. Request IDs may be reused after their job is deleted; idempotency lasts for job retention.
- Use server/DB time for cutoffs, never the event's client timestamp. Document eventual physical cleanup: deletion depends on sweep schedule, backlog, and database availability.
- Start is idempotent, Stop is idempotent, and restart after Stop returns an error. A shared lifecycle context cancels sweeps and streams; Stop joins them within 10s. The server owns the shared PostgreSQL pool and closes it only after job/session/auth tasks stop. Stream producers own channel closure, avoiding double closes and send/close races.

**Flags/defaults:** `--default-max-attempts=3`, `--lease-reaper-interval=5s`, `--job-retention-days=90`, `--events-retention-days=30` (replaces `--events-ttl-days`; zero keeps events for the job's lifetime), `--retention-interval=1h`, `--event-poll-interval=500ms`. Reject negative durations, invalid attempt limits, and nonpositive job-retention days. Worker: `--keep-failed-wal` (default 0, disabled).

**Metrics:** `jobs.redelivered`, `jobs.dead_lettered`, `jobs.lease_lost`, `jobs.cancelled`, `authz.denied`, `retention.{events,jobs,sessions}_deleted`; add sweep errors/duration/backlog age, event acknowledgement latency/retries/conflicts, active stream count/tail lag, WAL pending bytes, failed-WAL deletions, and local lease-budget aborts. Avoid per-job, token, and arbitrary queue labels.

## Deliverable 1: layered specification

Create `specs/job-lifecycle/` using [the layered template](LAYERED_SPEC_TEMPLATE.md), [CLI credentials](cli-credentials/README.md) as an existing navigation example, and [AGENT.md](../AGENT.md) standards. `specs/mtls/` is absent and must not be used as an available reference.

- `README.md`: scope, phase navigation, compatibility/reset constraints, completion criteria.
- `00-architecture.md`: schema, lifecycle, transaction acceptance point, unary acknowledgement contract, WAL identities, tenancy/errors, stream/cursor semantics, model inputs/invariants, verification limits, and source-backed decisions with alternatives.
- One phase file per implementation phase below (`01-phase1-worker-events.md` through `07-phase7-documentation.md`), with concrete success criteria and test commands.
- `operations-runbook.md`: dead-letter/expired-lease triage, cancellation timing, sweep backlog, failed WAL diagnostics, idempotency/retention limits, reproducible SQL audit queries, and an explicitly destructive opt-in local Compose reset procedure.
- `examples/`: schema SQL, fenced event transaction, bounded reaper/retention sweeps, authz interceptor, reference-model commands/invariants, and shared contract-test skeleton. Link all referenced files and source material.

## Deliverable 2: implementation phases

| Phase | Scope and completion gate | Main files | Depends on |
|---|---|---|---|
| 1 Worker events | Drain iterators through cleanup, handle ProcessError, preserve exit result, propagate batcher/WAL recording failures; deterministic iterator and output-boundary tests. Leave the transport rewrite to phase 4. | [executor](../internal/worker/worker.go), [batcher](../internal/worker/event_batcher.go) | none |
| 2 Schema and contract | Squash schema; proto generation including unary publish, CancelJob RPC and request/response types, attempt/status/cursor fields, effective lease durations and final sequence; Caller/errors. Delete the memory JobStore and memory server backend; move [server tests](../internal/server/server_test.go) and [batching integration tests](../internal/worker/batching_integration_test.go) to a shared PostgreSQL testcontainer helper. Adapt the server, client, UI status consumer, fixtures, and constructors. Implement required-column inserts/scans and org-scoped request-ID storage with fingerprints. Add the lifecycle reference model and differential replay harness; record which later-phase operations remain to be enabled. | [migrations](../internal/store/postgres/migrations/1_initial_schema.sql), [proto](../api/job/v1/job.proto), [store interface](../internal/store/job_store.go), new `internal/store/storetest/` | 1 |
| 3 Tenancy and lifecycle wiring | Authz on unary/streaming calls, trusted Caller propagation, complete org scoping, seeded dev identities, consistent errors, idempotent start and joined shutdown; tenancy/authz tests pass. | [auth](../internal/auth/), [server startup](../cmd/server/internal/commands/server.go), PostgreSQL store, handlers | 2 |
| 4 Fencing, durable events, and recovery | Atomic leases, all-path attempt bounds, WAL path/header/ownership and deletion on lease loss, committed unary acknowledgements, sequence accounting/completion gate, polling streams, worker watchdog and bounded cleanup, monitor/UI attempt selection. Before enabling redelivery: the WAL sender and renewal controller pass their fake-receiver tests, differential replay passes for implemented operations, and database/filesystem/process integration tests pass. | PostgreSQL store, [CLI worker](../cmd/cli/internal/commands/worker.go), [WAL](../internal/worker/wal/wal.go), [monitor](../cmd/cli/internal/commands/monitor.go), [dashboard](../ui/pages/dashboard.tsx) | 3 |
| 5 Retention | Bounded job-age event, job, and session sweeps, shared config, metrics and deterministic tests. | PostgreSQL store, [session contract](../internal/store/session_store.go), server startup, [metrics](../internal/telemetry/metrics.go) | 4 |
| 6 Cancellation | Store transition, handler, and CLI cancel command; cancellation histories in differential replay, including idempotency, publish/cancel races and connected/partitioned shutdown tests. RPC/types and role mapping already exist from earlier phases. | [job handler](../internal/server/job.go), PostgreSQL store, CLI commands | 5 |
| 7 Documentation | Update AGENT.md/README for JWT/session auth, tenancy, retention, lease/event guarantees, and the WAL loss boundary. Rewrite AGENT.md references to the absent `specs/mtls/`, mTLS auth, `internal/auth/authz.go`, `internal/store/store.go`, the memory development backend, and the event-partitioning claim. Mark the conflicting WAL isolation proposal superseded. Record infra as stale DynamoDB Terraform; rewriting it is out of scope. | [AGENT.md](../AGENT.md), [README](../README.md), [WAL isolation proposal](wal-execution-isolation.md), layered spec | 6 |

Execute phases sequentially because they change the same interfaces, stores, and startup paths. If implementers are later delegated, give each a committed predecessor and merge/review before the next phase; uncommitted edits are not shared into a new worktree. One Conventional Commit per phase, with rationale, compatibility impact, and meaningful verification in nontrivial commit bodies. Review every diff and rerun the phase gate before proceeding.

Do not reset Compose for testcontainers integration tests. Use isolated fresh test databases. A manual end-to-end run against the old Compose schema requires an explicitly selected local reset; `docker compose down -v` deletes its volumes and identities. Document the reset and re-bootstrap procedure separately from automated checks. Do not perform it merely to review or edit this plan.

## Verification and acceptance

For each implementation phase run `make lint`, `make test`, `make proto-lint`, and `make test-integration-postgres`. Regenerate Go/TypeScript clients with `make proto-generate` on proto changes; run repository TypeScript lint/build checks when changing UI consumers. Run focused Go race tests for store lifecycle, stream closure, sender shutdown, and publication/lease races. Pin integration tests to PostgreSQL 18, matching [Compose](../docker-compose.yml).

The fast model gate runs without Docker: `go test ./internal/store/storetest/...`. Differential replay against PostgreSQL runs inside `make test-integration-postgres`. The optional longer exploration is `go test ./internal/store/storetest -run='^$' -fuzz='^FuzzJobContract$' -fuzztime=60s`; ordinary tests replay its saved regression corpus. Do not put container startup inside the fuzz target.

Run `make proto-breaking` and record the exact expected incompatibilities: unary publish cardinality and removal/reservation of UpdateJobRequest.queue. Any additional incompatibility must be explained and reviewed; an expected failure is not permission to ignore all failures. Phase 2's generated changes and all fixtures must compile without placeholder callers or production bypasses.

**Store contract suite**, executed against PostgreSQL with explicit fixture timestamps and synchronization barriers rather than long sleeps or replacement of the database clock:

- Redelivery creates attempt 2 and a new receipt; every old-token operation returns ErrLeaseLost. Wrong worker in the same org and another org also fail; expired but unreaped leases cannot renew, publish, complete, or release.
- Repeated dequeue/release cannot exceed max_attempts. Final release and final expiry both end FAILED; explicit failed completion is terminal. Dequeue guards exhausted jobs. Failed multi-job delivery releases all undelivered items.
- Request IDs are unique per org, exact retries are stable, changed intent conflicts, and deletion ends the idempotency window. List/dequeue never expose another org; direct-ID stream/cancel returns NotFound. Verify all RPC error mappings.
- Publish is all-or-nothing; identical retries acknowledge without duplicate rows, changed payload conflicts, malformed ranges/gaps fail, and output-batch end sequences advance the prefix correctly. Completion with an unmatched final sequence fails.
- Use barriers to race publish with cancel, completion, release, and reaping. A publisher waiting past expiry validates the post-lock time and fails. A publisher accepted first may commit before a waiting revocation; one accepted after revocation never persists events.
- Subscribe before dequeue, pin latest, select a historical attempt, reconnect inside an output range, apply filters, cancel before first execution, and retry while subscribed. Verify final drain/status, expiry gaps, more than 100 records with a slow consumer, and cancellation during shutdown. For PostgreSQL, publish through one server instance and stream through another.
- Retention deletes events of terminal jobs past the event cutoff, never touches SCHEDULED/RUNNING jobs, cascades old terminal jobs, and batches sessions. Multiple sweepers do not double-count deletions; sweep cancellation does not leak tasks.
- Start twice/Stop twice produces one set of loops, cancellation releases blocked streams, and pool closure occurs after all shared users stop.

**Sender/controller and filesystem tests:** drive the real WAL sender and renewal controller with the fake receiver. Drop a response after commit and retry; fail before commit and retry; duplicate/misroute acknowledgements and deliver renewal responses after the deadline. Assert pending records remain pending until a valid acknowledgement and completion cannot overtake them. Cover batch limits, fsync/read failures, oversized output, sender restart, and shutdown during retry. Restart on the same WAL directory with a new attempt and verify old records enter neither its WAL nor its database namespace. Reject path/header mismatch and concurrent ownership; verify deletion on lease loss, `--keep-failed-wal` pruning, and no tokenless uploads. Use real files and process tests for the guarantees the fake receiver cannot establish.

**Authz tests:** cover every unary/streaming RPC, missing identity, every role, admin's org boundary, unknown job procedures, and no-auth seed idempotency/conflict behavior.

**Worker and end-to-end tests** on a fresh isolated database:

1. Bootstrap two orgs and distinct worker principals. Verify isolation and that a second same-org worker cannot reuse a token.
2. Kill a worker mid-job, restart on the same WAL directory, and verify attempt separation, redelivery, and final exhaustion. Also force repeated delivery failures/releases.
3. Disconnect a worker from the API during renewal/publication. Its watchdog cancels execution within the last confirmed budget; database writes after lease revocation fail. A later response cannot restart execution.
4. Assert ProcessEnd followed by ContainerRemove is fully recorded and acknowledged before completion for a successful container job. ProcessError, missing ProcessEnd, iterator error, and cleanup failure preserve the failure outcome.
5. Cancel running and scheduled jobs, including publish/cancel races. With connectivity, assert shutdown within `1.25 * effective_timeout/3 + renewal_rpc_timeout + 5s termination_grace`, allowing measured scheduler tolerance. Under partition use the local deadline bound; do not assert an unconditional timeout/3 promise.
6. Run the audits below after explicitly invoking and awaiting maintenance sweeps. Check representative EXPLAIN plans after ANALYZE, including generic prepared plans; a small fixture may legitimately choose a sequential scan. Benchmark dequeue/poll latency and query rate before claiming capacity.

## Reproducible SQL audits

These are replacement audit queries for the new schema, not a claimed reconstruction of the missing earlier session queries. Save a fixed test cutoff before running sweeps; concurrent new expiries must not cause flaky assertions. Apply the same fixed cutoff to maintenance hooks in tests. With backlog beyond the sweep budget, invoke additional sweeps until drained.

```sql
-- Event rows eligible for retention; $2 is the event retention in days.
SELECT count(*) FROM job_events e JOIN jobs j USING (job_id)
WHERE j.state IN (3,4,5)
  AND j.updated_at < $1::timestamptz - make_interval(days => $2::int);

-- Expired running leases as of the fixed sweep cutoff.
SELECT count(*), min(visibility_until) FROM jobs
WHERE state = 2 AND visibility_until <= $1::timestamptz;

-- Invariant violation: no lease acquisition beyond the configured bound.
SELECT job_id, attempt, max_attempts FROM jobs
WHERE attempt < 0 OR attempt > max_attempts OR max_attempts NOT BETWEEN 1 AND 100;

-- Eligible terminal jobs; $2 is the configured retention in days.
SELECT count(*) FROM jobs
WHERE state IN (3,4,5)
  AND updated_at < $1::timestamptz - make_interval(days => $2::int);

SELECT count(*) FROM sessions WHERE expires_at <= $1::timestamptz;

-- Inspect eligibility under the same literal state predicate as dequeue.
PREPARE audit_dequeue(uuid, varchar) AS
SELECT job_id FROM jobs
WHERE org_id = $1 AND queue = $2 AND state = 1 AND attempt < max_attempts
ORDER BY created_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED;
-- EXPLAIN (ANALYZE, BUFFERS) EXECUTE audit_dequeue('<org-uuid>', 'default');
-- Run once normally and once with plan_cache_mode = force_generic_plan.
DEALLOCATE audit_dequeue;
```

Prepared-statement parameters in the first five audit queries are bound by the test/SQL client. After a successful, fully drained sweep, eligible counts at its fixed cutoff should be zero. Track recurring backlog/age in production instead of asserting that expired rows can never exist between sweeps.

## Validated assumptions and repro tests

Checked 2026-10-18 on PostgreSQL 18 (Compose) before implementation.

**Experiment 1: partial index with a bound state parameter.** A 100,000-row temp table (1% SCHEDULED) with `(queue, created_at) WHERE state = 1` and `(queue, state)` indexes, queried with the current dequeue shape:

| Query form | `plan_cache_mode` | Plan |
|---|---|---|
| `state = $2` | `force_generic_plan` | Bitmap scan on `(queue, state)`, then Sort over 50,000 estimated rows |
| `state = 1` literal | `force_generic_plan` | Index scan on the partial index, no Sort |
| `state = $2` | `auto`, first executions | Index scan on the partial index (custom plan) |

PostgreSQL may switch to a generic plan after five executions, so a bound state parameter loses the partial index in steady state. **Result:** the literal-state rule in [Schema and invariants](#schema-and-invariants) is required.

**Experiment 2: transaction time across a row-lock wait.** Session 1 held `FOR UPDATE` on a row for 3s; session 2 began its transaction, then waited for the same lock. After the wait, `now()` still equalled the transaction start, while `clock_timestamp()` had advanced by 2.46s. **Result:** validating `visibility_until` with `now()` would accept a lease that expired during the wait. The post-lock `clock_timestamp()` rule in [Atomic fencing and time](#atomic-fencing-and-time) is required.

**Repro tests.** Each test asserts the correct behavior, was confirmed to fail on current code for the stated reason, and starts with `t.Skip("known bug: ...")`. The owning phase removes the skip as part of its fix.

| Test | Defect | Observed failure | Phase |
|---|---|---|---|
| [`TestHandleEventProcessError`](../internal/worker/process_error_test.go) | ProcessError dropped by `handleEvent` | No PROCESS_ERROR event published | 1 |
| [`TestContainerEventsRemoveAfterProcessEnd`](../internal/worker/container_events_integration_test.go) (integration) | Executor returns on ProcessEnd | No CONTAINER_REMOVE event published | 1 |
| [`TestRepro_DequeueIndexPredicateMatchesScheduledState`](../internal/store/postgres/job_lifecycle_repro_integration_test.go) | Partial index on `state = 0` | `idx_jobs_dequeue ... WHERE (state = 0)` | 2 |
| [`TestRepro_JobHandlersEnforceRoles`](../internal/server/authz_repro_test.go) | No role checks on job RPCs | `user` dequeue long-polled (DeadlineExceeded); `worker` enqueue succeeded | 3 |
| [`TestRepro_ExpiredLeaseIsRedelivered`](../internal/store/postgres/job_lifecycle_repro_integration_test.go) | No lease reclamation | Job never redelivered within 15s | 4 |
| [`TestRepro_StaleTokenCannotPublishEvents`](../internal/store/postgres/job_lifecycle_repro_integration_test.go) | Publish not fenced | Publish after completion succeeded | 4 |

`TestRepro_JobHandlersEnforceRoles` uses the memory JobStore; phase 2 moves it to the shared PostgreSQL helper along with [server tests](../internal/server/server_test.go). The existing `TestVisibilityTimeoutExpiry` in that file has been skipped as too slow, which is why missing redelivery went undetected; phase 4 replaces it with the fast repro.

## Research provenance

Sources accessed 2026-10-18. External facts inform the design; numeric limits, polling, and failure policies are project choices that require the verification above.

- **Attempt WAL isolation:** path/header identity by job and attempt, ownership locks, deletion on lease loss, and rejecting stale or tokenless replay. Evidence: the current WAL constructor and the conflicting local proposal linked above.
- **Durable acknowledgement:** committed unary batch replies, immutable retry content, bounded ordered sends, and completion sequence checks. Sources: [Connect streaming](https://connectrpc.com/docs/go/streaming/) and [AWS idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/).
- **Atomic fencing:** same-row locking, post-lock wall-clock validation, atomic event insertion, and a documented acceptance point. Sources: [PostgreSQL locking](https://www.postgresql.org/docs/current/explicit-locking.html), [time functions](https://www.postgresql.org/docs/current/functions-datetime.html), and [INSERT conflict behavior](https://www.postgresql.org/docs/current/sql-insert.html).
- **Attempt limits:** every acquisition counts, and the same bound applies at release, expiry, and dequeue. Delivery failures spend attempts in exchange for a simple enforceable limit.
- **Stream semantics:** pinned positive attempts, explicit status/cursors, ordered committed polling across replicas, backpressure, and terminal draining. Polling trades query load and subsecond delay for a smaller recovery model.
- **Renewal failures:** immediate initial renewal, a conservative monotonic deadline, bounded RPCs, watchdog abort, and explicit external-side-effect limits. Sources: [Go monotonic clocks](https://pkg.go.dev/time#hdr-Monotonic_Clocks) and [WithoutCancel](https://pkg.go.dev/context#WithoutCancel).
- **Execution details:** persisted dev identities, scoped collection/error semantics, one owned lifecycle, sequential phase gates, testcontainers isolation, enumerated protobuf breaks, and fixed-cutoff audit queries. Partial-index reasoning follows [PostgreSQL partial indexes](https://www.postgresql.org/docs/current/indexes-partial.html); concurrent dequeue uses [SELECT SKIP LOCKED](https://www.postgresql.org/docs/current/sql-select.html).
- **Verification scope:** one PostgreSQL backend checked against an independent reference model, with [Go fuzzing](https://go.dev/doc/security/fuzz/) available for longer model exploration. The model does not replace database, filesystem, or process integration tests. A generic workflow framework, mandatory formal proof tooling, a second job backend, and a broad package reorganization are outside scope.

[Repository guidance](../AGENT.md)
