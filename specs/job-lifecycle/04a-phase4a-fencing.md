# Phase 4a: Server fencing, reaper, and the publish contract

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 3](03-phase3-tenancy-authz.md) | [Phase 4b (planned) →](../job-lifecycle-tenancy-redesign-plan.md#deliverable-2-implementation-phases)

**Goal:** jobs whose lease has expired are redelivered or failed. Only the current lease holder can mutate a job or its event log. Events are committed contiguously and acknowledged only after commit. A job completes only once the server holds its whole log.

**Depends on:** [phase 3](03-phase3-tenancy-authz.md) (authorization, `ErrLeaseLost` → FailedPrecondition, lifecycle context).

Phase 4 ships as three PRs:

| PR | Scope |
|---|---|
| **4a (this)** | Server fencing, publish contract, completion gate, reaper, RPC limits, and the minimal worker change to send `final_event_sequence` |
| 4b | Per-attempt WAL path, header, and lock; acknowledgement-validating sender; renewal controller with watchdog; abort-and-delete on lease loss; `--keep-failed-wal` |
| 4c | Polling streams with attempt resolution and status responses, `monitor --attempt`, and UI keys `job_id-attempt-sequence` |

## Customer problem

Before this phase, the server had two defects:

- **No recovery.** A worker that crashed left its job RUNNING forever, because nothing reclaimed expired leases. `TestRepro_ExpiredLeaseIsRedelivered` proved this.
- **No fencing.** Token operations compared the receipt in one `UPDATE` evaluated at `now()`, which is the transaction start time. They never checked the leasing principal. `PublishEvents` never checked the receipt at all, so a correctly signed stale token could append events to a redelivered job. `TestRepro_StaleTokenCannotPublishEvents` proved this.

## Success criteria

- [ ] Both repro tests pass un-skipped.
- [ ] Every token operation is fenced by the leasing principal, the receipt, the queue, the RUNNING state, and the expiry measured after the row lock is acquired.
- [ ] Publish is contiguous, idempotent for identical retries, conflicts on changed content, and is all-or-nothing.
- [ ] Completion requires `final_event_sequence == last_event_sequence`.
- [ ] The reaper redelivers or fails expired leases using the same exhaustion rule as release.
- [ ] Differential replay passes with renew, release, expire, publish, and stale or wrong-caller tokens enabled.

## Fence algorithm

All token operations (UpdateJob, CompleteJob, release, and PublishJobEvents) share `lockLease`:

1. Decode the token; a malformed or forged token returns `ErrInvalidTaskToken`. Then open a READ COMMITTED transaction with `lock_timeout` and `statement_timeout` both set to 5s.
2. `SELECT ... FROM jobs WHERE org_id = $caller AND job_id = $token FOR UPDATE`.
3. After the lock is acquired, sample `clock_timestamp()` once as `operation_time`. `now()` stays frozen at transaction start, so it would accept a lease that expired while the transaction waited for the lock.
4. Require state RUNNING, a matching receipt and queue, `leased_by = caller`, and `visibility_until > operation_time`. Equality counts as expired. Any failure, including a missing row, returns `ErrLeaseLost` without saying which check failed.
5. Perform the whole mutation in the same transaction, and report success only after commit.

**Acceptance point.** A publish accepted under a valid lease may commit after the lease's wall-clock expiry while it still holds the lock. Cancellation and reclamation cannot commit ahead of it. An operation that reaches the lock after expiry fails. Barrier tests cover both orderings.

**Lock contention.** A lock-wait or statement timeout maps to `ErrUnavailable` (Connect Unavailable), which the caller may retry. Serialization failures, lost connections, and database shutdown map to the same error.

## Publish contract

| Case | Result |
|---|---|
| Record starts at `last_event_sequence + 1` | Inserted; `last` becomes its end |
| Record identical to a stored row (same start, end, and deterministic payload bytes) | No-op; acknowledged again |
| Same start but different end or payload | `ErrConflict` → AlreadyExists |
| Start ≤ `last` with no stored row at that start (overlap) | `ErrInvalidArgument` |
| Start > `last + 1` (gap) | `ErrInvalidArgument` |
| OutputBatch where `sequence ≠ start_sequence` or `len(outputs) ≠ end − start + 1` | `ErrInvalidArgument` |
| Missing timestamp | `ErrInvalidArgument` (the server no longer fills it) |
| Nonzero `event.attempt` ≠ the leased attempt | `ErrInvalidArgument` (zero is allowed until 4b) |
| More than 50 events, or more than 1 MiB encoded | ResourceExhausted, checked before store access |

Any rejection rolls back the whole request. The server stamps the attempt from the locked row. The response `{attempt, acknowledged_through_sequence}` is returned only after commit. Live fanout delivers only newly inserted rows.

## Completion gate

`CompleteJobRequest.final_event_sequence` must equal the attempt's `last_event_sequence`. Otherwise the call returns `ErrInvalidArgument` and leaves the job RUNNING. The worker sends the highest acknowledged sequence after flushing its WAL; zero is valid only when no events were published. In 4a the worker still marks WAL records sent when the RPC succeeds. Acknowledgement validation, and the policy for a failed final flush, arrive in 4b.

## Reaper

`ReapExpired(ctx, limit)` claims rows with `state = 2 AND visibility_until <= clock_timestamp()`, ordered by `(visibility_until, job_id)`, using `FOR UPDATE SKIP LOCKED`. It applies the release rule:

- if attempts remain, the job returns to SCHEDULED;
- otherwise it becomes FAILED with `result.reason = "delivery attempts exhausted"`.

Either way the lease columns are cleared.

The loop runs every `--lease-reaper-interval` (default 5s) under the store's lifecycle context. Each tick runs up to 10 batches of 100 rows. Multiple replicas can reap concurrently because rows are claimed with SKIP LOCKED.

**Edge case:** a row whose lock is held by an in-flight publish is skipped, and the next tick reclaims it once the publish commits or rolls back.

## RPC boundary

| Rule | Value |
|---|---|
| Visibility timeout | 0 means 300s; otherwise 30–3600s, else InvalidArgument |
| Dequeue delivery failure | Release the failed job and every unsent job in the batch. Each release runs under `WithTimeout(WithoutCancel(ctx), 5s)` |
| Worker renewal interval | Visibility timeout ÷ 3 |

## Differential replay

Model time is measured in seconds and mapped to the database with fixture timestamps. Before each command, the adapter rewrites every RUNNING job's `visibility_until` to `clock_timestamp() + (modelDeadline − modelNow)`. A zero offset is therefore already expired when the operation runs, which matches the model's equality rule. `Expire` maps to that rewrite followed by `ReapExpired`. Model records become OutputBatch events with deterministic payloads and timestamps, so identical retries are byte-identical. Cancel remains disabled until phase 6.

## Deferred behaviour

| Item | Phase |
|---|---|
| Required `event.attempt`, per-attempt WAL, ack validation, renewal watchdog, abort-and-delete, final-flush policy | 4b |
| Polling streams, `attempt` selection, status responses, monitor and UI attempt handling | 4c |
| `jobs.redelivered`, `jobs.dead_lettered`, `jobs.lease_lost` metrics | 5 |

## Verification

```bash
go test -tags integration -race -run 'Repro|Fenc|Race|Barrier' ./internal/store/postgres/
go test -tags integration -race -run TestDifferentialReplay ./internal/store/postgres/
make lint test proto-lint && go test -tags integration -race ./...
```

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 3](03-phase3-tenancy-authz.md) | [Phase 4b (planned) →](../job-lifecycle-tenancy-redesign-plan.md#deliverable-2-implementation-phases)
