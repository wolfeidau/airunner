# Job Lifecycle and Tenancy Redesign

[Architecture →](00-architecture.md) | [Runbook](operations-runbook.md) | [Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [Repository guidance](../../AGENT.md)

**Status:** implemented and merged in PRs #152 to #160, plus this documentation PR. This specification records the **as-built** behaviour. The [redesign plan](../job-lifecycle-tenancy-redesign-plan.md) records the original intent. Where the two differ, the code and this specification win; the differences are listed in [00-architecture.md](00-architecture.md#differences-from-the-plan).

## Overview

Before this work, airunner could lose a job's output, run a job twice without noticing, and show one tenant another's data. The redesign closes those gaps with a PostgreSQL-only, organization-scoped job lifecycle.

| Customer problem | Outcome |
|---|---|
| A worker crash left a job RUNNING forever | A reaper returns expired leases to the queue, or fails the job after `max_attempts` acquisitions |
| An old worker could still write to a redelivered job | Every token operation locks the job row and checks the leasing principal, receipt, queue, state and expiry. A stale token fails with FailedPrecondition |
| Events were acknowledged before they were stored | Publishing is unary. The server acknowledges a batch only after commit, and the worker marks records sent only on a matching acknowledgement |
| A job could complete with part of its log missing | `CompleteJob` must name the last committed event sequence, or it is rejected |
| Retried jobs interleaved their logs | Events are keyed `(job_id, attempt, sequence)`. Each attempt has its own log, WAL and stream |
| Any authenticated caller could call any job RPC, and jobs had no org boundary | Every RPC is role-checked, and every query is scoped to the caller's org |
| Nothing was ever deleted | Bounded, cancellable sweeps delete terminal jobs, their events and expired sessions |
| A runaway job could only be stopped by killing the worker | `CancelJob` stops scheduled and running jobs, and a connected worker terminates the command |
| Failures were invisible | About 30 bounded-label metrics cover the server, reaper, retention and worker |

## Prerequisites

- Go 1.26 or later (see `go.mod`), make, and [bun](https://bun.sh) for the dashboard.
- Docker. Compose runs PostgreSQL 18 for local development, and testcontainers runs PostgreSQL 18 for integration tests.
- Familiarity with Connect RPC, PostgreSQL row locks (`FOR UPDATE SKIP LOCKED`) and the difference between `now()` and `clock_timestamp()`.
- For operators: access to the metrics backend and read access to the database. The [runbook](operations-runbook.md) assumes `psql` access.

## Quick start

1. Read [00-architecture.md](00-architecture.md) for the data model, state machine, fencing rules and key decisions.
2. Read the phase files in order, starting at [01-phase1-worker-events.md](01-phase1-worker-events.md). Each is independent and ends with its verification commands.
3. Run the fast gate, which needs no Docker: `go test -race ./internal/store/storetest/... ./internal/worker/... ./internal/auth/ ./internal/server/`.
4. Run the full gate, which starts PostgreSQL testcontainers: `make lint test proto-lint test-integration`.
5. Operate it with the [runbook](operations-runbook.md), and copy test patterns from [examples/](examples/contract-test-skeleton.md).

## File navigation

| File | Purpose |
|---|---|
| [README.md](README.md) | This entry point |
| [00-architecture.md](00-architecture.md) | As-built design: schema, state machine, fencing, WAL, streams, retention, metrics, decisions |
| [01-phase1-worker-events.md](01-phase1-worker-events.md) | Retrospective: executor drains events after `ProcessEnd`, records `ProcessError`, surfaces recording failures |
| [02-phase2-schema-contract.md](02-phase2-schema-contract.md) | Org-scoped squashed schema, `store.Caller`, new protocol fields, reference model |
| [03-phase3-tenancy-authz.md](03-phase3-tenancy-authz.md) | Role interceptor, shared error mapper, org-membership foreign keys, safe store lifecycle |
| [04a-phase4a-fencing.md](04a-phase4a-fencing.md) | Fenced token operations, publish contract, completion gate, reaper |
| [04b-phase4b-worker-durability.md](04b-phase4b-worker-durability.md) | Per-attempt WAL, acknowledgement-validating sender, lease controller, completion decision table |
| [04c-phase4c-event-streams.md](04c-phase4c-event-streams.md) | Attempt-pinned polling streams, status responses, `monitor --attempt`, dashboard attempt selector |
| [05a-phase5a-retention.md](05a-phase5a-retention.md) | Bounded retention sweeps, session sweeper, `airunner-server cleanup` |
| [05b-phase5b-metrics.md](05b-phase5b-metrics.md) | Operational metrics, worker metrics, per-send stream deadline |
| [06-phase6-cancellation.md](06-phase6-cancellation.md) | `CancelJob`, lease-reason header, worker shutdown, dashboard Cancel |
| [07-phase7-documentation.md](07-phase7-documentation.md) | Documentation updates and how they were verified |
| [operations-runbook.md](operations-runbook.md) | Day 2 procedures, SQL audits, scheduling `cleanup`, local reset |
| [examples/schema.md](examples/schema.md) | `jobs` and `job_events` DDL, indexes and composite foreign keys |
| [examples/fenced-publish.md](examples/fenced-publish.md) | `lockLeaseRow` and the publish transaction |
| [examples/bounded-sweeps.md](examples/bounded-sweeps.md) | `ReapExpired`, `PurgeEvents`, `PurgeJobs` and session delete SQL |
| [examples/authz-interceptor.md](examples/authz-interceptor.md) | Role table, precedence and the error mapper |
| [examples/reference-model.md](examples/reference-model.md) | Model commands, invariants and differential replay commands |
| [examples/contract-test-skeleton.md](examples/contract-test-skeleton.md) | A runnable integration test using `postgrestest` and `telemetrytest` |

## Phases

All phases are done. Each phase was one pull request, executed in order because they change the same interfaces and startup paths.

| Phase | Scope | PR | Status |
|---|---|---|---|
| [1 Worker events](01-phase1-worker-events.md) | Drain the iterator through cleanup, record `ProcessError`, chunk large output, propagate recording failures | #152 | Done |
| [2 Schema and contract](02-phase2-schema-contract.md) | Squashed org-scoped schema, `Caller`, unary publish, dev identity, reference model, differential replay | #153 | Done |
| [3 Tenancy and authz](03-phase3-tenancy-authz.md) | Role interceptor, error mapper, composite foreign keys, idempotent Start/Stop | #154 | Done |
| [4a Fencing](04a-phase4a-fencing.md) | Row-lock fencing, publish contract, completion gate, reaper | #155 | Done |
| [4b Worker durability](04b-phase4b-worker-durability.md) | Per-attempt WAL, ack-validating sender, lease controller | #156 | Done |
| [4c Event streams](04c-phase4c-event-streams.md) | Polling streams, attempt selection, status responses | #157 | Done |
| [5a Retention](05a-phase5a-retention.md) | Event, job and session sweeps, `cleanup` command | #158 | Done |
| [5b Metrics](05b-phase5b-metrics.md) | Server and worker instruments, stream stall deadline | #159 | Done |
| [6 Cancellation](06-phase6-cancellation.md) | `CancelJob`, CLI, dashboard, worker shutdown | #160 | Done |
| [7 Documentation](07-phase7-documentation.md) | AGENT.md, README, this layered spec, superseded banners | this PR | Done |

Phase 1 also shipped the redesign plan and the repro tests (`433b7d7`, `7eb8480`, `86874fc`), the worker fix (`bbdba39`) and a JWK parsing fix that unblocked lint (`29a8ad9`).

## Compatibility and reset constraints

The project is undeployed. The redesign is greenfield by decision:

- **Squashed migrations.** Former migrations 1 to 3 are one file, [1_initial_schema.sql](../../internal/store/postgres/migrations/1_initial_schema.sql). A second file, [2_principal_org_fks.sql](../../internal/store/postgres/migrations/2_principal_org_fks.sql), adds the composite organization foreign keys.
- **No backfill and no compatibility migration.** A database that recorded the old version 1 must be recreated. Local Compose databases were wiped in phase 2. See the [local reset procedure](operations-runbook.md#local-compose-reset-destructive).
- **No protocol compatibility.** `PublishJobEvents` changed from client streaming to unary, `UpdateJobRequest.queue` was removed (field 1 and the name are reserved), and new fields were added. Old workers and CLIs do not work against the new server. `make proto-breaking` reports exactly those two incompatibilities.
- **PostgreSQL is the only job backend.** The in-memory job store is gone (the AWS backend was removed earlier). Memory principal, organization and session stores remain only as test fakes. The server flags `--store-type` and `--events-ttl-days` no longer exist.
- **Credentials.** A reset deletes identities. Re-register credentials afterwards. Tokens issued before a reset return 401.
- **Infrastructure.** `infra/` is stale DynamoDB and SQS Terraform and is not updated. It still sets `AIRUNNER_STORE_TYPE` and `AIRUNNER_EVENTS_TTL_DAYS`, which the server ignores.

## Completion criteria

Every goal of the [redesign plan](../job-lifecycle-tenancy-redesign-plan.md) is met.

- [x] Worker records every event through container cleanup, and recording failures fail the job ([phase 1](01-phase1-worker-events.md)).
- [x] Jobs, request IDs and queues are scoped to an organization; a changed intent under an existing request ID conflicts ([phase 2](02-phase2-schema-contract.md)).
- [x] PostgreSQL is the only backend; `--no-auth` seeds a fixed development identity ([phase 2](02-phase2-schema-contract.md)).
- [x] Every job RPC is role-checked and unknown procedures fail closed ([phase 3](03-phase3-tenancy-authz.md)).
- [x] Store errors map to consistent Connect codes through one mapper ([phase 3](03-phase3-tenancy-authz.md)).
- [x] A worker crash is recovered by redelivery with at most `max_attempts` acquisitions ([phase 4a](04a-phase4a-fencing.md)).
- [x] Only the current lease holder can mutate a job or its log ([phase 4a](04a-phase4a-fencing.md)).
- [x] Events are acknowledged after commit, and a job completes only with its whole log ([phase 4a](04a-phase4a-fencing.md), [4b](04b-phase4b-worker-durability.md)).
- [x] Each attempt has its own WAL, and a lost lease aborts execution without completing ([phase 4b](04b-phase4b-worker-durability.md)).
- [x] Readers stream exactly one attempt from any replica, with status and a clean end ([phase 4c](04c-phase4c-event-streams.md)).
- [x] Terminal jobs, events and sessions are deleted on a bounded schedule ([phase 5a](05a-phase5a-retention.md)).
- [x] Operators can see redelivery, dead letters, lease loss, backlog and worker health ([phase 5b](05b-phase5b-metrics.md)).
- [x] Users can cancel scheduled and running jobs, and workers stop ([phase 6](06-phase6-cancellation.md)).
- [x] Reference model and differential replay check the PostgreSQL store against an independent oracle ([phase 2](02-phase2-schema-contract.md), [architecture](00-architecture.md#reference-model-and-differential-replay)).
- [x] AGENT.md, README and this specification describe the system as built ([phase 7](07-phase7-documentation.md)).

## Guarantees in one place

| Guarantee | Bound |
|---|---|
| Delivery | At-least-once, at most `max_attempts` acquisitions (default 3, range 1 to 100). Not exactly-once |
| Stale writes | None. Every token operation is fenced under the job row lock |
| Committed events | Survive worker loss |
| Unacknowledged WAL records | Lost if the lease is lost or the worker disk is lost. Deliberate; see [WAL loss boundary](00-architecture.md#worker-wal-and-sender) |
| Completion | Only with `final_event_sequence` equal to the last committed sequence |
| Redelivery latency | Reaper interval (5s) plus the lease duration. A polling interval, not a hard bound under overload or database failure |
| Cancellation, connected worker | About `1.25 x timeout/3 + 5s` RPC bound, plus up to 5s termination grace: about 135s at the 300s default, about 22.5s at 30s |
| Cancellation, partitioned worker | The local lease deadline stops the worker |
| Stream latency | Up to one poll interval (500ms by default) behind the commit |
| Deletion | Eventual. Depends on sweep schedule, backlog and database availability |

Commands with external side effects still need idempotency keys or downstream concurrency controls. Fencing protects the job store, not arbitrary external effects, and a suspended process cannot be forced to stop on time.

## Known gaps

These are accepted limits of the current implementation. None blocks the completion criteria.

| Gap | Impact | Direction |
|---|---|---|
| `infra/` still sets `AIRUNNER_STORE_TYPE` and `AIRUNNER_EVENTS_TTL_DAYS` and describes DynamoDB and SQS | Terraform does not describe a deployable PostgreSQL server | Rewrite `infra/` in a separate effort |
| The worker stops on its **next renewal** after losing its lease, not on the first publish-side lease or cancel signal. The WAL sender stops publishing at once, but execution continues until the controller aborts | Up to one renewal interval of wasted work after a cancel or reclaim | Planned fix: cancel the execution context when the sender reports lease loss |
| `WAL CleanupStale` logs a pending count that is overstated | Record sent status is in memory only, so a crashed WAL looks fully pending. Diagnostic only; stale files are never uploaded | None needed |
| `streams.delivery_lag` uses worker clocks | Clock skew biases the histogram | Use for trends, not exact latency |
| Archived WALs (`~/.airunner/archive/*.wal.zst`) are never pruned | `wal.CleanupArchive` exists but nothing calls it, so the archive grows with every completed job | Prune with `find` as shown in the [runbook](operations-runbook.md#failed-wal-diagnostics) |
| The WAL directory is fixed at `~/.airunner/wal` | No flag selects another directory | Set `HOME` for the worker process |
| `airunner-server cleanup` accepts `--postgres-auto-migrate` but ignores it | None; the command never migrates | Run the server once with `--postgres-auto-migrate` |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| FailedPrecondition on renew, publish or complete | The lease was lost: expired and reclaimed, released, completed, or the job was cancelled. The server does not say which check failed | Expected for a superseded worker. The worker abandons the job. Check `jobs.lease_lost` and the job's `attempt`. If the header `Airunner-Lease-Reason: cancelled` is present, the job was cancelled |
| FailedPrecondition from `cancel` | The job is already COMPLETED or FAILED | Nothing to cancel. Read the job with `list --state` |
| InvalidArgument on publish: `missing the attempt` or `does not match leased attempt` | Worker and server disagree on the attempt, or an old worker binary is running | Upgrade the worker. Workers stamp `event.attempt` from `DequeueJobResponse.job.attempt` |
| InvalidArgument on publish: `starts at sequence N but next expected is M`, or `overlaps committed events` | A gap or overlap in the attempt's log. The WAL and the server disagree | A permanent error: the worker fails the job with the acknowledged prefix. File a bug with the job ID and attempt |
| InvalidArgument: `invalid task token` | Token signature mismatch, usually after `--postgres-token-signing-secret` changed | Keep the secret identical across replicas and restarts. Jobs leased under the old secret are recovered by expiry |
| InvalidArgument on complete: `final_event_sequence ... does not match` | The worker named a sequence other than the last committed one | The job stays RUNNING. A correct worker never sends this. Check for a mismatched worker build |
| InvalidArgument: `visibility_timeout_seconds must be between 30 and 3600` | `--visibility-timeout` is out of range | Use 30 to 3600 seconds |
| ResourceExhausted on publish | More than 50 events, more than 1 MiB per request, or an event over 350 KiB | A worker bug: the sender splits at 50 records and 900 KiB. Check the worker version. Counted in `events.publish_rejected{reason=too_large}` |
| AlreadyExists on publish | A retry with different content under an existing sequence | A permanent error. Inspect the job's events; a worker rewrote a WAL record |
| AlreadyExists on enqueue | The same `request_id` was used with a different queue, parameters or `max_attempts` | Use a new request ID, or resend the identical request |
| Unavailable | A job-row lock wait or statement exceeded 5s, a serialization failure, a lost connection, or the store is stopping | Retry. The worker retries publishes with backoff. Check database load and long transactions |
| DeadlineExceeded on `monitor` | The reader stopped reading for `--stream-send-timeout` (30s), or the client timeout elapsed | Reconnect with `--from-sequence` set to the last sequence seen |
| NotFound on stream or cancel | The job does not exist, is in another org, was deleted by retention, or the ID is malformed | These cases are indistinguishable by design. Check the org of the credential |
| Stream returns status only | The job's events were purged by retention | Expected after `--events-retention-days` |
| 401 after a database reset | The reset deleted principals and sessions | Re-register credentials. See the [reset procedure](operations-runbook.md#local-compose-reset-destructive) |
| Server fails: `reserved dev organization ... has conflicting owner` | `--no-auth` found a reserved development row with different content | Remove the conflicting rows or reset the local database |
| Server fails: `event retention must not exceed job retention` | `--events-retention-days` is greater than `--job-retention-days` | Lower the event retention or raise the job retention |
| `cleanup` fails: `token signing secret is required` | `cleanup` reuses the server's Postgres flag validation | Set `AIRUNNER_POSTGRES_TOKEN_SECRET`, at least 32 bytes, even though cleanup signs no tokens |
| Migrations skipped on an old database | `schema_migrations` already records a version, so the new file is not applied | Recreate the database. Compare `schema_migrations` with the files in the migrations directory |

## Next steps

- Update `infra/` to a PostgreSQL deployment, then remove the stale environment variables.
- Cancel execution as soon as the sender or `CompleteJob` reports lease loss, instead of waiting for the next renewal.
- Prune archived WALs by calling `wal.CleanupArchive` at worker start.
- Measure active streams, poll query rate and tail lag before changing the polling transport.
- Add a WAL directory flag to the worker.

[Architecture →](00-architecture.md) | [Runbook](operations-runbook.md) | [Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [Repository guidance](../../AGENT.md)
