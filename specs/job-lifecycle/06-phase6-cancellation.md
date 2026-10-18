# Phase 6: Job cancellation

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 5b](05b-phase5b-metrics.md) | [Phase 7 (planned) →](../job-lifecycle-tenancy-redesign-plan.md#deliverable-2-implementation-phases)

**Goal:** a user can stop a scheduled or running job. A connected worker stops its command within a bounded time, never completes the job, and leaves a clean, final CANCELLED state that streams and retention already understand.

**Depends on:** [phase 4a](04a-phase4a-fencing.md) (row-lock fencing), [4b](04b-phase4b-worker-durability.md) (lease controller and abandon path), [4c](04c-phase4c-event-streams.md) (streams close on non-RUNNING) and [5b](05b-phase5b-metrics.md) (metrics).

## Customer problem

The proto defined `CancelJob` from phase 2, but the handler returned Unimplemented. A wrong or runaway job could only be stopped by killing the worker host, which also delayed the job's redelivery until its lease expired.

## Success criteria

- [ ] `CancelJob` moves SCHEDULED and RUNNING jobs to CANCELLED under the job row lock.
- [ ] Cancel is idempotent. A finished job (COMPLETED or FAILED) returns FailedPrecondition, and another org's job returns NotFound.
- [ ] After a cancel, every fenced call from the old lease fails with FailedPrecondition and `Airunner-Lease-Reason: cancelled`.
- [ ] A connected worker detects cancellation on its next renewal, terminates the command, discards its WAL and never completes or releases the job.
- [ ] `airunner-cli cancel <job-id>` and a dashboard Cancel button are available.
- [ ] Differential replay includes cancel histories.

## Transitions

| From | CancelJob result | Effect |
|---|---|---|
| SCHEDULED | CANCELLED | Never dequeued. A waiting stream closes with CANCELLED |
| RUNNING | CANCELLED | Lease columns cleared. The holder's next fenced call fails, and its stream closes after the drain |
| CANCELLED | CANCELLED | No change (idempotent) |
| COMPLETED, FAILED | FailedPrecondition | No change; the result is preserved |
| Absent, other org, invalid ID | NotFound | Indistinguishable from a missing job |

`attempt` and `last_event_sequence` are unchanged, so history for the cancelled attempt stays readable until retention removes it.

## Serialization and acceptance point

Cancel takes the same `FOR UPDATE` row lock, with the same 5s lock bound, as publish, complete, release, renew, dequeue and the reaper.

- **A publish that holds the lock first commits.** Its events stay in the cancelled attempt's log.
- **A publish that locks after the cancel fails.** It gets `ErrJobCancelled` and persists nothing.
- **There is no interleaving in between.** This is the existing acceptance-point rule from [phase 4a](04a-phase4a-fencing.md).

## Worker detection and shutdown

| Step | Behaviour |
|---|---|
| Signal | `lockLeaseRow` returns `store.ErrJobCancelled`, which wraps `ErrLeaseLost`. The server maps it to FailedPrecondition and sets the Connect error metadata `Airunner-Lease-Reason: cancelled` (`internal/leasereason`). No proto change |
| Detection | Renewal maps the header to `lease.ErrCancelled` (wraps `lease.ErrLost`). The controller aborts immediately and cancels the execution context. A publish or complete that sees the header is treated the same way |
| Termination | console-stream sends SIGTERM to the process group, then SIGKILL after 5s; containers stop with a 2s grace |
| Cleanup | No complete, no release. The WAL is discarded (kept in `failed/` with `--keep-failed-wal`), and the job is logged as "job cancelled" |
| Bound (connected) | Detection takes at most the maximum jittered renewal interval plus one bounded RPC, about `1.25 × timeout/3 + 5s`. Shutdown adds up to the 5s termination grace. With the default 300s visibility timeout that is about 135s worst case; with 30s it is about 22.5s |
| Partitioned | The worker can't see the cancel. The local lease deadline from [phase 4b](04b-phase4b-worker-durability.md) stops it instead, and the server already fences every write |

Commands with external side effects still need idempotency keys or downstream concurrency controls. Cancellation stops future work; it can't undo work already done.

## Interfaces

| Interface | Behaviour |
|---|---|
| RPC | `JobService.CancelJob{job_id}` returns `{state}`. Roles: user, admin |
| CLI | `airunner-cli cancel <job-id>` prints `Job <id> cancelled` and exits 0, including for an already-cancelled job. A finished job or a missing job exits 1 with the server message |
| Dashboard | A Cancel button (with confirmation) on SCHEDULED and RUNNING jobs, in the job list and the job view. The job view's stream closes and its banner shows the cancelled state |

## Metrics

| Instrument | Attributes |
|---|---|
| `jobs.cancelled` | `from=scheduled\|running` |
| `jobs.lease_lost` | Still counts fenced calls rejected after a cancel, by `operation` |
| `worker.lease.aborts` | `reason=cancelled` (alongside `lost` and `budget`) |
| `worker.jobs.abandoned` | `reason=cancelled` |

## Verification

```bash
go test -tags integration -race -count=3 -run 'Cancel|Differential|RPCErrorCodes' ./internal/store/postgres/ ./internal/server/ ./cmd/cli/...
go test -tags integration -race ./...
make lint test proto-lint
bunx biome check ui/pages/ && bunx tsc --noEmit -p tsconfig.json
```

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 5b](05b-phase5b-metrics.md) | [Phase 7 (planned) →](../job-lifecycle-tenancy-redesign-plan.md#deliverable-2-implementation-phases)
