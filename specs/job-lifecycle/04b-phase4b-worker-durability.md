# Phase 4b: Worker durability

[← README](README.md) | [← Phase 4a](04a-phase4a-fencing.md) | [Phase 4c →](04c-phase4c-event-streams.md)

**Goal:** a worker publishes exactly the events of its own attempt and marks them sent only on a valid server acknowledgement. It stops work as soon as its lease is gone, and it never completes a job whose log the server does not hold.

**Depends on:** [phase 4a](04a-phase4a-fencing.md) (fenced token operations, publish contract, completion gate, reaper).

## Customer problem

After 4a the server enforced the contract, but the worker violated it in five ways:

- **Oversized requests retried forever.** The WAL sender sent every unsent record in one request. Requests over 50 events or 1 MiB were rejected with ResourceExhausted and retried without end.
- **Every error was retried.** That included permanent errors and lease loss.
- **Records were marked sent on any nil error,** without checking the acknowledged attempt or range.
- **Renewal never stopped execution.** It only logged errors, so a worker kept executing after losing its lease.
- **Weak WAL identity.** WAL files were identified by name only: no header identity, no lock, and no cleanup of stale files.

## Success criteria

- [ ] A WAL lives at `<wal-dir>/<job-id>/<attempt>.wal` with a v2 header `{magic, version=2, job UUID, attempt}`, under an exclusive `flock`.
- [ ] Batches respect the server limits, and records are marked sent only on a matching acknowledgement.
- [ ] Permanent errors and lease loss stop the sender immediately, and `Flush` returns them without waiting.
- [ ] The renewal controller aborts execution on lease loss or when the local budget runs out, and a late response cannot revive the budget.
- [ ] Completion follows the decision table below. A worker that has lost its lease never completes or releases the job.
- [ ] The server requires `event.attempt`.
- [ ] Stale and legacy WAL files are removed at startup, and `--keep-failed-wal` keeps failed WALs for diagnosis.

## WAL identity and lifecycle

| Rule | Behaviour |
|---|---|
| Path | `<wal-dir>/<job-id>/<attempt>.wal`. Attempts are never reused, so `(job, attempt)` is unique |
| Header | 36 bytes: magic, version 2, job UUID, attempt (uint32), reserved. A header that does not match its path is rejected |
| Ownership | Exclusive non-blocking `flock` for the WAL's lifetime. A second opener gets `ErrWALLocked` |
| Stale file for the same attempt | Truncated and given a new header under the lock. Its records are never replayed |
| Append | Stamps `event.attempt`, then fsyncs |
| Startup cleanup (`CleanupStale`) | Deletes legacy flat files. For each lockable `<job>/<attempt>.wal`, logs job, attempt, and pending count, then deletes it or moves it to `failed/`. Files locked by a live process are skipped. `failed/` is pruned by age |
| Discard | Cancels any in-flight send and deletes the file, or moves it to `failed/` when kept |
| Confirmed completion | Stop, then archive to `<job>-<attempt>.wal.zst` (existing `ArchiveOnComplete` behaviour) |

**Loss boundary.** Committed events survive worker loss. Events that were never acknowledged are lost when the lease expires or the worker's disk is lost. This is deliberate: the WAL is never uploaded under a new lease.

## Sender contract

- The sender sends one batch at a time, in sequence order. A batch holds at most 50 records and at most 900 KiB of encoded events. A record is never split.
- `EventSender.Send` returns `Ack{Attempt, Through}`. The batch is marked sent only when `Attempt` equals the WAL's attempt and `Through` equals the batch's last covered sequence (an output batch's end). Any other acknowledgement is `ErrAckMismatch`, which counts as permanent.
- An unreadable or corrupt pending record is a permanent failure. Later records are never sent past it.

| Connect code | WAL class | Sender behaviour |
|---|---|---|
| FailedPrecondition | `ErrLeaseLost` | Stop; error is sticky |
| InvalidArgument, AlreadyExists, ResourceExhausted | `ErrPermanent` | Stop; error is sticky |
| Unavailable, DeadlineExceeded, network errors | transient | Capped exponential backoff with ±20% jitter |

## Renewal controller

[internal/worker/lease](../../internal/worker/lease/controller.go) holds the controller.

- **Cadence.** Renew immediately, then every `accepted / 3` with ±25% jitter.
- **Local deadline.** `sent + accepted − max(2s, accepted/10)`, where `sent` is the monotonic time taken **before** the request. Before the first successful renewal, the deadline is `start + accepted − margin`.
- **RPC bound.** Each RPC times out at `min(5s, remaining budget)`. Transient failures retry with backoff from 500ms, capped at 5s.
- **Abort.** `ErrLost` (FailedPrecondition) aborts immediately. An independent watchdog aborts at the confirmed deadline, even while an RPC is blocked. A response received after that deadline is ignored. Nothing reverses an abort.
- **Effect.** Abort cancels the execution context, which terminates the command.

## Completion decision table

| Condition after execution | Action |
|---|---|
| Controller aborted, or the sender reports lease lost | No complete and no release; discard the WAL; the reaper redelivers |
| Flush returns `ErrPermanent` | Complete FAILED with `final_event_sequence = Acked()` and a diagnostic that the log is incomplete |
| Flush times out after `min(30s, Remaining())` with records pending | Stop renewal and do not complete; discard the WAL. Expiry redelivers, deliberately re-running a finished command rather than completing with an incomplete log |
| All records acknowledged | Complete with `final_event_sequence = Acked()`, then archive the WAL |
| Complete returns FailedPrecondition | Treat as lease lost |
| Complete response lost | Keep the WAL as diagnostic data, subject to `--keep-failed-wal` pruning; never re-execute because of it |

## Deferred behaviour

| Item | Phase |
|---|---|
| Polling streams, `attempt` resolution and status responses, `monitor --attempt`, UI attempt keys | 4c |
| WAL pending bytes, failed-WAL deletions, and lease-budget abort metrics | 5 |
| Cancellation detected on renewal (CancelJob) | 6 |

## Verification

```bash
go test -race -count=3 ./internal/worker/wal/ ./internal/worker/lease/
go test -tags integration -race ./...
make lint test proto-lint
```

[← README](README.md) | [← Phase 4a](04a-phase4a-fencing.md) | [Phase 4c →](04c-phase4c-event-streams.md)
