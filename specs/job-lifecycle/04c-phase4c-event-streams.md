# Phase 4c: Event streams

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 4b](04b-phase4b-worker-durability.md) | [Phase 5a →](05a-phase5a-retention.md)

**Goal:** a reader streams exactly one attempt's committed events, in order and without loss, from any server replica. The server tells the reader which attempt it selected, the job state, and when no further events can arrive.

**Depends on:** [phase 4a](04a-phase4a-fencing.md) (fenced publish, so a closed attempt cannot gain events) and [phase 4b](04b-phase4b-worker-durability.md) (workers stamp `event.attempt`).

## Customer problem

After 4b the write path was durable, but the read path was not:

- **Attempts were mixed.** A stream returned every attempt's events in one sequence, so a redelivered job's log interleaved two runs.
- **Events were dropped.** Replay and live delivery used non-blocking sends to a 100-slot channel. A slow reader silently lost events.
- **Single replica only.** Live events came from a process-local fanout, so a reader connected to a different server replica from the publisher saw no live events.
- **Streams never ended.** Clients guessed completion from `PROCESS_END`. `monitor` waited a 2s grace period, and the dashboard stopped reading at `PROCESS_END`, losing any later events.

## Success criteria

- [ ] `StreamJobEventsRequest.attempt` selects one attempt; 0 resolves once to the latest started attempt.
- [ ] Every response carries `resolved_attempt` and `job_state`. The first and last responses carry status only, and the last has `attempt_closed = true`.
- [ ] Streams are served by polling `job_events`. No event is dropped for a slow reader, and any replica serves any stream.
- [ ] The stream ends cleanly after the closed attempt is drained.
- [ ] `monitor --attempt` selects an attempt, and `monitor` exits when the server closes the stream.
- [ ] The dashboard keys events by `job_id-attempt-sequence` and offers an attempt selector for redelivered jobs.

## Stream contract

| Request `attempt` | Behaviour |
|---|---|
| `0` | Resolves once to `max(1, jobs.attempt)`. Pins the latest started attempt, or waits for attempt 1. It does not follow later retries |
| `1 .. max(1, jobs.attempt)` | Streams exactly that attempt |
| Greater than `max(1, jobs.attempt)`, or negative | InvalidArgument |
| Job absent or in another org | NotFound |

**Closed rule.** For resolved attempt `a`:

```
closed = jobs.attempt > a                              -- a later attempt started
      || (jobs.attempt == a && state != RUNNING)       -- a finished or its lease was reaped
      || (jobs.attempt <  a && state is terminal)      -- cancelled or failed before it started
```

Fencing rejects publishes for an attempt that is no longer RUNNING, so once the server observes `closed`, the attempt's event set is final.

## Producer loop

1. Resolve the attempt and send a status-only response.
2. Start the cursor at `max(from_sequence, 1)`.
3. Repeat:
   1. Read the job's state and attempt **before** reading events. A missing row ends the stream with NotFound.
   2. Read up to 100 rows: `attempt = a AND end_sequence >= cursor`, ordered by sequence, optionally filtered by `from_timestamp`.
   3. Advance the cursor to `end_sequence + 1` for every scanned row, including rows removed by `event_filter`. A row that fails to decode ends the stream with an error; it is never skipped.
   4. A full page reads the next page immediately.
   5. A short page after a `closed` observation sends the final status (`attempt_closed = true`) and ends the stream.
   6. Otherwise wait 500ms (`StreamPollInterval`) and poll again.

| Property | Behaviour |
|---|---|
| Backpressure | The handler sends synchronously. A slow reader slows its own stream; nothing is buffered or dropped. No database connection is held between pages |
| Reconnect inside an output batch | `end_sequence >= cursor` returns the batch that covers `from_sequence` |
| Replicas | All delivery comes from the database, so any replica serves any stream. Notifications may wake polling early later; correctness never depends on them |
| Latency | Up to one poll interval (500ms) of added tail latency |
| Purged events | Status-only responses. Missing records are never fabricated |
| Server shutdown | The stream ends with Unavailable, and the client reconnects from its last sequence |

## Clients

| Client | Behaviour |
|---|---|
| `monitor` | `--attempt N` (default 0). Prints `Attempt N, state X` when the status changes. Exits when the server closes the stream, and reports an attempt that closed without `PROCESS_END` (for example, a lease lost and the job redelivered) |
| `submit --monitor` | Streams the latest attempt (0) |
| Dashboard | Shows the resolved attempt and job state. Offers a selector of attempts `1..N` when `N > 1`, and re-opens the stream on change. Keys events by `job_id-attempt-sequence` |

## Deferred behaviour

| Item | Phase |
|---|---|
| DeadlineExceeded after 30s without send progress | 5 |
| Active stream count and tail-lag metrics | 5 |
| Event and job retention | 5 |
| Cancellation (CancelJob) closing waiting streams | 6 |

## Verification

```bash
go test -tags integration -race -count=3 -run Stream ./internal/store/postgres/ ./internal/server/
go test -tags integration -race ./...
make lint test proto-lint
bunx biome check ui/pages/
```

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 4b](04b-phase4b-worker-durability.md) | [Phase 5a →](05a-phase5a-retention.md)
