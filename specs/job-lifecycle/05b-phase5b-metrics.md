# Phase 5b: Operational metrics and the stream stall deadline

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 5a](05a-phase5a-retention.md) | [Phase 6 (planned) →](../job-lifecycle-tenancy-redesign-plan.md#deliverable-2-implementation-phases)

**Goal:** an operator can see redelivery, dead-lettering, lease loss, publish health, stream load, sweep backlog and worker durability from metrics alone, without per-job labels. A reader that stops reading cannot hold a stream open indefinitely.

**Depends on:** [phase 5a](05a-phase5a-retention.md) (retention counters and sweeps).

## Customer problem

- **Metrics went nowhere.** `internal/telemetry/metrics.go` defined about 15 instruments, but outside the 5a retention counters nothing recorded them. Several described designs that no longer exist (dropped events, channel overflow, historical replay).
- **Worker failures were invisible.** The worker had no telemetry, so lease aborts, publish retries and abandoned jobs appeared only in local logs.
- **Stalled readers blocked forever.** A reader that stopped reading blocked its stream goroutine for as long as the connection stayed open.

## Success criteria

- [ ] Instruments are built once with `telemetry.NewMetrics(meter)` and injected. There is no global singleton, and tests assert values through a ManualReader.
- [ ] The server records the lifecycle, reaper, retention, publish, stream and authz instruments below.
- [ ] `airunner-cli worker --tracing` exports the worker instruments below.
- [ ] A stream send that makes no progress for `--stream-send-timeout` (30s) ends with DeadlineExceeded and increments `streams.stalled`.

## Label policy

Attributes are bounded enums only: `result`, `operation`, `reason`, `category` and `procedure` (a generated RPC constant). Metrics never carry job IDs, tokens, org IDs or queue names. Per-job detail belongs in logs and traces.

## Server instruments

| Instrument | Type | Recorded when | Attributes |
|---|---|---|---|
| `jobs.enqueued` | counter | a new job is created. Idempotent replays don't count | – |
| `jobs.dequeued` | counter | jobs are leased | – |
| `jobs.released` | counter | a worker releases an undeliverable job | – |
| `jobs.completed` | counter | `CompleteJob` succeeds | `result=success\|failure` |
| `jobs.redelivered` | counter | the reaper returns an expired lease to SCHEDULED | – |
| `jobs.dead_lettered` | counter | the reaper fails a job with no attempts left | – |
| `jobs.lease_lost` | counter | a token operation fails with `ErrLeaseLost` | `operation=renew\|publish\|complete\|release` |
| `lease.renewals` | counter | `UpdateJobVisibility` succeeds | – |
| `reaper.sweep_duration` | histogram (s) | every reaper tick | – |
| `reaper.backlog` | gauge | after each tick: expired RUNNING leases still unreclaimed | – |
| `reaper.oldest_expired_age` | gauge (s) | after each tick: age of the oldest unreclaimed expiry, 0 when none | – |
| `retention.sweep_duration` | histogram (s) | every retention pass (in-process loop or `cleanup`) | – |
| `retention.oldest_eligible_age` | gauge (s) | after each pass: how far the oldest eligible terminal job is past its cutoff, 0 when drained | – |
| `retention.{events,jobs,sessions}_deleted` | counter | rows deleted ([5a](05a-phase5a-retention.md)) | – |
| `retention.sweep_errors` | counter | a retention category fails | `category=clock\|events\|jobs` |
| `events.published` | counter | events inserted by a committed publish | – |
| `events.publish_duration` | histogram (s) | every store publish | – |
| `events.publish_replays` | counter | an identical retry commits nothing new | – |
| `events.publish_rejected` | counter | publish fails in the handler or the store | `reason=lease_lost\|conflict\|invalid\|too_large\|unavailable\|other` |
| `streams.active` | up-down counter | stream start and end | – |
| `streams.delivery_lag` | histogram (s) | events sent while the attempt is open: `now − event.timestamp` | – |
| `streams.stalled` | counter | the stall deadline fires | – |
| `authz.denied` | counter | the job authz interceptor rejects a call | `procedure`, `reason=unauthenticated\|forbidden` |

**Delivery lag caveat.** The worker sets `event.timestamp` with its own clock, so worker clock skew biases `streams.delivery_lag`. Use it for trends and alerting on large jumps, not for exact latency.

## Worker instruments

Enable them with `airunner-cli worker --tracing` (env `AIRUNNER_TRACING`, using the standard `OTEL_EXPORTER_OTLP_*` variables).

| Instrument | Type | Recorded when | Attributes |
|---|---|---|---|
| `worker.wal.pending_records` | gauge | after every batch outcome and discard | – |
| `worker.wal.failed_deleted` | counter | a WAL file is removed from disk (stale or legacy cleanup, `failed/` pruning, discard). Moves to `failed/` don't count | – |
| `worker.publish.ack_latency` | histogram (s) | from send to a valid acknowledgement | – |
| `worker.publish.retries` | counter | a transient publish failure is retried | – |
| `worker.lease.aborts` | counter | the lease controller aborts, at most once per job | `reason=lost\|budget` |
| `worker.jobs.abandoned` | counter | the worker gives up a job without completing it | `reason=lease_lost\|flush_timeout\|other` |

## Stream stall deadline

| Rule | Behaviour |
|---|---|
| Mechanism | Middleware on `/job.v1.JobEventsService/` exposes `http.ResponseController.SetWriteDeadline`. The handler sets `now + timeout` before each send and clears it afterwards |
| Outcome | A send blocked past the deadline fails. The handler returns DeadlineExceeded and increments `streams.stalled`. The client reconnects from its last sequence |
| Scope | Per send, not per stream. A long-lived stream that keeps draining is never cut off |
| Server `WriteTimeout` | Clearing the deadline after a send also lifts the HTTP server's 5m `WriteTimeout` for event streams. A monitor on a job running longer than 5 minutes is no longer cut off; the per-send deadline replaces the global cap |
| Config | `--stream-send-timeout=30s` (env `AIRUNNER_STREAM_SEND_TIMEOUT`). 0 disables it |
| Unsupported writer | If write deadlines aren't supported, the server logs once at Debug and streams without a deadline |

## Alerting starting points

| Signal | Suggested condition |
|---|---|
| Redelivery storm | `jobs.redelivered` rate well above baseline, especially alongside `worker.lease.aborts{reason=budget}` |
| Dead letters | any increase in `jobs.dead_lettered` |
| Reaper falling behind | `reaper.oldest_expired_age` > 60s for 5 minutes |
| Retention falling behind | `retention.oldest_eligible_age` > 1 day, or any `retention.sweep_errors` |
| Publish health | `events.publish_rejected{reason=conflict\|invalid}` above zero (these point to client bugs); `worker.publish.retries` sustained |
| Stalled readers | sustained `streams.stalled`, or `streams.active` growing without bound |

## Verification

```bash
go test -race -count=3 ./internal/telemetry/... ./internal/worker/... ./internal/auth/
go test -tags integration -race -count=3 -run 'Metric|Stall|Deadline' ./internal/store/postgres/ ./internal/server/
go test -tags integration -race ./...
make lint test proto-lint
```

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 5a](05a-phase5a-retention.md) | [Phase 6 (planned) →](../job-lifecycle-tenancy-redesign-plan.md#deliverable-2-implementation-phases)
