# Phase 5a: Retention

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 4c](04c-phase4c-event-streams.md) | [Phase 5b →](05b-phase5b-metrics.md)

**Goal:** terminal jobs, their events and expired sessions are deleted on a bounded, cancellable schedule. Live jobs are never touched.

**Depends on:** [phase 4c](04c-phase4c-event-streams.md) (streams already return status only for a job whose events are gone, and NotFound for a deleted job).

## Customer problem

Before 5a nothing was ever deleted:

- **Jobs and events grew without bound.** The schema dropped the per-event TTL in phase 2, but no retention loop replaced it.
- **Sessions were never cleaned up.** `SessionStore.DeleteExpired` existed but had no caller, and it deleted every expired row in one unbounded statement.
- **The reaper didn't sweep at Start.** It waited a full interval after Start before its first sweep.

## Success criteria

- [ ] Events of COMPLETED, FAILED and CANCELLED jobs are deleted after `--events-retention-days`.
- [ ] Those jobs are deleted after `--job-retention-days`. SCHEDULED and RUNNING jobs are never deleted.
- [ ] Every delete is bounded, sweeps can be cancelled, and multiple replicas can sweep at once.
- [ ] Expired sessions are deleted in bounded batches by a server-owned sweeper.
- [ ] Cutoffs come from the database clock, never from client or event timestamps.
- [ ] `airunner-server cleanup` runs one pass for external schedulers, and `--retention-interval=0` disables the in-process sweeps.
- [ ] `retention.{events,jobs,sessions}_deleted` and `retention.sweep_errors` counters are emitted.

## Rules

| Rule | Behaviour |
|---|---|
| Eligible jobs | `state IN (3, 4, 5)` (COMPLETED, FAILED, CANCELLED), selected with literal predicates so `idx_jobs_retention` applies |
| Age | `jobs.updated_at`, compared with `clock_timestamp()` read once per sweep |
| Event cutoff | `now − EventRetention`. When `EventRetention` is 0, `now − JobRetention`, so events live as long as their job |
| Job cutoff | `now − JobRetention`. A job is deleted only once it has no events left, so the `ON DELETE CASCADE` is a safety net, not the bounded path |
| Order | Events, then jobs, in the same sweep. With `EventRetention` 0, one sweep removes a job's events and then the job |
| Lock order | `PurgeEvents` locks job rows (`FOR UPDATE SKIP LOCKED`, at most 100) before deleting their events, matching publish |
| Bounds | 1,000 rows per statement and at most 10 statements per category per sweep. A short batch ends the category early, and leftover work waits for the next sweep |
| Replicas | `SKIP LOCKED` lets sweepers run concurrently without double-deleting or double-counting |
| Sessions | `expires_at < clock_timestamp()`, oldest first, 1,000 rows per statement and at most 10 per sweep. The server runs the sweep at Start and then every `--retention-interval` |
| Failure | An error is logged and counted with a `category` label (`clock`, `events`, `jobs`); that category is skipped until the next sweep |
| Lifecycle | Job and event retention runs inside the JobStore lifecycle and joins on Stop. The session sweeper is cancelled and joined before the pool closes |

## Scheduling

Retention can run in two places. Both use the same bounded code path (`JobStore.SweepRetention` and `SweepExpiredSessions`), so they can safely overlap.

| Mode | How | When to use |
|---|---|---|
| In-process (default) | The server sweeps at Start and then every `--retention-interval` (1h) | A single node, or local development |
| Scheduled | `--retention-interval=0` on the server, plus `airunner-server cleanup` from cron, an ECS scheduled task or a Kubernetes CronJob | When you want cleanup outside the API process, with its own schedule, logs and exit status |

`airunner-server cleanup` runs one pass and exits:

- It deletes events, then jobs, then expired sessions, each drained in batches of 1,000 up to `--max-batches` (default 100) batches per category.
- It never runs migrations and never starts the reaper or other background loops.
- It exits non-zero if any category fails. If backlog remains, it logs a warning and exits 0; the next run continues.
- It accepts `--job-retention-days`, `--events-retention-days`, `--postgres-*` and `--tracing`, with the same env vars as the server. It reuses the Postgres flag validation, so `AIRUNNER_POSTGRES_TOKEN_SECRET` must be set even though cleanup signs no tokens.

The lease reaper always runs in the server. Redelivery depends on its 5s cadence, which makes it unsuitable for an external scheduler.

## Semantics

- **Idempotency window.** Request IDs are unique per org only while the job exists. After the job is deleted, the same request ID creates a new job, so idempotency lasts for the job retention period.
- **Eventual deletion.** Deletion depends on the sweep schedule, the backlog and database availability. A backlog beyond 10,000 rows per category drains over several sweeps.
- **Readers.** A stream on a terminal job whose events were purged sends its initial and final status with no events. A stream on a deleted job ends with NotFound.

## Configuration

| Flag | Env | Default | Validation |
|---|---|---|---|
| `--job-retention-days` | `AIRUNNER_JOB_RETENTION_DAYS` | 90 | > 0 |
| `--events-retention-days` | `AIRUNNER_EVENTS_RETENTION_DAYS` | 30 | ≥ 0 and ≤ job retention; 0 keeps events for the job's lifetime |
| `--retention-interval` | `AIRUNNER_RETENTION_INTERVAL` | 1h | ≥ 0; 0 disables the in-process retention and session sweeps |
| `cleanup --max-batches` | `AIRUNNER_CLEANUP_MAX_BATCHES` | 100 | > 0; batches per category per run |
| `--event-poll-interval` | `AIRUNNER_EVENT_POLL_INTERVAL` | 500ms | > 0 (stream polling from [4c](04c-phase4c-event-streams.md)) |

`--events-retention-days` replaces the removed `--events-ttl-days`. `infra/main.tf` still sets `AIRUNNER_EVENTS_TTL_DAYS`; infra is out of scope for this redesign.

## Audit queries

Run these after a fully drained sweep, using the same fixed cutoff. Each count should be zero.

```sql
-- Events past the event cutoff ($2 = event retention days)
SELECT count(*) FROM job_events e JOIN jobs j USING (job_id)
WHERE j.state IN (3, 4, 5) AND j.updated_at < $1::timestamptz - make_interval(days => $2::int);

-- Terminal jobs past the job cutoff ($2 = job retention days)
SELECT count(*) FROM jobs
WHERE state IN (3, 4, 5) AND updated_at < $1::timestamptz - make_interval(days => $2::int);

SELECT count(*) FROM sessions WHERE expires_at <= $1::timestamptz;
```

## Deferred behaviour

| Item | Phase |
|---|---|
| Backlog-age and sweep-duration metrics, plus the remaining lifecycle, stream, WAL and lease metrics | 5b |
| Replacing the unused `internal/telemetry/metrics.go` instruments | 5b |
| DeadlineExceeded after 30s without stream send progress | 5b |
| CancelJob (cancelled jobs already qualify for retention) | 6 |

## Verification

```bash
go test -tags integration -race -count=3 -run 'Retention|Purge|Session' ./internal/store/postgres/
go test -tags integration -race ./...
make lint test proto-lint
```

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [← Phase 4c](04c-phase4c-event-streams.md) | [Phase 5b →](05b-phase5b-metrics.md)
