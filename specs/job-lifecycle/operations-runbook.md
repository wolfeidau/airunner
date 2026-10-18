# Operations Runbook: Job Lifecycle

[← README](README.md) | [Architecture](00-architecture.md) | [Phase 7 →](07-phase7-documentation.md)

This runbook covers Day 2 operation of the job lifecycle: triage, SQL audits, scheduling `cleanup`, worker WAL diagnostics and a local reset. Every column name was checked against [1_initial_schema.sql](../../internal/store/postgres/migrations/1_initial_schema.sql), and every query was run read-only against a PostgreSQL 18 database (see [phase 7](07-phase7-documentation.md#verification-performed)). Design background is in [00-architecture.md](00-architecture.md).

## Contents

- [Conventions](#conventions)
- [Dead letters](#dead-letters)
- [Expired leases and reaper backlog](#expired-leases-and-reaper-backlog)
- [Redelivery storms and lease loss](#redelivery-storms-and-lease-loss)
- [Cancellation timing](#cancellation-timing)
- [Retention backlog and scheduling cleanup](#retention-backlog-and-scheduling-cleanup)
- [Failed WAL diagnostics](#failed-wal-diagnostics)
- [Idempotency and retention limits](#idempotency-and-retention-limits)
- [Stalled streams](#stalled-streams)
- [Authz denials](#authz-denials)
- [SQL audit queries](#sql-audit-queries)
- [Local Compose reset (DESTRUCTIVE)](#local-compose-reset-destructive)
- [Metrics reference](#metrics-reference)

## Conventions

State values: 1 SCHEDULED, 2 RUNNING, 3 COMPLETED, 4 FAILED, 5 CANCELLED.

Run SQL read-only. For the local Compose database:

```bash
docker compose exec -T postgres psql -U airunner -d airunner_dev -c "BEGIN READ ONLY; <query>; ROLLBACK;"
```

For any other database, use `psql "$POSTGRES_CONNECTION_STRING"` and wrap the same statements in `BEGIN READ ONLY; ... ROLLBACK;`. Replace `<job-uuid>` and `<org-uuid>` with literals. Audit queries below use a fixed cutoff `$CUTOFF`; set it once, for example `now()`, so concurrent expiries do not make results flap.

Metric names are OpenTelemetry names; your backend may rewrite dots to underscores.

## Dead letters

A dead letter is a job that failed with `result.reason = 'delivery attempts exhausted'`: it used every attempt and its last lease expired or was released. An explicit failed `CompleteJob` is a different case (`result.success = false`) and is terminal on the first attempt.

**Symptoms:** any increase in `jobs.dead_lettered`; jobs in FAILED with `attempt = max_attempts`.

**Metrics:** `jobs.dead_lettered`, `jobs.redelivered`, `worker.lease.aborts`, `worker.jobs.abandoned`.

```sql
-- Recent dead letters
SELECT job_id, org_id, queue, attempt, max_attempts, updated_at
FROM jobs
WHERE state = 4 AND result->>'reason' = 'delivery attempts exhausted'
ORDER BY updated_at DESC LIMIT 20;
```

**Action**

1. Find the cause. For each dead letter, stream each attempt: `airunner-cli monitor --attempt 1 <job-id>`, then `--attempt 2`, and so on. An attempt that closes without `PROCESS_END` lost its lease.
2. Check the worker logs for `Abandoning job without completing` (the `reason` field gives `lease_lost`, `flush_timeout` or `other`) and `lease aborted`.
3. Common causes: the command outlasts the visibility timeout and the worker cannot renew (network), a worker crashes repeatedly on the same job, or `--visibility-timeout` is too short.
4. Resubmit with a new `request_id`. The old `request_id` returns the existing FAILED job until retention deletes it.
5. For jobs that legitimately take long, raise `airunner-cli worker --visibility-timeout` (30 to 3600) rather than `max_attempts`.

## Expired leases and reaper backlog

The reaper returns expired RUNNING jobs to SCHEDULED or fails them. It runs in the server every `--lease-reaper-interval` (5s), 10 batches of 100 rows per tick.

**Symptoms:** `reaper.oldest_expired_age` above 60s for 5 minutes, `reaper.backlog` growing, jobs stuck in RUNNING past `visibility_until`.

**Metrics:** `reaper.backlog`, `reaper.oldest_expired_age`, `reaper.sweep_duration`.

```sql
-- Expired leases waiting for the reaper
SELECT count(*) AS expired, min(visibility_until) AS oldest
FROM jobs
WHERE state = 2 AND visibility_until <= clock_timestamp();

-- Which jobs
SELECT job_id, org_id, queue, attempt, max_attempts, leased_by, visibility_until
FROM jobs
WHERE state = 2 AND visibility_until <= clock_timestamp()
ORDER BY visibility_until, job_id LIMIT 20;
```

A few seconds of expired rows between ticks is normal. A sustained backlog means the reaper is not keeping up or not running.

**Action**

1. Confirm a server is running with the reaper: the log line `Starting PostgreSQL job store` appears at start, and `Reclaimed expired leases` appears when it works.
2. Rows locked by in-flight publishes are skipped and picked up on the next tick. A long-held row lock keeps a row out. Look for blockers:

```sql
SELECT pid, state, wait_event_type, now() - xact_start AS xact_age, left(query, 80) AS query
FROM pg_stat_activity
WHERE datname = current_database() AND xact_start IS NOT NULL
ORDER BY xact_start LIMIT 10;
```

3. Fenced operations time out after 5s, so a stuck lock points to a session outside the server. End it with `pg_terminate_backend(pid)` after review.
4. If `reaper.sweep_duration` is high, check database load and the `idx_jobs_lease` plan (`EXPLAIN` the first query above).
5. Replicas can run the reaper concurrently; adding a replica is safe.

Redelivery latency is the lease duration plus the reaper interval. It is a polling interval, not a hard bound.

## Redelivery storms and lease loss

**Symptoms:** `jobs.redelivered` well above baseline, `jobs.lease_lost` rising, `worker.lease.aborts{reason=budget}` rising.

**Metrics:** `jobs.redelivered`, `jobs.lease_lost{operation}`, `lease.renewals`, `worker.lease.aborts{reason=lost|budget|cancelled}`, `worker.publish.retries`.

```sql
-- Jobs on a later attempt, by queue
SELECT org_id, queue, attempt, count(*) AS jobs
FROM jobs
WHERE state IN (1, 2) AND attempt > 1
GROUP BY org_id, queue, attempt
ORDER BY jobs DESC LIMIT 20;
```

**Reading the signals**

| Signal | Meaning |
|---|---|
| `worker.lease.aborts{reason=budget}` | The worker could not confirm a renewal before its local deadline: network partition, slow API, or CPU starvation. The worker stopped the command and discarded the WAL |
| `worker.lease.aborts{reason=lost}` | The server rejected a renewal: the lease had already been reclaimed |
| `jobs.lease_lost{operation=publish}` with no matching aborts | A stale worker was still publishing. The server fenced it |
| `worker.jobs.abandoned{reason=flush_timeout}` | The command finished but events could not be published before the lease budget ran out. The job re-runs by design |
| `jobs.lease_lost{operation=renew}` after a deploy | Old and new servers disagree on the token signing secret (`invalid task token` is InvalidArgument, not lease loss); check the secret |

**Action**

1. Check API latency and error rates from the workers' network. Renewals use `min(5s, remaining budget)`.
2. Check database lock waits (previous section). A 5s lock timeout returns Unavailable, which the controller retries within its budget.
3. If a worker host is overloaded or suspended, a stalled process cannot stop on time. Fencing protects the job store but not external effects. Commands with side effects need idempotency keys.
4. If storms follow a longer-running workload, raise `--visibility-timeout` (renewal still runs every one third of it).

## Cancellation timing

**Symptom:** a cancelled job's command keeps running.

```sql
SELECT job_id, state, attempt, updated_at, now() - updated_at AS since_cancel
FROM jobs
WHERE job_id = '<job-uuid>';
```

State 5 means the server side is done. The worker learns at its next publish or renewal, whichever comes first.

| Case | Bound |
|---|---|
| Connected worker, producing output | About 2s (event batch flush) plus one publish RPC to detect, plus up to 5s for SIGTERM to SIGKILL |
| Connected worker, silent | Up to `1.25 x timeout/3 + 5s` to detect, plus up to 5s for SIGTERM to SIGKILL. About 135s at the 300s default, about 22.5s at 30s |
| Partitioned worker | The local lease deadline (`timeout` minus `max(2s, timeout/10)` after the last confirmed renewal) |
| Scheduled job | Immediate: it is never dequeued |

**Action**

1. Wait for the bound for the job's `visibility-timeout` before escalating.
2. Check the worker log for `job cancelled; stopping execution` (publish saw it) or `lease aborted` with `lease cancelled` (renewal saw it), then `job cancelled`.
3. If the worker is unreachable, the job is already fenced; stop the process or host directly.

## Retention backlog and scheduling cleanup

**Symptoms:** `retention.oldest_eligible_age` above 1 day, `retention.sweep_errors`, table growth.

**Metrics:** `retention.oldest_eligible_age`, `retention.sweep_duration`, `retention.sweep_errors{category}`, `retention.{events,jobs,sessions}_deleted`.

Check backlog at a fixed cutoff (see [SQL audit queries](#sql-audit-queries) for the full set):

```sql
SELECT count(*) AS terminal_jobs_past_90_days
FROM jobs
WHERE state IN (3, 4, 5) AND updated_at < now() - make_interval(days => 90);
```

**Action when behind**

1. Look for `Retention sweep failed` with a `category` of `clock`, `events` or `jobs`.
2. A single in-process pass deletes at most 10,000 rows per category. Run `cleanup` with a higher `--max-batches` to drain faster:

```bash
airunner-server cleanup --max-batches=1000
```

3. If the `events` category fails repeatedly, check for long transactions holding job rows; the sweep skips locked jobs (`SKIP LOCKED`) rather than blocking.

### Run cleanup on a schedule

Set `--retention-interval=0` on the server to turn off in-process retention and session sweeps. The reaper keeps running. Then run `airunner-server cleanup` from a scheduler. It runs one pass and exits, never migrates and never starts the reaper. It needs `POSTGRES_CONNECTION_STRING` and `AIRUNNER_POSTGRES_TOKEN_SECRET` (at least 32 bytes) even though it signs no tokens, and it must use the same `--job-retention-days` and `--events-retention-days` as the server. Exit status is non-zero if any category failed; with backlog remaining it logs a warning and exits 0.

**Cron (hourly)**

```cron
7 * * * * . /etc/airunner/cleanup.env && /usr/local/bin/airunner-server cleanup --max-batches=100 >> /var/log/airunner-cleanup.log 2>&1
```

**ECS scheduled task (sketch)**

```json
{
  "family": "airunner-cleanup",
  "containerDefinitions": [{
    "name": "cleanup",
    "image": "<your server image>",
    "command": ["cleanup", "--max-batches=100"],
    "environment": [
      {"name": "AIRUNNER_JOB_RETENTION_DAYS", "value": "90"},
      {"name": "AIRUNNER_EVENTS_RETENTION_DAYS", "value": "30"}
    ],
    "secrets": [
      {"name": "POSTGRES_CONNECTION_STRING", "valueFrom": "<secret arn>"},
      {"name": "AIRUNNER_POSTGRES_TOKEN_SECRET", "valueFrom": "<secret arn>"}
    ]
  }]
}
```

Create an EventBridge rule `rate(1 hour)` that runs this task definition. Alert on a non-zero task exit code. Adjust `command` to match your image's entrypoint (the example assumes the entrypoint is `airunner-server`).

**Kubernetes CronJob**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: airunner-cleanup
spec:
  schedule: "7 * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 1
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: cleanup
              image: <your server image>
              args: ["cleanup", "--max-batches=100"]
              env:
                - name: AIRUNNER_JOB_RETENTION_DAYS
                  value: "90"
                - name: AIRUNNER_EVENTS_RETENTION_DAYS
                  value: "30"
              envFrom:
                - secretRef:
                    name: airunner-db   # POSTGRES_CONNECTION_STRING, AIRUNNER_POSTGRES_TOKEN_SECRET
```

Overlapping runs are safe (`SKIP LOCKED`), but `Forbid` avoids wasted work. Pass `--tracing` (env `AIRUNNER_TRACING`) to export `retention.*` metrics from the job.

## Failed WAL diagnostics

Worker WALs live on the worker host under `~/.airunner/wal` (there is no flag to change it; set `HOME` for the worker process).

| Path | Contents |
|---|---|
| `~/.airunner/wal/<job-id>/<attempt>.wal` | An active attempt. Locked with `flock` while the worker runs |
| `~/.airunner/wal/failed/<job-id>-<attempt>.wal` | Discarded or stale WALs kept by `--keep-failed-wal=<duration>` |
| `~/.airunner/archive/<job-id>-<attempt>.wal.zst` | WALs archived after a confirmed completion (zstd) |

**What happens to a WAL**

| Event | Result |
|---|---|
| Lease lost, budget exhausted, cancel, permanent publish error, flush timeout | Deleted, or moved to `failed/` if `--keep-failed-wal` is set |
| `CompleteJob` failed without a lease-loss answer (response lost) | Always moved to `failed/` (log: `complete response lost; WAL kept in failed/ for diagnosis`). Pruned on the next start under the `--keep-failed-wal` rule |
| Confirmed completion | Archived |
| Worker restart | `CleanupStale` deletes (or moves to `failed/`) every WAL it can lock, logs `Cleaned up stale WAL` with job, attempt and pending count, and prunes `failed/` by age. Archives older than `--archive-retention` are deleted |

Keeping failed WALs for a day:

```bash
airunner-cli worker --keep-failed-wal=24h
```

Records on disk are never uploaded under a new lease; the job is redelivered and re-run. The WAL exists only for diagnosis.

**Inspect**

```bash
ls -l ~/.airunner/wal ~/.airunner/wal/failed
lsof ~/.airunner/wal/<job-id>/<attempt>.wal        # who holds the lock
zstd -dc ~/.airunner/archive/<job-id>-<attempt>.wal.zst | head -c 36 | xxd   # header
```

The header is 36 bytes: `ARWAL001`, version 2, job UUID, attempt. Compare it with the file name. The committed log is on the server, not in the WAL; stream it with `airunner-cli monitor --attempt N <job-id>`.

Grep the worker log for: `WAL publishing stopped` (sticky error), `Recreating stale WAL file`, `Cleaned up stale WAL`, `WAL discarded`, `Abandoning job without completing`.

Interpreting a pending count: in `Cleaned up stale WAL` it is an upper bound, because sent status is held in memory and a crashed WAL looks fully pending.

**Archive growth.** The worker deletes archives older than `--archive-retention` (default 168h) at startup; 0 keeps them. A long-running worker prunes only when it restarts. To keep 30 days:

```bash
airunner-cli worker --archive-retention=720h
```

Metrics: `worker.wal.pending_records`, `worker.wal.failed_deleted`, `worker.publish.retries`, `worker.publish.ack_latency`.

## Idempotency and retention limits

- `request_id` is unique per org only while the job row exists. After retention deletes the job (90 days by default, `--job-retention-days`), the same `request_id` creates a new job. Idempotency lasts for job retention.
- Re-sending a `request_id` with a different queue, `job_params` or `max_attempts` returns AlreadyExists. An omitted `max_attempts` stays "omitted" even if the server default changes.
- Events are deleted `--events-retention-days` (30) after the job's last update. After that, `monitor` and the dashboard show status only for that job. `--events-retention-days=0` keeps events until the job is deleted. Events retention cannot exceed job retention.
- Retention measures from `jobs.updated_at` using the database clock. A cancel or completion resets the age.
- Deletion is eventual: it depends on the sweep schedule, backlog and database availability.
- Retention never deletes SCHEDULED or RUNNING jobs. A stuck RUNNING job is the reaper's concern; a stuck SCHEDULED job can be cancelled.

```sql
-- Oldest jobs per state
SELECT state, count(*) AS jobs, min(updated_at) AS oldest_update
FROM jobs GROUP BY state ORDER BY state;
```

## Stalled streams

A stream send that blocks longer than `--stream-send-timeout` (30s) ends with DeadlineExceeded and increments `streams.stalled`. The client reconnects from its last sequence.

**Symptoms:** sustained `streams.stalled`; `streams.active` growing without bound; `monitor` reporting DeadlineExceeded.

**Action**

1. Identify the reader (a paused terminal, a slow browser tab, a proxy that buffers). A reader that stops reading cannot hold a stream beyond one send timeout.
2. Reconnect with `airunner-cli monitor --from-sequence=<last> --attempt <n> <job-id>`.
3. A growing `streams.active` without stalls means readers are connected to long jobs. Each costs one query per `--event-poll-interval` (500ms). Raise the interval if query rate is a concern.
4. `streams.delivery_lag` uses worker clocks; a jump may be clock skew, not slow delivery.
5. A stream on a job whose events were purged returns status only. A stream on a deleted job returns NotFound.

## Authz denials

**Metric:** `authz.denied{procedure, reason=unauthenticated|forbidden}`.

| Reason | Meaning | Check |
|---|---|---|
| `unauthenticated` | No principal reached the interceptor | JWT missing or expired, session cookie missing, credential not imported. Check `airunner-cli credentials list` |
| `forbidden` | A principal without an allowed role, or an unknown job procedure | Role matrix below |

| RPC | Roles |
|---|---|
| EnqueueJob, ListJobs, CancelJob, StreamJobEvents | user, admin |
| DequeueJob, UpdateJob, CompleteJob, PublishJobEvents | worker, admin |

```sql
SELECT principal_id, org_id, type, name, roles, deleted_at
FROM principals
WHERE principal_id = '<principal-uuid>';
```

Common causes: a worker credential used to submit jobs, a user session used as a worker, a revoked principal (`deleted_at` set). The log line `authz: permission denied` carries the procedure, principal and org. NotFound for a job that exists means the caller is in a different org; that is by design.

## SQL audit queries

All queries are read-only. Replace `now()` with a fixed timestamp to compare before and after a sweep. After a fully drained sweep, the eligible counts at that cutoff should be zero.

```sql
-- 1. Attempt bounds: must return no rows
SELECT job_id, attempt, max_attempts FROM jobs
WHERE attempt < 0 OR attempt > max_attempts OR max_attempts NOT BETWEEN 1 AND 100;

-- 2. Lease columns exist exactly when RUNNING: must return no rows
SELECT job_id, state FROM jobs
WHERE (state = 2) <> (visibility_until IS NOT NULL AND receipt_handle IS NOT NULL AND leased_by IS NOT NULL);

-- 3. Expired running leases at the cutoff
SELECT count(*), min(visibility_until) FROM jobs
WHERE state = 2 AND visibility_until <= now();

-- 4. Event rows past the event cutoff (30 days)
SELECT count(*) FROM job_events e JOIN jobs j USING (job_id)
WHERE j.state IN (3, 4, 5) AND j.updated_at < now() - make_interval(days => 30);

-- 5. Terminal jobs past the job cutoff (90 days)
SELECT count(*) FROM jobs
WHERE state IN (3, 4, 5) AND updated_at < now() - make_interval(days => 90);

-- 6. Expired sessions
SELECT count(*) FROM sessions WHERE expires_at <= now();

-- 7. last_event_sequence matches the highest covered sequence of the current attempt
SELECT j.job_id, j.attempt, j.last_event_sequence, COALESCE(max(e.end_sequence), 0) AS stored
FROM jobs j LEFT JOIN job_events e ON e.job_id = j.job_id AND e.attempt = j.attempt
WHERE j.attempt > 0
GROUP BY j.job_id, j.attempt, j.last_event_sequence
HAVING j.last_event_sequence <> COALESCE(max(e.end_sequence), 0)
LIMIT 20;

-- 8. Events per job attempt with gaps in the sequence space: must return no rows
SELECT job_id, attempt FROM (
  SELECT job_id, attempt, sequence,
         lag(end_sequence, 1, 0) OVER (PARTITION BY job_id, attempt ORDER BY sequence) AS prev_end
  FROM job_events) t
WHERE sequence <> prev_end + 1 LIMIT 20;

-- 9. Jobs per state per org
SELECT org_id, state, count(*) FROM jobs GROUP BY org_id, state ORDER BY org_id, state;

-- 10. Schema sanity: composite organization foreign keys are present
SELECT conname FROM pg_constraint
WHERE conrelid = 'jobs'::regclass AND contype = 'f' ORDER BY conname;

-- 11. Applied migrations (must match the files in the migrations directory)
SELECT version, applied_at FROM schema_migrations ORDER BY version;
```

Notes:

- Query 7 can flag a row mid-publish; rerun it before acting. After a cancel, `last_event_sequence` is unchanged, so it still matches.
- Query 10 should list `jobs_created_by_org_fkey`, `jobs_leased_by_org_fkey` and `jobs_org_id_fkey`. If it shows `jobs_created_by_fkey` or `jobs_leased_by_fkey` instead, or query 11 lists a version with no file, the database predates the current migrations. Recreate it (see the reset below); migrations already recorded are skipped, so the new files do not apply.
- Check dequeue plans after `ANALYZE`, once with `plan_cache_mode = force_generic_plan`. A small table may legitimately choose a sequential scan.

```sql
PREPARE audit_dequeue(uuid, varchar) AS
SELECT job_id FROM jobs
WHERE org_id = $1 AND queue = $2 AND state = 1 AND attempt < max_attempts
ORDER BY created_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED;
-- EXPLAIN EXECUTE audit_dequeue('<org-uuid>', 'default');   -- run inside BEGIN ... ROLLBACK
DEALLOCATE audit_dequeue;
```

## Local Compose reset (DESTRUCTIVE)

> **DESTRUCTIVE. LOCAL DEVELOPMENT ONLY. OPT-IN.** This deletes the Compose PostgreSQL volume: every job, event, organization, principal, imported credential and session is lost. Never run it against a shared or production database. Never run it as part of a review, a test run or an automated check. Integration tests use isolated testcontainers databases and do not need it. Run these commands one at a time, typed by a person who has confirmed the target is the local Compose project.

Use it when migrations will not apply (the database recorded an older `schema_migrations` version) or when you want a clean slate.

1. Confirm the target. The output must show the local `postgres` service of this project and no remote host:

```bash
docker compose ps
echo "$POSTGRES_CONNECTION_STRING" | sed -E 's#//[^@]*@#//***@#'  # host only; never print the password
```

2. Stop the server and worker (`goreman` or `air`).

3. Delete the volume. This is the destructive step:

```bash
docker compose down -v
```

4. Start PostgreSQL and wait for health:

```bash
docker compose up -d postgres
docker compose ps
```

5. Start the server with migrations enabled. `Procfile.dev` already passes `--postgres-auto-migrate` and `--no-auth`:

```bash
direnv exec . goreman -f Procfile.dev start
```

6. Re-register credentials. The reset deleted all principals, so CLI credentials and sessions return 401:
   - With `--no-auth`, the server seeds the development org and principal on start. No credential is needed.
   - With authentication, log in to the dashboard with GitHub (this recreates your user and org), import the worker public key in the Credentials view, then run `airunner-cli credentials update --org-id=<id> --principal-id=<id> <name>`.

7. Verify with the read-only queries 10 and 11 above. `schema_migrations` must list exactly the migration files.

## Metrics reference

Full tables, attributes and alert starting points are in [05b-phase5b-metrics.md](05b-phase5b-metrics.md). Labels are bounded enums; none carry job IDs, tokens, org IDs or queue names.

| Question | Instrument |
|---|---|
| Are jobs being redelivered or dead-lettered? | `jobs.redelivered`, `jobs.dead_lettered` |
| Are workers losing leases? | `jobs.lease_lost{operation}`, `worker.lease.aborts{reason}`, `worker.jobs.abandoned{reason}` |
| Is the reaper keeping up? | `reaper.backlog`, `reaper.oldest_expired_age`, `reaper.sweep_duration` |
| Is retention keeping up? | `retention.oldest_eligible_age`, `retention.sweep_errors{category}`, `retention.sweep_duration` |
| Is publishing healthy? | `events.published`, `events.publish_replays`, `events.publish_rejected{reason}`, `events.publish_duration`, `worker.publish.retries`, `worker.publish.ack_latency` |
| Are streams healthy? | `streams.active`, `streams.stalled`, `streams.delivery_lag` |
| Is access denied? | `authz.denied{procedure, reason}` |
| Is the worker WAL backing up? | `worker.wal.pending_records`, `worker.wal.failed_deleted` |
| Are cancels arriving? | `jobs.cancelled{from}` |

| Alert starting point | Condition |
|---|---|
| Redelivery storm | `jobs.redelivered` rate well above baseline, especially with `worker.lease.aborts{reason=budget}` |
| Dead letters | any increase in `jobs.dead_lettered` |
| Reaper behind | `reaper.oldest_expired_age` above 60s for 5 minutes |
| Retention behind | `retention.oldest_eligible_age` above 1 day, or any `retention.sweep_errors` |
| Client bugs | `events.publish_rejected{reason=conflict or invalid}` above zero |
| Stalled readers | sustained `streams.stalled` |

Enable export with `--tracing` (env `AIRUNNER_TRACING`) on `airunner-server server`, `airunner-server cleanup` and `airunner-cli worker`, and the standard `OTEL_EXPORTER_OTLP_*` variables.

## Additional resources

- [README.md](README.md), [00-architecture.md](00-architecture.md)
- Phases: [1](01-phase1-worker-events.md), [2](02-phase2-schema-contract.md), [3](03-phase3-tenancy-authz.md), [4a](04a-phase4a-fencing.md), [4b](04b-phase4b-worker-durability.md), [4c](04c-phase4c-event-streams.md), [5a](05a-phase5a-retention.md), [5b](05b-phase5b-metrics.md), [6](06-phase6-cancellation.md), [7](07-phase7-documentation.md)
- Examples: [schema](examples/schema.md), [fenced publish](examples/fenced-publish.md), [bounded sweeps](examples/bounded-sweeps.md), [authz interceptor](examples/authz-interceptor.md), [reference model](examples/reference-model.md), [contract test skeleton](examples/contract-test-skeleton.md)

[← README](README.md) | [Architecture](00-architecture.md) | [Phase 7 →](07-phase7-documentation.md)
