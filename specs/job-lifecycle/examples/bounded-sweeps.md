# Example: bounded sweeps (reaper and retention)

[← README](../README.md) | [← Fenced publish](fenced-publish.md) | [Authz interceptor →](authz-interceptor.md)

Source of truth: [job_store.go](../../../internal/store/postgres/job_store.go) (reaper) and [job_store_retention.go](../../../internal/store/postgres/job_store_retention.go) (retention)

These are excerpts, trimmed with `// ...`. If they differ from the source, the source wins. Behaviour is described in [00-architecture.md](../00-architecture.md#retention) and [05a-phase5a-retention.md](../05a-phase5a-retention.md).

## Shared rules

- Every sweep is bounded twice: rows per statement and statements per pass.
- Rows are claimed with `FOR UPDATE SKIP LOCKED`, so replicas never block each other and never double-count.
- State predicates are literals so the partial indexes apply.
- A short batch means the category drained and ends the pass early.

## Reaper: exhaustion rule and batch constants

Release and the reaper share one rule: a job that has used every attempt fails with a reason; otherwise it returns to SCHEDULED.

```go
const (
	nextStateSQL = `CASE WHEN attempt < max_attempts THEN 1 ELSE 4 END`
	exhaustedSQL = `CASE WHEN attempt < max_attempts THEN NULL
		ELSE jsonb_build_object('job_id', jobs.job_id, 'reason', 'delivery attempts exhausted') END`
)

const (
	reaperBatchSize  = 100
	reaperMaxBatches = 10
)
```

## Reaper: ReapExpired

The scan uses `idx_jobs_lease`. A row locked by an in-flight publish is skipped and picked up on the next tick. The expiry predicate uses `clock_timestamp()`, which is re-evaluated against the locked row.

```go
	rows, err := s.pool.Query(queryCtx, `
		WITH expired AS (
			SELECT job_id
			FROM jobs
			WHERE state = 2 AND visibility_until <= clock_timestamp()
			ORDER BY visibility_until, job_id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE jobs
		SET
			state = `+nextStateSQL+`,
			result = `+exhaustedSQL+`,
			visibility_until = NULL,
			receipt_handle = NULL,
			leased_by = NULL,
			updated_at = clock_timestamp()
		FROM expired
		WHERE jobs.job_id = expired.job_id
		RETURNING jobs.state
	`, limit)
```

## Reaper: tick loop

```go
	total := 0
	for range reaperMaxBatches {
		n, err := s.ReapExpired(ctx, reaperBatchSize)
		total += n
		if err != nil {
			if ctx.Err() == nil {
				log.Error().Err(err).Msg("Failed to reap expired leases")
			}
			break
		}
		if n < reaperBatchSize {
			break
		}
	}
```

## Retention: PurgeEvents

Job rows are locked first (at most 100), then their events are deleted, matching the lock order of publish. Only terminal jobs qualify, so no live writer can need the deleted rows.

```go
	tag, err := s.pool.Exec(queryCtx, `
		WITH eligible AS (
			SELECT job_id FROM jobs
			WHERE state IN (3, 4, 5) AND updated_at < $1
				AND EXISTS (SELECT 1 FROM job_events e WHERE e.job_id = jobs.job_id)
			ORDER BY updated_at, job_id
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		), doomed AS (
			SELECT e.job_id, e.attempt, e.sequence
			FROM job_events e JOIN eligible USING (job_id)
			LIMIT $2
		)
		DELETE FROM job_events e USING doomed d
		WHERE e.job_id = d.job_id AND e.attempt = d.attempt AND e.sequence = d.sequence
	`, cutoff, limit, retentionJobLockLimit)
```

## Retention: PurgeJobs

A job is deleted only once it has no events left, so the `ON DELETE CASCADE` is a safety net and not the bounded path.

```go
	tag, err := s.pool.Exec(queryCtx, `
		DELETE FROM jobs WHERE job_id IN (
			SELECT job_id FROM jobs
			WHERE state IN (3, 4, 5) AND updated_at < $1
				AND NOT EXISTS (SELECT 1 FROM job_events e WHERE e.job_id = jobs.job_id)
			ORDER BY updated_at, job_id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
	`, cutoff, limit)
```

## Retention: bounds and cutoffs

Cutoffs come from the database clock, read once per pass. When `EventRetention` is 0, events live as long as their job.

```go
const (
	retentionBatchSize = 1000
	retentionMaxBatches = 10
	retentionJobLockLimit = 100
)
// ...
	eventRetention := s.cfg.EventRetention
	if eventRetention == 0 {
		eventRetention = s.cfg.JobRetention
	}
	eventCutoff := now.Add(-eventRetention)
	jobCutoff := now.Add(-s.cfg.JobRetention)
```

## Sessions: bounded delete

```go
	query := `
		DELETE FROM sessions WHERE session_id IN (
			SELECT session_id FROM sessions WHERE expires_at < clock_timestamp()
			ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)`
```

Source: [session_store.go](../../../internal/store/postgres/session_store.go)

[← README](../README.md) | [← Fenced publish](fenced-publish.md) | [Authz interceptor →](authz-interceptor.md)
