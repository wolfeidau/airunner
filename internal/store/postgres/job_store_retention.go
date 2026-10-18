package postgres

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	// retentionBatchSize is the maximum rows deleted per Purge call from the sweep.
	retentionBatchSize = 1000
	// retentionMaxBatches bounds the Purge calls per category in one sweep.
	retentionMaxBatches = 10
	// retentionJobLockLimit bounds how many job rows PurgeEvents locks per call.
	retentionJobLockLimit = 100
)

// PurgeEvents deletes up to limit event rows of terminal jobs last updated before cutoff.
// Job rows are locked (skipping locked ones) before their events are touched, matching the
// publish lock ordering. It returns the number of events deleted.
func (s *JobStore) PurgeEvents(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

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
	if err != nil {
		return 0, mapPostgresError(err)
	}

	return int(tag.RowsAffected()), nil
}

// PurgeJobs deletes up to limit terminal jobs last updated before cutoff that have no
// events left. It returns the number of jobs deleted.
func (s *JobStore) PurgeJobs(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

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
	if err != nil {
		return 0, mapPostgresError(err)
	}

	return int(tag.RowsAffected()), nil
}

// runRetention sweeps immediately and then every RetentionInterval until ctx ends.
func (s *JobStore) runRetention(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.RetentionInterval)
	defer ticker.Stop()

	s.retentionTick(ctx)

	for {
		select {
		case <-ticker.C:
			s.retentionTick(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// retentionTick purges events and then jobs older than their retention, using the database
// clock. Each category runs at most retentionMaxBatches batches; remaining work is picked up
// by the next tick.
func (s *JobStore) retentionTick(ctx context.Context) {
	var now time.Time
	queryCtx, cancel := s.withQueryTimeout(ctx)
	err := s.pool.QueryRow(queryCtx, `SELECT clock_timestamp()`).Scan(&now)
	cancel()
	if err != nil {
		s.retentionError(ctx, "clock", err)
		return
	}

	eventRetention := s.cfg.EventRetention
	if eventRetention == 0 {
		eventRetention = s.cfg.JobRetention
	}
	eventCutoff := now.Add(-eventRetention)
	jobCutoff := now.Add(-s.cfg.JobRetention)

	m := telemetry.GetMetrics()

	events := s.purgeBatches(ctx, "events", func() (int, error) {
		return s.PurgeEvents(ctx, eventCutoff, retentionBatchSize)
	})
	if events > 0 {
		m.RetentionEventsDeleted.Add(ctx, int64(events))
		log.Info().Int("deleted", events).Msg("Deleted expired job events")
	}

	jobs := s.purgeBatches(ctx, "jobs", func() (int, error) {
		return s.PurgeJobs(ctx, jobCutoff, retentionBatchSize)
	})
	if jobs > 0 {
		m.RetentionJobsDeleted.Add(ctx, int64(jobs))
		log.Info().Int("deleted", jobs).Msg("Deleted expired jobs")
	}
}

// purgeBatches runs purge up to retentionMaxBatches times, stopping on a short batch,
// cancellation or error, and returns the total deleted.
func (s *JobStore) purgeBatches(ctx context.Context, category string, purge func() (int, error)) int {
	total := 0
	for range retentionMaxBatches {
		if ctx.Err() != nil {
			break
		}
		n, err := purge()
		total += n
		if err != nil {
			s.retentionError(ctx, category, err)
			break
		}
		if n < retentionBatchSize {
			break
		}
	}
	return total
}

func (s *JobStore) retentionError(ctx context.Context, category string, err error) {
	if ctx.Err() != nil {
		return
	}
	log.Error().Err(err).Str("category", category).Msg("Retention sweep failed")
	telemetry.GetMetrics().RetentionSweepErrors.Add(ctx, 1,
		metric.WithAttributes(attribute.String("category", category)))
}
