package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/util"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// maxAttemptsLimit is the upper bound for a job's max_attempts.
	maxAttemptsLimit = 100

	// defaultVisibilityTimeoutSeconds is the lease duration when the caller does not request one.
	defaultVisibilityTimeoutSeconds = 300
)

// JobStore implements the store.JobStore interface using PostgreSQL as the backend.
// It provides FIFO queue semantics with visibility timeouts, idempotent job enqueuing,
// and event streaming with historical replay.
type JobStore struct {
	pool *pgxpool.Pool
	cfg  *JobStoreConfig

	// Lifecycle. lcMu guards state, lifeCtx and lifeCancel; wg.Add is only called
	// while the store is started so Stop's wg.Wait cannot race with it.
	lcMu       sync.RWMutex
	state      lifecycleState
	lifeCtx    context.Context
	lifeCancel context.CancelFunc
	wg         sync.WaitGroup
}

type lifecycleState int

const (
	stateNew lifecycleState = iota
	stateStarted
	stateStopped
)

// stopTimeout bounds how long Stop waits for background tasks.
const stopTimeout = 10 * time.Second

// NewJobStore creates a new PostgreSQL-backed job store.
// The pool parameter should be a shared connection pool created via postgres.NewPool().
// Migrations should be run separately via postgres.RunMigrations() before creating stores.
func NewJobStore(pool *pgxpool.Pool, cfg *JobStoreConfig) (*JobStore, error) {
	// Apply defaults and validate config
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if pool == nil {
		return nil, fmt.Errorf("pool cannot be nil")
	}

	return &JobStore{
		pool: pool,
		cfg:  cfg,
	}, nil
}

// Start initializes the job store and starts background tasks.
// It is idempotent while started and returns an error after Stop.
func (s *JobStore) Start() error {
	s.lcMu.Lock()
	defer s.lcMu.Unlock()

	switch s.state {
	case stateStarted:
		return nil
	case stateStopped:
		return errors.New("job store is stopped and cannot be restarted")
	}

	log.Info().Msg("Starting PostgreSQL job store")

	s.lifeCtx, s.lifeCancel = context.WithCancel(context.Background())
	s.state = stateStarted

	// Start connection pool monitoring goroutine
	lifeCtx := s.lifeCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.monitorConnectionPool(lifeCtx)
	}()

	// Start lease reaper goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runReaper(lifeCtx)
	}()

	return nil
}

// Stop gracefully shuts down background tasks and open event streams.
// It is idempotent. It does not close the connection pool, which is owned by the caller.
func (s *JobStore) Stop() error {
	s.lcMu.Lock()
	switch s.state {
	case stateStopped:
		s.lcMu.Unlock()
		return nil
	case stateNew:
		s.state = stateStopped
		s.lcMu.Unlock()
		return nil
	}
	s.state = stateStopped
	cancel := s.lifeCancel
	s.lcMu.Unlock()

	log.Info().Msg("Stopping PostgreSQL job store")

	// Signal shutdown; stream goroutines observe the lifecycle ctx and close their own channels.
	cancel()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(stopTimeout):
		return fmt.Errorf("timed out after %s waiting for job store background tasks to stop", stopTimeout)
	}

	log.Info().Msg("PostgreSQL job store stopped")
	return nil
}

// monitorConnectionPool logs connection pool statistics periodically.
func (s *JobStore) monitorConnectionPool(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := s.pool.Stat()
			log.Debug().
				Int32("total_conns", stats.TotalConns()).
				Int32("idle_conns", stats.IdleConns()).
				Int32("acquired_conns", stats.AcquiredConns()).
				Int64("acquire_count", stats.AcquireCount()).
				Int64("acquire_duration_ns", stats.AcquireDuration().Nanoseconds()).
				Msg("Connection pool stats")
		case <-ctx.Done():
			return
		}
	}
}

// EnqueueJob adds a new job to the caller's org queue with idempotency support.
// A retry with the same request_id and the same intent returns the existing job;
// the same request_id with a different intent returns store.ErrConflict.
func (s *JobStore) EnqueueJob(ctx context.Context, caller store.Caller, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error) {
	// Apply query timeout
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	maxAttempts := s.cfg.DefaultMaxAttempts
	if req.MaxAttempts != nil {
		maxAttempts = req.GetMaxAttempts()
		if maxAttempts < 1 || maxAttempts > maxAttemptsLimit {
			return nil, fmt.Errorf("%w: invalid max_attempts %d: must be between 1 and %d", store.ErrInvalidArgument, maxAttempts, maxAttemptsLimit)
		}
	}

	fingerprint, err := enqueueFingerprint(req.Queue, req.JobParams, req.MaxAttempts)
	if err != nil {
		return nil, err
	}

	// Generate new job ID
	jobUUID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate job ID: %w", err)
	}
	jobID := jobUUID.String()
	now := time.Now()

	// Use default execution config
	execConfig := s.cfg.DefaultExecutionConfig

	// Marshal job params and execution config to JSON for JSONB columns
	jobParamsJSON, err := util.MarshalProtoJSON(req.JobParams)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal job_params: %w", err)
	}

	execConfigJSON, err := util.MarshalProtoJSON(execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal execution_config: %w", err)
	}

	// Insert job (state 1 = SCHEDULED)
	query := `
		INSERT INTO jobs (
			job_id, org_id, created_by, queue, state, request_id, request_fingerprint,
			attempt, max_attempts, created_at, updated_at, job_params, execution_config
		) VALUES (
			$1, $2, $3, $4, 1, $5, $6, 0, $7, $8, $9, $10, $11
		)
		ON CONFLICT (org_id, request_id) DO NOTHING
		RETURNING job_id
	`

	var returnedJobID string
	err = s.pool.QueryRow(queryCtx, query,
		jobID,
		caller.OrgID,
		caller.PrincipalID,
		req.Queue,
		req.RequestId,
		fingerprint,
		maxAttempts,
		now,
		now,
		jobParamsJSON,
		execConfigJSON,
	).Scan(&returnedJobID)

	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, mapPostgresError(err)
		}

		// Conflict occurred, fetch the existing job and compare intent
		var existingID string
		var createdAt time.Time
		var state jobv1.JobState
		var existingFingerprint []byte
		err = s.pool.QueryRow(queryCtx, `
			SELECT job_id, created_at, state, request_fingerprint
			FROM jobs
			WHERE org_id = $1 AND request_id = $2
		`, caller.OrgID, req.RequestId).Scan(&existingID, &createdAt, &state, &existingFingerprint)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("concurrent insert conflict but job not found")
			}
			return nil, mapPostgresError(err)
		}

		if !bytes.Equal(existingFingerprint, fingerprint) {
			return nil, fmt.Errorf("%w: request_id %q was used with a different job", store.ErrConflict, req.RequestId)
		}

		log.Debug().
			Str("job_id", existingID).
			Str("request_id", req.RequestId).
			Msg("Job already exists (idempotent)")
		return &jobv1.EnqueueJobResponse{
			JobId:     existingID,
			CreatedAt: timestamppb.New(createdAt),
			State:     state,
		}, nil
	}

	log.Info().
		Str("job_id", jobID).
		Str("queue", req.Queue).
		Str("request_id", req.RequestId).
		Msg("Enqueued job")

	// Return the response
	return &jobv1.EnqueueJobResponse{
		JobId:     jobID,
		CreatedAt: timestamppb.New(now),
		State:     jobv1.JobState_JOB_STATE_SCHEDULED,
	}, nil
}

// DequeueJobs claims jobs from the caller's org queue using SELECT FOR UPDATE SKIP LOCKED.
// Returns at most maxJobs SCHEDULED jobs with attempts remaining, oldest first.
// Each acquisition consumes an attempt.
func (s *JobStore) DequeueJobs(ctx context.Context, caller store.Caller, queue string, maxJobs int, timeoutSeconds int) ([]*store.JobWithToken, error) {
	// Apply query timeout
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultVisibilityTimeoutSeconds
	}

	// State predicates are literals (1=SCHEDULED, 2=RUNNING) so generic plans can
	// prove the idx_jobs_dequeue partial index predicate.
	query := `
		WITH claimable AS (
			SELECT job_id
			FROM jobs
			WHERE org_id = $1
			  AND queue = $2
			  AND state = 1
			  AND attempt < max_attempts
			ORDER BY created_at ASC, job_id ASC
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE jobs
		SET
			state = 2,
			attempt = jobs.attempt + 1,
			last_event_sequence = 0,
			result = NULL,
			leased_by = $4,
			visibility_until = NOW() + $5 * INTERVAL '1 second',
			receipt_handle = gen_random_uuid(),
			updated_at = NOW()
		FROM claimable
		WHERE jobs.job_id = claimable.job_id
		RETURNING jobs.job_id, jobs.queue, jobs.receipt_handle, jobs.created_at, jobs.updated_at,
		          jobs.job_params, jobs.execution_config, jobs.attempt, jobs.max_attempts
	`

	rows, err := s.pool.Query(queryCtx, query,
		caller.OrgID,
		queue,
		maxJobs,
		caller.PrincipalID,
		timeoutSeconds,
	)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()

	var results []*store.JobWithToken
	for rows.Next() {
		var jobID, queueName, receiptHandle string
		var createdAt, updatedAt time.Time
		var jobParamsJSON, execConfigJSON []byte
		var attempt, maxAttempts int32

		err := rows.Scan(
			&jobID,
			&queueName,
			&receiptHandle,
			&createdAt,
			&updatedAt,
			&jobParamsJSON,
			&execConfigJSON,
			&attempt,
			&maxAttempts,
		)
		if err != nil {
			return nil, mapPostgresError(err)
		}

		// Unmarshal job params from JSON
		jobParams := &jobv1.JobParams{}
		if err := util.UnmarshalProtoJSON(jobParamsJSON, jobParams); err != nil {
			return nil, fmt.Errorf("failed to unmarshal job_params: %w", err)
		}

		// Unmarshal execution config from JSON
		execConfig := &jobv1.ExecutionConfig{}
		if err := util.UnmarshalProtoJSON(execConfigJSON, execConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal execution_config: %w", err)
		}

		// Create job
		job := &jobv1.Job{
			JobId:           jobID,
			State:           jobv1.JobState_JOB_STATE_RUNNING,
			CreatedAt:       timestamppb.New(createdAt),
			UpdatedAt:       timestamppb.New(updatedAt),
			JobParams:       jobParams,
			ExecutionConfig: execConfig,
			Attempt:         attempt,
			MaxAttempts:     maxAttempts,
		}

		// Generate task token
		taskToken := s.encodeTaskToken(jobID, queueName, receiptHandle)

		results = append(results, &store.JobWithToken{
			Job:                      job,
			TaskToken:                taskToken,
			VisibilityTimeoutSeconds: int32(timeoutSeconds), //nolint:gosec // bounded by request validation
		})
	}

	if err := rows.Err(); err != nil {
		return nil, mapPostgresError(err)
	}

	// UPDATE ... RETURNING does not preserve the claim order
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i].Job, results[j].Job
		if !a.CreatedAt.AsTime().Equal(b.CreatedAt.AsTime()) {
			return a.CreatedAt.AsTime().Before(b.CreatedAt.AsTime())
		}
		return a.JobId < b.JobId
	})

	// Only log at info level when jobs are actually dequeued
	if len(results) > 0 {
		log.Info().
			Str("queue", queue).
			Int("dequeued", len(results)).
			Int("max_jobs", maxJobs).
			Msg("Dequeued jobs")
	} else {
		log.Debug().
			Str("queue", queue).
			Int("max_jobs", maxJobs).
			Msg("No jobs available to dequeue")
	}

	return results, nil
}

// SQL fragments shared by release and reaping: a job that has used every attempt fails
// with a reason, otherwise it returns to SCHEDULED with an empty result.
const (
	nextStateSQL = `CASE WHEN attempt < max_attempts THEN 1 ELSE 4 END`
	exhaustedSQL = `CASE WHEN attempt < max_attempts THEN NULL
		ELSE jsonb_build_object('job_id', jobs.job_id, 'reason', 'delivery attempts exhausted') END`
)

// fenceTimeoutSQL bounds lock waits and statements inside a fenced transaction.
const fenceTimeoutSQL = `SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '5s'`

// leaseRow is the locked job row a fenced operation runs against.
type leaseRow struct {
	attempt           int32
	lastEventSequence int64
	// operationTime is sampled once with clock_timestamp() after the row lock is held.
	// now() would be frozen at transaction start and could predate a long lock wait.
	operationTime time.Time
}

// lockLease starts a READ COMMITTED transaction, locks the job row and verifies that the
// caller holds a live lease for the token. Any mismatch returns store.ErrLeaseLost with a
// generic message. On success the caller owns the returned transaction and must commit it
// (a deferred Rollback after Commit is a no-op). On error the transaction is already rolled back.
func (s *JobStore) lockLease(ctx context.Context, caller store.Caller, tt *taskToken) (pgx.Tx, *leaseRow, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, mapPostgresError(err)
	}

	row, err := lockLeaseRow(ctx, tx, caller, tt)
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, nil, err
	}

	return tx, row, nil
}

func lockLeaseRow(ctx context.Context, tx pgx.Tx, caller store.Caller, tt *taskToken) (*leaseRow, error) {
	if _, err := tx.Exec(ctx, fenceTimeoutSQL); err != nil {
		return nil, mapPostgresError(err)
	}

	var (
		state, attempt, maxAttempts int32
		queue                       string
		receipt, leasedBy           *string
		visibilityUntil             *time.Time
		lastSeq                     int64
	)
	err := tx.QueryRow(ctx, `
		SELECT state, queue, receipt_handle::text, leased_by::text, visibility_until,
		       attempt, max_attempts, last_event_sequence
		FROM jobs
		WHERE org_id = $1 AND job_id = $2
		FOR UPDATE
	`, caller.OrgID, tt.JobID).Scan(&state, &queue, &receipt, &leasedBy, &visibilityUntil, &attempt, &maxAttempts, &lastSeq)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: no matching lease", store.ErrLeaseLost)
		}
		return nil, mapPostgresError(err)
	}

	var opTime time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&opTime); err != nil {
		return nil, mapPostgresError(err)
	}

	if state != int32(jobv1.JobState_JOB_STATE_RUNNING) ||
		receipt == nil || *receipt != tt.ReceiptHandle ||
		queue != tt.Queue ||
		leasedBy == nil || *leasedBy != caller.PrincipalID.String() ||
		visibilityUntil == nil || !visibilityUntil.After(opTime) {
		return nil, fmt.Errorf("%w: no matching lease", store.ErrLeaseLost)
	}

	return &leaseRow{attempt: attempt, lastEventSequence: lastSeq, operationTime: opTime}, nil
}

// UpdateJobVisibility extends the lease and returns the effective timeout in seconds.
// The receipt handle does NOT change (matches AWS SQS behavior). The new expiry is
// measured from the fenced operation time.
func (s *JobStore) UpdateJobVisibility(ctx context.Context, caller store.Caller, taskToken string, timeoutSeconds int) (int32, error) {
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return 0, err
	}

	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultVisibilityTimeoutSeconds
	}

	tx, row, err := s.lockLease(queryCtx, caller, tt)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(queryCtx)) }()

	_, err = tx.Exec(queryCtx, `
		UPDATE jobs
		SET visibility_until = $1::timestamptz + $2 * INTERVAL '1 second',
		    updated_at = $1
		WHERE org_id = $3 AND job_id = $4
	`, row.operationTime, timeoutSeconds, caller.OrgID, tt.JobID)
	if err != nil {
		return 0, mapPostgresError(err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		return 0, mapPostgresError(err)
	}

	log.Debug().
		Str("job_id", tt.JobID).
		Int("timeout_seconds", timeoutSeconds).
		Msg("Updated job visibility")

	return int32(timeoutSeconds), nil //nolint:gosec // bounded by request validation
}

// CompleteJob marks a job as completed or failed and removes it from the queue.
// finalEventSequence must equal the attempt's last committed event sequence, otherwise
// the job is left RUNNING and store.ErrInvalidArgument is returned.
// Clears the receipt_handle, visibility_until and leased_by fields together.
func (s *JobStore) CompleteJob(ctx context.Context, caller store.Caller, taskToken string, result *jobv1.JobResult, finalEventSequence int64) error {
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
	}

	if result == nil {
		return fmt.Errorf("%w: result is required", store.ErrInvalidArgument)
	}

	if result.JobId != tt.JobID {
		return fmt.Errorf("%w: token job_id=%s, result job_id=%s",
			store.ErrJobIDMismatch, tt.JobID, result.JobId)
	}

	finalState := jobv1.JobState_JOB_STATE_COMPLETED
	if !result.Success {
		finalState = jobv1.JobState_JOB_STATE_FAILED
	}

	resultJSON, err := util.MarshalProtoJSON(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	tx, row, err := s.lockLease(queryCtx, caller, tt)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(queryCtx)) }()

	if finalEventSequence != row.lastEventSequence {
		return fmt.Errorf("%w: final_event_sequence=%d does not match last committed sequence=%d",
			store.ErrInvalidArgument, finalEventSequence, row.lastEventSequence)
	}

	// 3=COMPLETED, 4=FAILED
	_, err = tx.Exec(queryCtx, `
		UPDATE jobs
		SET
			state = CASE WHEN $1::BOOLEAN THEN 3 ELSE 4 END,
			visibility_until = NULL,
			receipt_handle = NULL,
			leased_by = NULL,
			result = $2,
			updated_at = $3
		WHERE org_id = $4 AND job_id = $5
	`, result.Success, resultJSON, row.operationTime, caller.OrgID, tt.JobID)
	if err != nil {
		return mapPostgresError(err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		return mapPostgresError(err)
	}

	log.Info().
		Str("job_id", tt.JobID).
		Str("state", finalState.String()).
		Bool("success", result.Success).
		Msg("Completed job")

	return nil
}

// ReleaseJob returns a job back to the queue in SCHEDULED state, or fails it when
// no attempts remain. Clears the receipt_handle, visibility_until and leased_by fields together.
func (s *JobStore) ReleaseJob(ctx context.Context, caller store.Caller, taskToken string) error {
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
	}

	tx, row, err := s.lockLease(queryCtx, caller, tt)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(queryCtx)) }()

	// 1=SCHEDULED unless attempts are exhausted, then 4=FAILED
	_, err = tx.Exec(queryCtx, `
		UPDATE jobs
		SET
			state = `+nextStateSQL+`,
			result = `+exhaustedSQL+`,
			visibility_until = NULL,
			receipt_handle = NULL,
			leased_by = NULL,
			updated_at = $1
		WHERE org_id = $2 AND job_id = $3
	`, row.operationTime, caller.OrgID, tt.JobID)
	if err != nil {
		return mapPostgresError(err)
	}

	if err := tx.Commit(queryCtx); err != nil {
		return mapPostgresError(err)
	}

	log.Info().
		Str("job_id", tt.JobID).
		Msg("Released job back to queue")

	return nil
}

// ReapExpired reclaims up to limit RUNNING jobs whose lease has expired, returning them
// to SCHEDULED or failing them when no attempts remain. Rows locked by an in-flight fenced
// operation are skipped and picked up by a later sweep. It returns the number reclaimed.
func (s *JobStore) ReapExpired(ctx context.Context, limit int) (int, error) {
	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	tag, err := s.pool.Exec(queryCtx, `
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
	`, limit)
	if err != nil {
		return 0, mapPostgresError(err)
	}

	return int(tag.RowsAffected()), nil
}

const (
	reaperBatchSize  = 100
	reaperMaxBatches = 10
)

// runReaper sweeps expired leases every LeaseReaperInterval until ctx ends.
func (s *JobStore) runReaper(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.LeaseReaperInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.reapTick(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// reapTick runs up to reaperMaxBatches batches, stopping early on a short batch.
func (s *JobStore) reapTick(ctx context.Context) {
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

	if total > 0 {
		log.Info().Int("reclaimed", total).Msg("Reclaimed expired leases")
	}
}

// ListJobs returns jobs in the caller's org matching the filter criteria.
func (s *JobStore) ListJobs(ctx context.Context, caller store.Caller, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error) {
	// Build query with filters
	baseQuery := `
		SELECT job_id, state, created_at, updated_at,
		       job_params, execution_config, attempt, max_attempts
		FROM jobs
		WHERE org_id = $1
	`

	var conditions []string
	args := []any{caller.OrgID}
	argIdx := 2

	// Filter by queue (optional)
	if req.Queue != "" {
		conditions = append(conditions, fmt.Sprintf("AND queue = $%d", argIdx))
		args = append(args, req.Queue)
		argIdx++
	}

	// Filter by state (optional)
	if req.State != jobv1.JobState_JOB_STATE_UNSPECIFIED {
		conditions = append(conditions, fmt.Sprintf("AND state = $%d", argIdx))
		args = append(args, req.State)
		argIdx++
	}

	// Build final query
	var queryBuilder strings.Builder
	queryBuilder.WriteString(baseQuery)
	for _, cond := range conditions {
		queryBuilder.WriteString(" ")
		queryBuilder.WriteString(cond)
	}
	queryBuilder.WriteString(" ORDER BY created_at DESC, job_id DESC")
	// Add pagination
	pageSize := int32(50) // Default page size
	if req.PageSize > 0 && req.PageSize <= 100 {
		pageSize = req.PageSize
	}

	fmt.Fprintf(&queryBuilder, " LIMIT $%d", argIdx)
	args = append(args, pageSize+1) // Fetch one extra to check if there are more
	query := queryBuilder.String()

	// Execute query
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()

	var jobs []*jobv1.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		if job != nil {
			jobs = append(jobs, job)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, mapPostgresError(err)
	}

	// Check if there are more results
	var lastPage int32
	if len(jobs) > int(pageSize) {
		// Remove the extra job
		jobs = jobs[:pageSize]
		lastPage = req.Page + 1
	} else {
		lastPage = req.Page
	}

	log.Debug().
		Str("queue", req.Queue).
		Str("state", req.State.String()).
		Int("count", len(jobs)).
		Msg("Listed jobs")

	return &jobv1.ListJobsResponse{
		Jobs:     jobs,
		LastPage: lastPage,
	}, nil
}

// preparedEvent is a validated event ready to be stored.
type preparedEvent struct {
	event   *jobv1.JobEvent
	start   int64
	end     int64
	payload []byte
}

// prepareEvents validates events against the leased attempt, stamps the attempt and
// computes each event's covered range and deterministic payload.
func prepareEvents(events []*jobv1.JobEvent, attempt int32) ([]preparedEvent, error) {
	prepared := make([]preparedEvent, 0, len(events))
	for i, event := range events {
		if event.Attempt == 0 {
			return nil, fmt.Errorf("%w: event %d is missing the attempt", store.ErrInvalidArgument, i)
		}
		if event.Attempt != attempt {
			return nil, fmt.Errorf("%w: event %d attempt=%d does not match leased attempt=%d",
				store.ErrInvalidArgument, i, event.Attempt, attempt)
		}
		if event.Timestamp == nil {
			return nil, fmt.Errorf("%w: event %d is missing a timestamp", store.ErrInvalidArgument, i)
		}
		if event.Sequence <= 0 {
			return nil, fmt.Errorf("%w: event %d has invalid sequence %d", store.ErrInvalidArgument, i, event.Sequence)
		}

		// An output batch covers [start_sequence, end_sequence]; other events cover one sequence.
		end := event.Sequence
		if ob := event.GetOutputBatch(); ob != nil {
			end = ob.EndSequence
			if ob.StartSequence != event.Sequence || end < ob.StartSequence ||
				int64(len(ob.Outputs)) != end-ob.StartSequence+1 {
				return nil, fmt.Errorf("%w: event %d output batch range [%d,%d] does not match sequence=%d outputs=%d",
					store.ErrInvalidArgument, i, ob.StartSequence, end, event.Sequence, len(ob.Outputs))
			}
		}

		event.Attempt = attempt
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal event: %w", err)
		}
		if len(payload) > maxEventPayloadBytes {
			return nil, fmt.Errorf("%w: event size=%d exceeds limit=%d",
				store.ErrEventTooLarge, len(payload), maxEventPayloadBytes)
		}

		prepared = append(prepared, preparedEvent{event: event, start: event.Sequence, end: end, payload: payload})
	}

	return prepared, nil
}

// PublishEvents persists events under the caller's live lease and fans them out to active streams.
// The whole request is validated and applied in one fenced transaction: events must extend the
// attempt's committed sequence without gaps, and a replay of already stored events is accepted
// only if it matches them exactly. The acknowledgement is returned only after commit.
func (s *JobStore) PublishEvents(ctx context.Context, caller store.Caller, taskToken string, events []*jobv1.JobEvent) (*store.PublishResult, error) {
	if len(events) == 0 {
		return &store.PublishResult{}, nil
	}

	queryCtx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return nil, err
	}

	tx, row, err := s.lockLease(queryCtx, caller, tt)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(queryCtx)) }()

	prepared, err := prepareEvents(events, row.attempt)
	if err != nil {
		return nil, err
	}

	last := row.lastEventSequence
	var acked int64
	var inserted []*jobv1.JobEvent

	for i, p := range prepared {
		switch {
		case p.start == last+1:
			_, err := tx.Exec(queryCtx, `
				INSERT INTO job_events (job_id, attempt, sequence, end_sequence, timestamp, event_type, event_payload)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, tt.JobID, row.attempt, p.start, p.end, p.event.Timestamp.AsTime(), p.event.EventType, p.payload)
			if err != nil {
				return nil, mapPostgresError(fmt.Errorf("failed to insert event %d: %w", i, err))
			}
			last = p.end
			inserted = append(inserted, p.event)
		case p.start <= last:
			if err := s.checkReplay(queryCtx, tx, tt.JobID, row.attempt, i, p); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: event %d starts at sequence %d but next expected is %d",
				store.ErrInvalidArgument, i, p.start, last+1)
		}
		acked = max(acked, p.end)
	}

	if last != row.lastEventSequence {
		if _, err := tx.Exec(queryCtx,
			`UPDATE jobs SET last_event_sequence = $1 WHERE org_id = $2 AND job_id = $3`,
			last, caller.OrgID, tt.JobID); err != nil {
			return nil, mapPostgresError(err)
		}
	}

	if err := tx.Commit(queryCtx); err != nil {
		return nil, mapPostgresError(err)
	}

	log.Debug().
		Str("job_id", tt.JobID).
		Int32("attempt", row.attempt).
		Int("event_count", len(events)).
		Int("inserted", len(inserted)).
		Msg("Published events")

	return &store.PublishResult{Attempt: row.attempt, AcknowledgedThroughSequence: acked}, nil
}

// checkReplay verifies an event at or below the committed sequence matches the stored row exactly.
func (s *JobStore) checkReplay(ctx context.Context, tx pgx.Tx, jobID string, attempt int32, idx int, p preparedEvent) error {
	var storedEnd int64
	var storedPayload []byte
	err := tx.QueryRow(ctx, `
		SELECT end_sequence, event_payload FROM job_events
		WHERE job_id = $1 AND attempt = $2 AND sequence = $3
	`, jobID, attempt, p.start).Scan(&storedEnd, &storedPayload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: event %d sequence %d overlaps committed events", store.ErrInvalidArgument, idx, p.start)
		}
		return mapPostgresError(err)
	}

	if storedEnd != p.end || !bytes.Equal(storedPayload, p.payload) {
		return fmt.Errorf("%w: event %d sequence %d differs from the committed event", store.ErrConflict, idx, p.start)
	}

	return nil
}

// streamPageSize is the maximum number of event rows read per stream poll query.
const streamPageSize = 100

// StreamEvents streams the events of one attempt of a job, then follows the attempt
// until it closes. See store.JobStore.StreamEvents for the contract.
func (s *JobStore) StreamEvents(ctx context.Context, caller store.Caller, req store.StreamRequest, send func(*store.StreamResponse) error) error {
	// Streams are only served while the store is started. wg.Add happens under the
	// read lock so Stop cannot begin waiting between the check and the Add.
	s.lcMu.RLock()
	if s.state != stateStarted {
		s.lcMu.RUnlock()
		return errors.New("job store is not running")
	}
	lifeCtx := s.lifeCtx
	s.wg.Add(1)
	s.lcMu.RUnlock()
	defer s.wg.Done()

	// streamCtx ends when either the request ctx or the store lifecycle ctx ends.
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	stopAfter := context.AfterFunc(lifeCtx, cancelStream)
	defer stopAfter()

	err := s.runStream(streamCtx, caller, req, send)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if lifeCtx.Err() != nil {
		return fmt.Errorf("%w: job store stopping", store.ErrUnavailable)
	}
	return err
}

// jobStreamState is the job row state observed by a stream poll.
type jobStreamState struct {
	state   jobv1.JobState
	attempt int32
}

// closed reports whether the given attempt can no longer produce events.
func (j jobStreamState) closed(attempt int32) bool {
	switch {
	case j.attempt > attempt:
		return true
	case j.attempt == attempt:
		return j.state != jobv1.JobState_JOB_STATE_RUNNING
	default:
		switch j.state {
		case jobv1.JobState_JOB_STATE_COMPLETED, jobv1.JobState_JOB_STATE_FAILED, jobv1.JobState_JOB_STATE_CANCELLED:
			return true
		}
		return false
	}
}

// observeJob reads the job's current state and attempt, scoped to the caller's org.
func (s *JobStore) observeJob(ctx context.Context, orgID uuid.UUID, jobID string) (jobStreamState, error) {
	qctx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	var js jobStreamState
	err := s.pool.QueryRow(qctx,
		`SELECT state, attempt FROM jobs WHERE org_id = $1 AND job_id = $2`,
		orgID, jobID).Scan(&js.state, &js.attempt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return js, store.ErrJobNotFound
		}
		return js, mapPostgresError(err)
	}
	return js, nil
}

func (s *JobStore) runStream(ctx context.Context, caller store.Caller, req store.StreamRequest, send func(*store.StreamResponse) error) error {
	if req.Attempt < 0 {
		return fmt.Errorf("%w: attempt must not be negative", store.ErrInvalidArgument)
	}
	if _, err := uuid.Parse(req.JobID); err != nil {
		return store.ErrJobNotFound
	}

	js, err := s.observeJob(ctx, caller.OrgID, req.JobID)
	if err != nil {
		return err
	}

	// Attempt 1 is the first attempt even before the first dequeue (jobs.attempt is 0).
	latest := max(int32(1), js.attempt)
	attempt := req.Attempt
	if attempt == 0 {
		attempt = latest
	}
	if attempt > latest {
		return fmt.Errorf("%w: attempt %d does not exist (latest is %d)", store.ErrInvalidArgument, attempt, latest)
	}

	filter := make(map[jobv1.EventType]struct{}, len(req.EventFilter))
	for _, et := range req.EventFilter {
		filter[et] = struct{}{}
	}

	if err := send(&store.StreamResponse{Attempt: attempt, JobState: js.state, AttemptClosed: js.closed(attempt)}); err != nil {
		return err
	}

	cursor := max(req.FromSequence, 1)
	timer := time.NewTimer(s.cfg.StreamPollInterval)
	defer timer.Stop()

	for {
		// Observe the job before reading events: if the attempt is closed here, every
		// event it will ever have is already visible to the page query below.
		js, err := s.observeJob(ctx, caller.OrgID, req.JobID)
		if err != nil {
			return err
		}
		closed := js.closed(attempt)

		events, next, rows, err := s.streamPage(ctx, req, attempt, cursor, filter)
		if err != nil {
			return err
		}
		cursor = next

		for _, event := range events {
			if err := send(&store.StreamResponse{Event: event, Attempt: attempt, JobState: js.state}); err != nil {
				return err
			}
		}

		if rows >= streamPageSize {
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}

		if closed {
			return send(&store.StreamResponse{Attempt: attempt, JobState: js.state, AttemptClosed: true})
		}

		timer.Reset(s.cfg.StreamPollInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// streamPage reads one page of events at or after cursor. It returns the matching
// events, the next cursor (past every scanned row, including filtered ones) and the
// number of rows scanned.
func (s *JobStore) streamPage(ctx context.Context, req store.StreamRequest, attempt int32, cursor int64, filter map[jobv1.EventType]struct{}) ([]*jobv1.JobEvent, int64, int, error) {
	qctx, cancel := s.withQueryTimeout(ctx)
	defer cancel()

	query := `
		SELECT sequence, end_sequence, event_type, event_payload
		FROM job_events
		WHERE job_id = $1 AND attempt = $2 AND end_sequence >= $3`
	args := []any{req.JobID, attempt, cursor}
	if req.FromTimestamp > 0 {
		query += ` AND timestamp >= to_timestamp($4::bigint / 1000.0)`
		args = append(args, req.FromTimestamp)
	}
	query += fmt.Sprintf(` ORDER BY sequence LIMIT %d`, streamPageSize)

	rows, err := s.pool.Query(qctx, query, args...)
	if err != nil {
		return nil, cursor, 0, mapPostgresError(err)
	}
	defer rows.Close()

	var events []*jobv1.JobEvent
	count := 0
	for rows.Next() {
		var sequence, endSequence int64
		var eventType int32
		var payload []byte
		if err := rows.Scan(&sequence, &endSequence, &eventType, &payload); err != nil {
			return nil, cursor, 0, fmt.Errorf("failed to scan event row: %w", err)
		}
		count++
		cursor = endSequence + 1

		if len(filter) > 0 {
			if _, ok := filter[jobv1.EventType(eventType)]; !ok {
				continue
			}
		}

		event := &jobv1.JobEvent{}
		if err := util.UnmarshalProto(payload, event); err != nil {
			return nil, cursor, 0, fmt.Errorf("failed to unmarshal event %d: %w", sequence, err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, 0, mapPostgresError(err)
	}

	return events, cursor, count, nil
}

// Helper methods

// rowScanner is an interface for scanning database rows.
// Both pgx.Row and pgx.Rows implement this interface.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanJob scans a job row and unmarshals its JSON fields.
// Expected columns: job_id, state, created_at, updated_at, job_params, execution_config, attempt, max_attempts
func scanJob(scanner rowScanner) (*jobv1.Job, error) {
	var jobProto jobv1.Job
	var jobParamsJSON, execConfigJSON []byte
	var createdAt, updatedAt time.Time

	err := scanner.Scan(
		&jobProto.JobId,
		&jobProto.State,
		&createdAt,
		&updatedAt,
		&jobParamsJSON,
		&execConfigJSON,
		&jobProto.Attempt,
		&jobProto.MaxAttempts,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, mapPostgresError(err)
	}

	jobProto.CreatedAt = timestamppb.New(createdAt)
	jobProto.UpdatedAt = timestamppb.New(updatedAt)

	jobProto.JobParams = &jobv1.JobParams{}
	if err := util.UnmarshalProtoJSON(jobParamsJSON, jobProto.JobParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job_params: %w", err)
	}

	if execConfigJSON != nil {
		jobProto.ExecutionConfig = &jobv1.ExecutionConfig{}
		if err := util.UnmarshalProtoJSON(execConfigJSON, jobProto.ExecutionConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal execution_config: %w", err)
		}
	}

	return &jobProto, nil
}

// withQueryTimeout creates a context with a query timeout.
// If a parent context already has a deadline, it uses the earlier deadline.
func (s *JobStore) withQueryTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.cfg.QueryTimeoutSeconds > 0 {
		return context.WithTimeout(ctx, time.Duration(s.cfg.QueryTimeoutSeconds)*time.Second)
	}
	// If QueryTimeoutSeconds is 0, use a reasonable default
	return context.WithTimeout(ctx, 10*time.Second)
}
