package postgres

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// JobStore implements the store.JobStore interface using PostgreSQL as the backend.
// It provides FIFO queue semantics with visibility timeouts, idempotent job enqueuing,
// and event streaming with historical replay.
type JobStore struct {
	pool *pgxpool.Pool
	cfg  *JobStoreConfig

	// Event streaming support (in-memory fanout)
	mu           sync.RWMutex
	eventStreams map[string][]chan *jobv1.JobEvent

	// Lifecycle
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewJobStore creates a new PostgreSQL-backed job store.
// It establishes a connection pool, runs migrations, and initializes the store.
func NewJobStore(ctx context.Context, cfg *JobStoreConfig) (*JobStore, error) {
	// Apply defaults and validate config
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Parse connection string and configure pool
	poolConfig, err := pgxpool.ParseConfig(cfg.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Apply pool configuration
	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = time.Duration(cfg.MaxConnLifetime) * time.Second
	poolConfig.MaxConnIdleTime = time.Duration(cfg.MaxConnIdleTime) * time.Second
	poolConfig.HealthCheckPeriod = 1 * time.Minute
	poolConfig.ConnConfig.ConnectTimeout = 10 * time.Second

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info().
		Str("database", poolConfig.ConnConfig.Database).
		Str("host", poolConfig.ConnConfig.Host).
		Int32("max_conns", cfg.MaxConns).
		Msg("Connected to PostgreSQL")

	// Run migrations only if explicitly enabled
	if cfg.AutoMigrate {
		if err := runMigrations(ctx, pool); err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}
		log.Info().Msg("Database migrations completed")
	}

	return &JobStore{
		pool:         pool,
		cfg:          cfg,
		eventStreams: make(map[string][]chan *jobv1.JobEvent),
		stopCh:       make(chan struct{}),
	}, nil
}

// Start initializes the job store and starts background tasks.
func (s *JobStore) Start() error {
	log.Info().Msg("Starting PostgreSQL job store")

	// Start connection pool monitoring goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.monitorConnectionPool()
	}()

	return nil
}

// Stop gracefully shuts down the job store and closes connections.
func (s *JobStore) Stop() error {
	log.Info().Msg("Stopping PostgreSQL job store")

	// Signal shutdown
	close(s.stopCh)

	// Wait for background tasks
	s.wg.Wait()

	// Close event streams
	s.mu.Lock()
	for jobID, streams := range s.eventStreams {
		for _, ch := range streams {
			close(ch)
		}
		delete(s.eventStreams, jobID)
	}
	s.mu.Unlock()

	// Close connection pool
	s.pool.Close()

	log.Info().Msg("PostgreSQL job store stopped")
	return nil
}

// monitorConnectionPool logs connection pool statistics periodically.
func (s *JobStore) monitorConnectionPool() {
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
		case <-s.stopCh:
			return
		}
	}
}

// EnqueueJob adds a new job to the queue with idempotency support.
// If a job with the same request_id already exists, returns the existing job.
func (s *JobStore) EnqueueJob(ctx context.Context, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error) {
	// Check idempotency first
	existing, err := s.getJobByRequestID(ctx, req.RequestId)
	if err != nil {
		log.Error().Err(err).Str("request_id", req.RequestId).Msg("Failed to check idempotency")
		return nil, err
	}

	if existing != nil {
		log.Debug().
			Str("job_id", existing.JobId).
			Str("request_id", req.RequestId).
			Msg("Job already exists (idempotent)")
		return &jobv1.EnqueueJobResponse{
			JobId:     existing.JobId,
			CreatedAt: existing.CreatedAt,
			State:     existing.State,
		}, nil
	}

	// Generate new job ID
	jobID := uuid.Must(uuid.NewV7()).String()
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

	// Insert job
	query := `
		INSERT INTO jobs (
			job_id, queue, state, request_id, created_at, updated_at,
			job_params, execution_config
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (request_id) DO NOTHING
		RETURNING job_id
	`

	var returnedJobID string
	err = s.pool.QueryRow(ctx, query,
		jobID,
		req.Queue,
		jobv1.JobState_JOB_STATE_SCHEDULED,
		req.RequestId,
		now,
		now,
		jobParamsJSON,
		execConfigJSON,
	).Scan(&returnedJobID)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Conflict occurred, fetch the existing job
			existing, err := s.getJobByRequestID(ctx, req.RequestId)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				log.Debug().
					Str("job_id", existing.JobId).
					Str("request_id", req.RequestId).
					Msg("Job created concurrently (race)")
				return &jobv1.EnqueueJobResponse{
					JobId:     existing.JobId,
					CreatedAt: existing.CreatedAt,
					State:     existing.State,
				}, nil
			}
			return nil, fmt.Errorf("concurrent insert conflict but job not found")
		}
		return nil, mapPostgresError(err)
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

// DequeueJobs claims jobs from the queue using SELECT FOR UPDATE SKIP LOCKED.
// Returns at most maxJobs jobs that are SCHEDULED and not currently visible.
func (s *JobStore) DequeueJobs(ctx context.Context, queue string, maxJobs int, timeoutSeconds int) ([]*store.JobWithToken, error) {
	query := `
		WITH claimable AS (
			SELECT job_id, queue, created_at, job_params, execution_config
			FROM jobs
			WHERE queue = $1
			  AND state = $2
			  AND (visibility_until IS NULL OR visibility_until < NOW())
			ORDER BY created_at ASC
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE jobs
		SET
			state = $4,
			visibility_until = NOW() + $5 * INTERVAL '1 second',
			receipt_handle = gen_random_uuid(),
			updated_at = NOW()
		FROM claimable
		WHERE jobs.job_id = claimable.job_id
		RETURNING jobs.job_id, jobs.queue, jobs.receipt_handle, jobs.created_at,
		          jobs.job_params, jobs.execution_config
	`

	rows, err := s.pool.Query(ctx, query,
		queue,
		jobv1.JobState_JOB_STATE_SCHEDULED,
		maxJobs,
		jobv1.JobState_JOB_STATE_RUNNING,
		timeoutSeconds,
	)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()

	var results []*store.JobWithToken
	for rows.Next() {
		var jobID, queueName, receiptHandle string
		var createdAt time.Time
		var jobParamsJSON, execConfigJSON []byte

		err := rows.Scan(
			&jobID,
			&queueName,
			&receiptHandle,
			&createdAt,
			&jobParamsJSON,
			&execConfigJSON,
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
			UpdatedAt:       timestamppb.Now(),
			JobParams:       jobParams,
			ExecutionConfig: execConfig,
		}

		// Generate task token
		taskToken := s.encodeTaskToken(jobID, queueName, receiptHandle)

		results = append(results, &store.JobWithToken{
			Job:       job,
			TaskToken: taskToken,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, mapPostgresError(err)
	}

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

// UpdateJobVisibility extends the visibility timeout for a job.
// The receipt handle does NOT change (matches AWS SQS behavior).
func (s *JobStore) UpdateJobVisibility(ctx context.Context, queue string, taskToken string, timeoutSeconds int) error {
	// Decode and verify task token
	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
	}

	// Verify queue matches
	if tt.Queue != queue {
		log.Warn().Str("expected_queue", queue).Str("token_queue", tt.Queue).Msg("Queue mismatch")
		return fmt.Errorf("%w: expected %s, got %s", store.ErrQueueMismatch, queue, tt.Queue)
	}

	// Update visibility timeout (receipt_handle stays the same)
	query := `
		UPDATE jobs
		SET
			visibility_until = NOW() + $1 * INTERVAL '1 second',
			updated_at = NOW()
		WHERE job_id = $2
		  AND receipt_handle = $3::UUID
		  AND queue = $4
	`

	result, err := s.pool.Exec(ctx, query,
		timeoutSeconds,
		tt.JobID,
		tt.ReceiptHandle,
		queue,
	)
	if err != nil {
		return mapPostgresError(err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: job not found or receipt handle mismatch", store.ErrJobNotFound)
	}

	log.Debug().
		Str("job_id", tt.JobID).
		Int("timeout_seconds", timeoutSeconds).
		Msg("Updated job visibility")

	return nil
}

// CompleteJob marks a job as completed or failed and removes it from the queue.
// Clears the receipt_handle and visibility_until fields.
func (s *JobStore) CompleteJob(ctx context.Context, taskToken string, result *jobv1.JobResult) error {
	// Decode and verify task token
	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
	}

	// Verify job ID matches
	if result.JobId != tt.JobID {
		return fmt.Errorf("%w: token job_id=%s, result job_id=%s",
			store.ErrJobIDMismatch, tt.JobID, result.JobId)
	}

	// Determine final state
	finalState := jobv1.JobState_JOB_STATE_COMPLETED
	if !result.Success {
		finalState = jobv1.JobState_JOB_STATE_FAILED
	}

	// Marshal result to JSON for JSONB column
	resultJSON, err := util.MarshalProtoJSON(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	// Update job state and clear visibility
	query := `
		UPDATE jobs
		SET
			state = $1,
			visibility_until = NULL,
			receipt_handle = NULL,
			result = $2,
			updated_at = NOW()
		WHERE job_id = $3
		  AND receipt_handle = $4::UUID
	`

	execResult, err := s.pool.Exec(ctx, query,
		finalState,
		resultJSON,
		tt.JobID,
		tt.ReceiptHandle,
	)
	if err != nil {
		return mapPostgresError(err)
	}

	if execResult.RowsAffected() == 0 {
		return fmt.Errorf("%w: job not found or receipt handle mismatch", store.ErrJobNotFound)
	}

	log.Info().
		Str("job_id", tt.JobID).
		Str("state", finalState.String()).
		Bool("success", result.Success).
		Msg("Completed job")

	return nil
}

// ReleaseJob returns a job back to the queue in SCHEDULED state.
// Clears the receipt_handle and visibility_until fields.
func (s *JobStore) ReleaseJob(ctx context.Context, taskToken string) error {
	// Decode and verify task token
	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
	}

	// Update job back to SCHEDULED state
	query := `
		UPDATE jobs
		SET
			state = $1,
			visibility_until = NULL,
			receipt_handle = NULL,
			updated_at = NOW()
		WHERE job_id = $2
		  AND receipt_handle = $3::UUID
	`

	result, err := s.pool.Exec(ctx, query,
		jobv1.JobState_JOB_STATE_SCHEDULED,
		tt.JobID,
		tt.ReceiptHandle,
	)
	if err != nil {
		return mapPostgresError(err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: job not found or receipt handle mismatch", store.ErrJobNotFound)
	}

	log.Info().
		Str("job_id", tt.JobID).
		Msg("Released job back to queue")

	return nil
}

// ListJobs returns jobs matching the filter criteria.
func (s *JobStore) ListJobs(ctx context.Context, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error) {
	// Build query with filters
	baseQuery := `
		SELECT job_id, queue, state, request_id, created_at, updated_at,
		       job_params, execution_config
		FROM jobs
		WHERE 1=1
	`

	var conditions []string
	var args []any
	argIdx := 1

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
	query := baseQuery
	for _, cond := range conditions {
		query += " " + cond
	}
	query += " ORDER BY created_at DESC"

	// Add pagination
	pageSize := int32(50) // Default page size
	if req.PageSize > 0 && req.PageSize <= 100 {
		pageSize = req.PageSize
	}

	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, pageSize+1) // Fetch one extra to check if there are more

	// Execute query
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()

	var jobs []*jobv1.Job
	for rows.Next() {
		var jobProto jobv1.Job
		var jobParamsJSON, execConfigJSON []byte
		var createdAt, updatedAt time.Time
		var queue, requestID string // Read but not returned in Job proto

		err := rows.Scan(
			&jobProto.JobId,
			&queue, // Read but not used (not in Job proto)
			&jobProto.State,
			&requestID, // Read but not used (not in Job proto)
			&createdAt,
			&updatedAt,
			&jobParamsJSON,
			&execConfigJSON,
		)
		if err != nil {
			return nil, mapPostgresError(err)
		}

		// Convert timestamps
		jobProto.CreatedAt = timestamppb.New(createdAt)
		jobProto.UpdatedAt = timestamppb.New(updatedAt)

		// Unmarshal job params from JSON
		jobProto.JobParams = &jobv1.JobParams{}
		if err := util.UnmarshalProtoJSON(jobParamsJSON, jobProto.JobParams); err != nil {
			return nil, fmt.Errorf("failed to unmarshal job_params: %w", err)
		}

		// Unmarshal execution config from JSON
		if execConfigJSON != nil {
			jobProto.ExecutionConfig = &jobv1.ExecutionConfig{}
			if err := util.UnmarshalProtoJSON(execConfigJSON, jobProto.ExecutionConfig); err != nil {
				return nil, fmt.Errorf("failed to unmarshal execution_config: %w", err)
			}
		}

		jobs = append(jobs, &jobProto)
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

// PublishEvents persists events to the database and fanouts to active streams.
func (s *JobStore) PublishEvents(ctx context.Context, taskToken string, events []*jobv1.JobEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Decode and verify task token
	tt, err := s.decodeTaskToken(taskToken)
	if err != nil {
		log.Warn().Err(err).Msg("Invalid task token")
		return err
	}

	// Verify job exists
	job, err := s.getJobByID(ctx, tt.JobID)
	if err != nil {
		return err
	}
	if job == nil {
		return store.ErrJobNotFound
	}

	// Validate event sizes and set timestamps
	now := time.Now()
	for _, event := range events {
		if event.Timestamp == nil {
			event.Timestamp = timestamppb.New(now)
		}

		// Validate event size
		eventBytes, err := util.MarshalProto(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		if len(eventBytes) > maxEventPayloadBytes {
			return fmt.Errorf("%w: event size=%d exceeds limit=%d",
				store.ErrEventTooLarge, len(eventBytes), maxEventPayloadBytes)
		}
	}

	// Batch insert events
	query := `
		INSERT INTO job_events (job_id, sequence, timestamp, event_type, event_payload, ttl)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (job_id, sequence) DO NOTHING
	`

	batch := &pgx.Batch{}
	var ttl *time.Time
	if s.cfg.EventsTTLDays > 0 {
		ttlTime := now.AddDate(0, 0, int(s.cfg.EventsTTLDays))
		ttl = &ttlTime
	}

	for _, event := range events {
		eventPayload, err := util.MarshalProto(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		batch.Queue(query,
			tt.JobID,
			event.Sequence,
			event.Timestamp.AsTime(),
			event.EventType,
			eventPayload,
			ttl,
		)
	}

	// Execute batch
	batchResults := s.pool.SendBatch(ctx, batch)
	defer batchResults.Close()

	// Check for errors
	for i := 0; i < len(events); i++ {
		_, err := batchResults.Exec()
		if err != nil {
			return mapPostgresError(fmt.Errorf("failed to insert event %d: %w", i, err))
		}
	}

	log.Debug().
		Str("job_id", tt.JobID).
		Int("event_count", len(events)).
		Msg("Published events")

	// Fanout to active streams
	for _, event := range events {
		s.fanoutEvent(tt.JobID, event)
	}

	return nil
}

// StreamEvents returns a channel that streams events for a job.
// Replays historical events from the database, then streams real-time events.
func (s *JobStore) StreamEvents(ctx context.Context, jobID string, fromSequence int64, fromTimestamp int64, eventFilter []jobv1.EventType) (<-chan *jobv1.JobEvent, error) {
	// Verify job exists
	job, err := s.getJobByID(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job == nil {
		return nil, store.ErrJobNotFound
	}

	// Create event channel
	eventCh := make(chan *jobv1.JobEvent, 100)

	// Register stream
	s.registerEventStream(jobID, eventCh)

	// Create filter map for efficient lookup
	filterMap := make(map[jobv1.EventType]bool)
	for _, et := range eventFilter {
		filterMap[et] = true
	}

	// Start goroutine for historical replay and streaming
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.deregisterEventStream(jobID, eventCh)
		defer close(eventCh)

		// Historical replay
		query := `
			SELECT sequence, timestamp, event_type, event_payload
			FROM job_events
			WHERE job_id = $1
		`

		var conditions []string
		var args = []any{jobID}
		argIdx := 2

		if fromSequence > 0 {
			conditions = append(conditions, fmt.Sprintf("AND sequence >= $%d", argIdx))
			args = append(args, fromSequence)
			argIdx++
		}

		if fromTimestamp > 0 {
			conditions = append(conditions, fmt.Sprintf("AND EXTRACT(EPOCH FROM timestamp) * 1000 >= $%d", argIdx))
			args = append(args, fromTimestamp)
		}

		for _, cond := range conditions {
			query += " " + cond
		}
		query += " ORDER BY sequence ASC"

		rows, err := s.pool.Query(ctx, query, args...)
		if err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("Failed to query historical events")
			return
		}
		defer rows.Close()

		for rows.Next() {
			var sequence int64
			var timestamp time.Time
			var eventType int32
			var eventPayload []byte

			err := rows.Scan(&sequence, &timestamp, &eventType, &eventPayload)
			if err != nil {
				log.Error().Err(err).Msg("Failed to scan event row")
				continue
			}

			// Apply event type filter
			if len(filterMap) > 0 && !filterMap[jobv1.EventType(eventType)] {
				continue
			}

			// Unmarshal event
			event := &jobv1.JobEvent{}
			if err := util.UnmarshalProto(eventPayload, event); err != nil {
				log.Error().Err(err).Msg("Failed to unmarshal event")
				continue
			}

			// Send event (non-blocking)
			select {
			case eventCh <- event:
				// Sent successfully
			case <-ctx.Done():
				return
			default:
				log.Warn().Str("job_id", jobID).Int64("sequence", sequence).Msg("Event channel full during replay")
			}
		}

		log.Debug().Str("job_id", jobID).Msg("Historical replay complete, streaming real-time events")

		// Wait for context cancellation (real-time events come via fanout)
		<-ctx.Done()
	}()

	return eventCh, nil
}

// Helper methods

// getJobByID retrieves a job by its job_id.
func (s *JobStore) getJobByID(ctx context.Context, jobID string) (*jobv1.Job, error) {
	query := `
		SELECT job_id, state, created_at, updated_at,
		       job_params, execution_config
		FROM jobs
		WHERE job_id = $1
	`

	var jobProto jobv1.Job
	var jobParamsJSON, execConfigJSON []byte
	var createdAt, updatedAt time.Time

	err := s.pool.QueryRow(ctx, query, jobID).Scan(
		&jobProto.JobId,
		&jobProto.State,
		&createdAt,
		&updatedAt,
		&jobParamsJSON,
		&execConfigJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, store.ErrJobNotFound
		}
		return nil, mapPostgresError(err)
	}

	// Convert timestamps
	jobProto.CreatedAt = timestamppb.New(createdAt)
	jobProto.UpdatedAt = timestamppb.New(updatedAt)

	// Unmarshal job params from JSON
	jobProto.JobParams = &jobv1.JobParams{}
	if err := util.UnmarshalProtoJSON(jobParamsJSON, jobProto.JobParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job_params: %w", err)
	}

	// Unmarshal execution config from JSON
	if execConfigJSON != nil {
		jobProto.ExecutionConfig = &jobv1.ExecutionConfig{}
		if err := util.UnmarshalProtoJSON(execConfigJSON, jobProto.ExecutionConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal execution_config: %w", err)
		}
	}

	return &jobProto, nil
}

// getJobByRequestID retrieves a job by its request_id (for idempotency checks).
func (s *JobStore) getJobByRequestID(ctx context.Context, requestID string) (*jobv1.Job, error) {
	query := `
		SELECT job_id, state, created_at, updated_at,
		       job_params, execution_config
		FROM jobs
		WHERE request_id = $1
	`

	var jobProto jobv1.Job
	var jobParamsJSON, execConfigJSON []byte
	var createdAt, updatedAt time.Time

	err := s.pool.QueryRow(ctx, query, requestID).Scan(
		&jobProto.JobId,
		&jobProto.State,
		&createdAt,
		&updatedAt,
		&jobParamsJSON,
		&execConfigJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Not an error - just not found
		}
		return nil, mapPostgresError(err)
	}

	// Convert timestamps
	jobProto.CreatedAt = timestamppb.New(createdAt)
	jobProto.UpdatedAt = timestamppb.New(updatedAt)

	// Unmarshal job params from JSON
	jobProto.JobParams = &jobv1.JobParams{}
	if err := util.UnmarshalProtoJSON(jobParamsJSON, jobProto.JobParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job_params: %w", err)
	}

	// Unmarshal execution config from JSON
	if execConfigJSON != nil {
		jobProto.ExecutionConfig = &jobv1.ExecutionConfig{}
		if err := util.UnmarshalProtoJSON(execConfigJSON, jobProto.ExecutionConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal execution_config: %w", err)
		}
	}

	return &jobProto, nil
}

// fanoutEvent sends an event to all active stream channels for a job.
// Uses non-blocking sends to prevent slow consumers from blocking.
func (s *JobStore) fanoutEvent(jobID string, event *jobv1.JobEvent) {
	s.mu.RLock()
	streams := s.eventStreams[jobID]
	s.mu.RUnlock()

	if len(streams) == 0 {
		return
	}

	for _, ch := range streams {
		select {
		case ch <- event:
			// Event sent successfully
		default:
			// Channel full, drop event (non-blocking)
			log.Warn().
				Str("job_id", jobID).
				Int64("sequence", event.Sequence).
				Msg("Event channel full, dropping event")
		}
	}
}

// registerEventStream adds a channel to receive events for a job.
func (s *JobStore) registerEventStream(jobID string, ch chan *jobv1.JobEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventStreams[jobID] = append(s.eventStreams[jobID], ch)
	log.Debug().Str("job_id", jobID).Int("stream_count", len(s.eventStreams[jobID])).Msg("Registered event stream")
}

// deregisterEventStream removes a channel from receiving events for a job.
func (s *JobStore) deregisterEventStream(jobID string, ch chan *jobv1.JobEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	streams := s.eventStreams[jobID]
	for i, stream := range streams {
		if stream == ch {
			// Remove channel from slice
			s.eventStreams[jobID] = append(streams[:i], streams[i+1:]...)
			break
		}
	}

	// Clean up empty stream lists
	if len(s.eventStreams[jobID]) == 0 {
		delete(s.eventStreams, jobID)
	}

	log.Debug().Str("job_id", jobID).Msg("Deregistered event stream")
}
