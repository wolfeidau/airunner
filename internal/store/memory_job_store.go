package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MemoryJobStore implements JobStore using in-memory storage
type MemoryJobStore struct {
	mu sync.RWMutex

	// Core job storage
	jobs      map[string]*jobv1.Job   // job ID -> Job
	jobQueues map[string]string       // job ID -> queue name
	queues    map[string][]*jobv1.Job // queue name -> Jobs (FIFO)

	// Visibility timeout management
	invisibleJobs map[string]time.Time // job ID -> visibility expiry
	taskTokens    map[string]string    // task token -> job ID
	jobTokens     map[string]string    // job ID -> current task token (reverse map)

	// Idempotency support
	requestIds map[string]string // request ID -> job ID

	// Event streaming
	jobEvents    map[string][]*jobv1.JobEvent      // job ID -> event buffer
	eventStreams map[string][]chan *jobv1.JobEvent // job ID -> active streams

	// Background cleanup
	cleanupTicker *time.Ticker
	stopCleanup   chan bool
}

// NewMemoryJobStore creates a new in-memory job store
func NewMemoryJobStore() *MemoryJobStore {
	return &MemoryJobStore{
		jobs:          make(map[string]*jobv1.Job),
		jobQueues:     make(map[string]string),
		queues:        make(map[string][]*jobv1.Job),
		invisibleJobs: make(map[string]time.Time),
		taskTokens:    make(map[string]string),
		jobTokens:     make(map[string]string),
		requestIds:    make(map[string]string),
		jobEvents:     make(map[string][]*jobv1.JobEvent),
		eventStreams:  make(map[string][]chan *jobv1.JobEvent),
		stopCleanup:   make(chan bool),
	}
}

// Start begins background cleanup operations
func (s *MemoryJobStore) Start() error {
	s.cleanupTicker = time.NewTicker(30 * time.Second)
	go s.cleanupLoop()
	return nil
}

// Stop terminates background operations
func (s *MemoryJobStore) Stop() error {
	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
	}
	close(s.stopCleanup)
	return nil
}

// cleanupLoop runs background cleanup of expired visibility timeouts
func (s *MemoryJobStore) cleanupLoop() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.cleanupExpiredJobs()
		case <-s.stopCleanup:
			return
		}
	}
}

// cleanupExpiredJobs returns expired jobs back to their queues
func (s *MemoryJobStore) cleanupExpiredJobs() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for jobId, expiry := range s.invisibleJobs {
		if now.After(expiry) {
			job := s.jobs[jobId]
			if job != nil {
				// Return job to queue
				job.State = jobv1.JobState_JOB_STATE_SCHEDULED
				queueName := s.jobQueues[jobId]
				s.queues[queueName] = append(s.queues[queueName], job)

				// Clean up tracking using reverse map
				delete(s.invisibleJobs, jobId)
				if token, exists := s.jobTokens[jobId]; exists {
					delete(s.taskTokens, token)
					delete(s.jobTokens, jobId)
				}
			}
		}
	}
}

// EnqueueJob adds a new job to the specified queue
func (s *MemoryJobStore) EnqueueJob(ctx context.Context, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for idempotency
	if existingJobId, exists := s.requestIds[req.RequestId]; exists {
		job := s.jobs[existingJobId]
		if job != nil {
			return &jobv1.EnqueueJobResponse{
				JobId:     job.JobId,
				CreatedAt: job.CreatedAt,
				State:     job.State,
			}, nil
		}
	}

	// Generate job ID
	jobId := uuid.Must(uuid.NewV7()).String()
	now := timestamppb.Now()

	// Create default ExecutionConfig (memory store uses built-in defaults)
	executionConfig := &jobv1.ExecutionConfig{
		Batching: &jobv1.BatchingConfig{
			FlushIntervalSeconds:   2,
			MaxBatchSize:           50,
			MaxBatchBytes:          1048576,
			PlaybackIntervalMillis: 50,
		},
		HeartbeatIntervalSeconds:  30,
		OutputFlushIntervalMillis: 100, // Flush console output every 100ms
	}

	// Create job
	job := &jobv1.Job{
		JobId:           jobId,
		JobParams:       req.JobParams,
		State:           jobv1.JobState_JOB_STATE_SCHEDULED,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExecutionConfig: executionConfig,
	}

	// Store job
	s.jobs[jobId] = job
	s.jobQueues[jobId] = req.Queue
	s.requestIds[req.RequestId] = jobId

	// Add to queue
	s.queues[req.Queue] = append(s.queues[req.Queue], job)

	return &jobv1.EnqueueJobResponse{
		JobId:     jobId,
		CreatedAt: now,
		State:     job.State,
	}, nil
}

// DequeueJobs retrieves jobs from the specified queue
func (s *MemoryJobStore) DequeueJobs(ctx context.Context, queue string, maxJobs int, timeoutSeconds int) ([]*JobWithToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	queueJobs := s.queues[queue]
	if len(queueJobs) == 0 {
		return nil, nil
	}

	// Take jobs from front of queue (FIFO)
	numJobs := min(maxJobs, len(queueJobs))

	results := make([]*JobWithToken, 0, numJobs)
	remainingJobs := make([]*jobv1.Job, 0, len(queueJobs)-numJobs)

	for i, job := range queueJobs {
		if i < numJobs {
			// Generate task token
			taskToken := uuid.Must(uuid.NewV7()).String()

			// Update job state
			job.State = jobv1.JobState_JOB_STATE_RUNNING
			job.UpdatedAt = timestamppb.Now()

			// Set visibility timeout
			expiry := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
			s.invisibleJobs[job.JobId] = expiry
			s.taskTokens[taskToken] = job.JobId
			s.jobTokens[job.JobId] = taskToken

			results = append(results, &JobWithToken{
				Job:       job,
				TaskToken: taskToken,
			})
		} else {
			remainingJobs = append(remainingJobs, job)
		}
	}

	// Update queue
	s.queues[queue] = remainingJobs

	return results, nil
}

// UpdateJobVisibility extends the visibility timeout for a job
func (s *MemoryJobStore) UpdateJobVisibility(ctx context.Context, queue string, taskToken string, timeoutSeconds int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobId, exists := s.taskTokens[taskToken]
	if !exists {
		return ErrInvalidTaskToken
	}

	// Verify the job belongs to the correct queue
	if s.jobQueues[jobId] != queue {
		return fmt.Errorf("%w: expected queue %s", ErrQueueMismatch, queue)
	}

	// Update visibility timeout
	expiry := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	s.invisibleJobs[jobId] = expiry

	// Update job timestamp
	if job := s.jobs[jobId]; job != nil {
		job.UpdatedAt = timestamppb.Now()
	}

	log.Debug().Str("job_id", jobId).Str("queue", queue).Int("timeout_seconds", timeoutSeconds).Msg("Updated job visibility timeout")
	return nil
}

// CompleteJob marks a job as completed and removes it from processing
func (s *MemoryJobStore) CompleteJob(ctx context.Context, taskToken string, result *jobv1.JobResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobId, exists := s.taskTokens[taskToken]
	if !exists {
		return ErrInvalidTaskToken
	}

	job := s.jobs[jobId]
	if job == nil {
		return fmt.Errorf("%w: %s", ErrJobNotFound, jobId)
	}

	// Verify job ID matches
	if result.JobId != jobId {
		log.Warn().Str("token_job_id", jobId).Str("result_job_id", result.JobId).Msg("Job ID mismatch")
		return fmt.Errorf("%w: expected %s, got %s", ErrJobIDMismatch, jobId, result.JobId)
	}

	// Update job state
	if result.Success {
		job.State = jobv1.JobState_JOB_STATE_COMPLETED
	} else {
		job.State = jobv1.JobState_JOB_STATE_FAILED
	}
	job.UpdatedAt = timestamppb.Now()

	// Clean up visibility timeout and task token
	delete(s.invisibleJobs, jobId)
	delete(s.taskTokens, taskToken)
	delete(s.jobTokens, jobId)

	log.Info().Str("job_id", jobId).Bool("success", result.Success).Msg("Job completed")
	return nil
}

// ReleaseJob returns a job back to the queue, resetting its state to SCHEDULED
func (s *MemoryJobStore) ReleaseJob(ctx context.Context, taskToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobId, exists := s.taskTokens[taskToken]
	if !exists {
		return ErrInvalidTaskToken
	}

	job := s.jobs[jobId]
	if job == nil {
		return fmt.Errorf("%w: %s", ErrJobNotFound, jobId)
	}

	// Reset job state to SCHEDULED
	job.State = jobv1.JobState_JOB_STATE_SCHEDULED
	job.UpdatedAt = timestamppb.Now()

	// Return job to the front of the queue (prepend for priority)
	queueName := s.jobQueues[jobId]
	s.queues[queueName] = append([]*jobv1.Job{job}, s.queues[queueName]...)

	// Clean up visibility timeout and task token
	delete(s.invisibleJobs, jobId)
	delete(s.taskTokens, taskToken)
	delete(s.jobTokens, jobId)

	log.Info().Str("job_id", jobId).Str("queue", queueName).Msg("Job released back to queue")
	return nil
}

// ListJobs returns a filtered list of jobs
func (s *MemoryJobStore) ListJobs(ctx context.Context, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filteredJobs []*jobv1.Job

	for _, job := range s.jobs {
		// Filter by queue if specified
		if req.Queue != "" && s.jobQueues[job.JobId] != req.Queue {
			continue
		}

		// Filter by state if specified
		if req.State != jobv1.JobState_JOB_STATE_UNSPECIFIED && job.State != req.State {
			continue
		}

		filteredJobs = append(filteredJobs, job)
	}

	// Simple pagination (in production, this would be more sophisticated)
	pageSize := int(req.PageSize)
	if pageSize <= 0 {
		pageSize = 50 // default page size
	}

	page := int(req.Page)
	if page <= 0 {
		page = 1
	}

	startIdx := (page - 1) * pageSize
	endIdx := startIdx + pageSize

	if startIdx >= len(filteredJobs) {
		lastPage := (len(filteredJobs)-1)/pageSize + 1
		return &jobv1.ListJobsResponse{
			Jobs:     []*jobv1.Job{},
			LastPage: util.AsInt32(lastPage),
		}, nil
	}

	if endIdx > len(filteredJobs) {
		endIdx = len(filteredJobs)
	}

	lastPage := (len(filteredJobs)-1)/pageSize + 1
	return &jobv1.ListJobsResponse{
		Jobs:     filteredJobs[startIdx:endIdx],
		LastPage: util.AsInt32(lastPage),
	}, nil
}

// PublishEvents publishes events for a job
func (s *MemoryJobStore) PublishEvents(ctx context.Context, taskToken string, events []*jobv1.JobEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobId, exists := s.taskTokens[taskToken]
	if !exists {
		return ErrInvalidTaskToken
	}

	// Set timestamp if not already set
	for _, event := range events {
		if event.Timestamp == nil {
			event.Timestamp = timestamppb.Now()
		}
	}

	// Add to event buffer (simple implementation - in production would use LRU)
	s.jobEvents[jobId] = append(s.jobEvents[jobId], events...)

	// Fanout to active streams
	for _, event := range events {
		s.fanoutEvent(jobId, event)
	}

	log.Debug().Str("job_id", jobId).Int("event_count", len(events)).Msg("Published events")
	return nil
}

// StreamEvents creates a stream of events for a job
func (s *MemoryJobStore) StreamEvents(ctx context.Context, jobId string, fromSequence int64, fromTimestamp int64, eventFilter []jobv1.EventType) (<-chan *jobv1.JobEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify job exists
	if _, exists := s.jobs[jobId]; !exists {
		return nil, fmt.Errorf("%w: %s", ErrJobNotFound, jobId)
	}

	// Create event filter map for efficient lookup
	filterMap := make(map[jobv1.EventType]bool)
	for _, eventType := range eventFilter {
		filterMap[eventType] = true
	}

	// Create channel for streaming
	eventChan := make(chan *jobv1.JobEvent, 100)

	// Add to active streams
	s.eventStreams[jobId] = append(s.eventStreams[jobId], eventChan)

	// Send historical events if requested
	go func() {
		defer func() {
			// Remove from active streams when done
			s.mu.Lock()
			streams := s.eventStreams[jobId]
			for i, ch := range streams {
				if ch == eventChan {
					s.eventStreams[jobId] = append(streams[:i], streams[i+1:]...)
					break
				}
			}
			s.mu.Unlock()
			close(eventChan)
		}()

		// Send historical events
		s.mu.RLock()
		events := s.jobEvents[jobId]
		s.mu.RUnlock()

		for _, event := range events {
			// Skip if before requested sequence
			if fromSequence > 0 && event.Sequence < fromSequence {
				continue
			}

			// Skip if before requested timestamp
			if fromTimestamp > 0 && event.Timestamp.AsTime().UnixMilli() < fromTimestamp {
				continue
			}

			// Skip if not in filter
			if len(filterMap) > 0 && !filterMap[event.EventType] {
				continue
			}

			select {
			case eventChan <- event:
			case <-ctx.Done():
				return
			}
		}

		// Keep channel open for future events
		<-ctx.Done()
	}()

	return eventChan, nil
}

// fanoutEvent sends an event to all active streams for a job
func (s *MemoryJobStore) fanoutEvent(jobId string, event *jobv1.JobEvent) {
	streams := s.eventStreams[jobId]
	for _, ch := range streams {
		select {
		case ch <- event:
		default:
			// Channel full, skip this stream - DATA LOSS
			log.Error().Str("job_id", jobId).Int64("sequence", event.Sequence).Msg("Event channel full, dropping event")
		}
	}
}
