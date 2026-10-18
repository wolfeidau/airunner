package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// Sentinel errors for common error conditions
var (
	ErrInvalidTaskToken = errors.New("invalid task token")
	ErrQueueMismatch    = errors.New("queue mismatch")
	ErrJobNotFound      = errors.New("job not found")
	ErrJobIDMismatch    = errors.New("job ID mismatch")
	ErrEventTooLarge    = errors.New("event exceeds maximum size")

	// ErrLeaseLost indicates the task token no longer holds a valid lease.
	ErrLeaseLost = errors.New("lease lost")

	// ErrConflict indicates a request conflicts with previously recorded intent or content.
	ErrConflict = errors.New("conflict")
)

// Caller identifies the authenticated principal making a store call.
// Identity is supplied by trusted authentication, never by request fields.
type Caller struct {
	OrgID       uuid.UUID
	PrincipalID uuid.UUID
}

// PublishResult reports the committed outcome of a PublishEvents call.
type PublishResult struct {
	// Attempt is the job attempt the events were recorded against.
	Attempt int32
	// AcknowledgedThroughSequence is the highest sequence covered by the request,
	// including output batch end ranges.
	AcknowledgedThroughSequence int64
}

// JobStore defines the interface for job storage operations.
// Every caller-facing method is scoped to caller.OrgID.
type JobStore interface {
	// Job lifecycle
	EnqueueJob(ctx context.Context, caller Caller, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error)
	DequeueJobs(ctx context.Context, caller Caller, queue string, maxJobs int, timeoutSeconds int) ([]*JobWithToken, error)

	// UpdateJobVisibility renews the lease and returns the effective timeout in seconds.
	UpdateJobVisibility(ctx context.Context, caller Caller, taskToken string, timeoutSeconds int) (int32, error)
	CompleteJob(ctx context.Context, caller Caller, taskToken string, result *jobv1.JobResult) error
	ListJobs(ctx context.Context, caller Caller, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error)

	// ReleaseJob returns a job back to the queue, resetting its state to SCHEDULED.
	// This is used when a dequeued job cannot be delivered to the client (e.g., stream failure).
	// The job becomes immediately available for another worker to pick up.
	ReleaseJob(ctx context.Context, caller Caller, taskToken string) error

	// Event streaming
	PublishEvents(ctx context.Context, caller Caller, taskToken string, events []*jobv1.JobEvent) (*PublishResult, error)

	// StreamEvents replays and follows events for a job. The attempt parameter is
	// accepted but ignored until phase 4; all attempts are returned ordered by (attempt, sequence).
	StreamEvents(ctx context.Context, caller Caller, jobID string, attempt int32, fromSequence int64, fromTimestamp int64, eventFilter []jobv1.EventType) (<-chan *jobv1.JobEvent, error)

	// Lifecycle
	Start() error
	Stop() error
}

// JobWithToken represents a job with its associated task token
type JobWithToken struct {
	Job       *jobv1.Job
	TaskToken string

	// VisibilityTimeoutSeconds is the effective lease duration granted at dequeue.
	VisibilityTimeoutSeconds int32
}
