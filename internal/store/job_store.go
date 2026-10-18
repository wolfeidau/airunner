package store

import (
	"context"
	"errors"
	"fmt"

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

	// ErrInvalidArgument indicates the request failed validation.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrUnavailable indicates a transient storage failure (lock or statement
	// timeout, serialization conflict, lost connection); the caller may retry.
	ErrUnavailable = errors.New("storage temporarily unavailable")

	// ErrLeaseLost indicates the task token no longer holds a valid lease.
	ErrLeaseLost = errors.New("lease lost")

	// ErrJobCancelled indicates the job was cancelled while the caller held (or
	// believed it held) a lease. It wraps ErrLeaseLost, so existing lease-loss
	// handling applies; check it first to tell cancellation from other lease loss.
	ErrJobCancelled = fmt.Errorf("job cancelled: %w", ErrLeaseLost)

	// ErrFailedPrecondition indicates the job is in a state that does not permit the operation.
	ErrFailedPrecondition = errors.New("failed precondition")

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
	// CompleteJob records the result. finalEventSequence must equal the attempt's
	// last committed event sequence.
	CompleteJob(ctx context.Context, caller Caller, taskToken string, result *jobv1.JobResult, finalEventSequence int64) error
	ListJobs(ctx context.Context, caller Caller, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error)

	// ReleaseJob returns a job back to the queue, resetting its state to SCHEDULED.
	// This is used when a dequeued job cannot be delivered to the client (e.g., stream failure).
	// The job becomes immediately available for another worker to pick up.
	ReleaseJob(ctx context.Context, caller Caller, taskToken string) error

	// CancelJob cancels a SCHEDULED or RUNNING job. Cancelling a CANCELLED job is a no-op;
	// COMPLETED or FAILED returns ErrFailedPrecondition. It returns the resulting state.
	CancelJob(ctx context.Context, caller Caller, jobID string) (jobv1.JobState, error)

	// Event streaming
	PublishEvents(ctx context.Context, caller Caller, taskToken string, events []*jobv1.JobEvent) (*PublishResult, error)

	// StreamEvents streams one attempt of a job: an initial status message, then the
	// attempt's events in sequence order, then a final status with AttemptClosed set.
	// It is synchronous: send is called from the caller's goroutine, and a send error
	// aborts the stream and is returned as-is. It returns nil after the final closed
	// status, ctx.Err() if ctx ends, and ErrUnavailable if the store stops.
	StreamEvents(ctx context.Context, caller Caller, req StreamRequest, send func(*StreamResponse) error) error

	// Lifecycle
	Start() error
	Stop() error
}

// StreamRequest selects the attempt and starting point of an event stream.
type StreamRequest struct {
	JobID         string
	Attempt       int32 // 0 resolves to the latest started attempt, or waits for attempt 1
	FromSequence  int64
	FromTimestamp int64 // unix milliseconds
	EventFilter   []jobv1.EventType
}

// StreamResponse is one stream message. Event is nil for status-only responses.
type StreamResponse struct {
	Event         *jobv1.JobEvent
	Attempt       int32
	JobState      jobv1.JobState
	AttemptClosed bool
}

// JobWithToken represents a job with its associated task token
type JobWithToken struct {
	Job       *jobv1.Job
	TaskToken string

	// VisibilityTimeoutSeconds is the effective lease duration granted at dequeue.
	VisibilityTimeoutSeconds int32
}
