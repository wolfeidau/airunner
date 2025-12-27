package store

import (
	"context"
	"errors"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// Sentinel errors for common error conditions
var (
	ErrInvalidTaskToken = errors.New("invalid task token")
	ErrQueueMismatch    = errors.New("queue mismatch")
	ErrJobNotFound      = errors.New("job not found")
	ErrJobIDMismatch    = errors.New("job ID mismatch")
	ErrThrottled        = errors.New("AWS request throttled")
	ErrEventTooLarge    = errors.New("event exceeds maximum size")
)

// JobStore defines the interface for job storage operations
type JobStore interface {
	// Job lifecycle
	EnqueueJob(ctx context.Context, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error)
	DequeueJobs(ctx context.Context, queue string, maxJobs int, timeoutSeconds int) ([]*JobWithToken, error)
	UpdateJobVisibility(ctx context.Context, queue string, taskToken string, timeoutSeconds int) error
	CompleteJob(ctx context.Context, taskToken string, result *jobv1.JobResult) error
	ListJobs(ctx context.Context, req *jobv1.ListJobsRequest) (*jobv1.ListJobsResponse, error)

	// ReleaseJob returns a job back to the queue, resetting its state to SCHEDULED.
	// This is used when a dequeued job cannot be delivered to the client (e.g., stream failure).
	// The job becomes immediately available for another worker to pick up.
	ReleaseJob(ctx context.Context, taskToken string) error

	// Event streaming
	PublishEvents(ctx context.Context, taskToken string, events []*jobv1.JobEvent) error
	StreamEvents(ctx context.Context, jobId string, fromSequence int64, fromTimestamp int64, eventFilter []jobv1.EventType) (<-chan *jobv1.JobEvent, error)

	// Lifecycle
	Start() error
	Stop() error
}

// JobWithToken represents a job with its associated task token
type JobWithToken struct {
	Job       *jobv1.Job
	TaskToken string
}
