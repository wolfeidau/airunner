package server

import (
	"context"
	"math/rand/v2"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
)

// Server-side polling configuration
const (
	// dequeuePollingInterval is the base interval between polls when no messages are available.
	// With SQS long polling enabled (20s), this only applies when the queue is empty.
	// Actual interval will have jitter applied (±25%) to prevent thundering herd.
	dequeuePollingInterval = 500 * time.Millisecond
)

var _ jobv1connect.JobServiceHandler = &JobServer{}

type JobServer struct {
	store store.JobStore
}

func NewJobServer(store store.JobStore) *JobServer {
	return &JobServer{
		store: store,
	}
}

func (s *JobServer) EnqueueJob(ctx context.Context, req *connect.Request[v1.EnqueueJobRequest]) (*connect.Response[v1.EnqueueJobResponse], error) {
	resp, err := s.store.EnqueueJob(ctx, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resp), nil
}

func (s *JobServer) DequeueJob(ctx context.Context, req *connect.Request[v1.DequeueJobRequest], stream *connect.ServerStream[v1.DequeueJobResponse]) error {
	maxJobs := int(req.Msg.MaxJobs)
	if maxJobs <= 0 {
		maxJobs = 1
	}

	timeoutSeconds := int(req.Msg.VisibilityTimeoutSeconds)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300 // 5 minutes default
	}

	// Polling with jitter to prevent thundering herd
	// SQS long polling handles the wait, this is for when queue is empty
	for {
		jobs, err := s.store.DequeueJobs(ctx, req.Msg.Queue, maxJobs, timeoutSeconds)
		if err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}

		// Send jobs if found
		for _, jobWithToken := range jobs {
			resp := &v1.DequeueJobResponse{
				Job:       jobWithToken.Job,
				TaskToken: jobWithToken.TaskToken,
			}
			if err := stream.Send(resp); err != nil {
				// Release the job back to the queue so it can be picked up by another worker
				// This prevents jobs from being stuck in RUNNING state until visibility timeout
				if releaseErr := s.store.ReleaseJob(ctx, jobWithToken.TaskToken); releaseErr != nil {
					log.Error().Err(releaseErr).Str("job_id", jobWithToken.Job.JobId).Msg("Failed to release job after stream error")
				} else {
					log.Warn().Str("job_id", jobWithToken.Job.JobId).Msg("Released job back to queue after stream failure")
				}
				return connect.NewError(connect.CodeInternal, err)
			}
		}

		// If we got jobs, we're done
		if len(jobs) > 0 {
			return nil
		}

		// Wait for next poll with jitter (±25%) to prevent thundering herd
		pollInterval := addJitter(dequeuePollingInterval, 0.25)
		select {
		case <-time.After(pollInterval):
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *JobServer) UpdateJob(ctx context.Context, req *connect.Request[v1.UpdateJobRequest]) (*connect.Response[v1.UpdateJobResponse], error) {
	timeoutSeconds := int(req.Msg.VisibilityTimeoutSeconds)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300 // 5 minutes default
	}

	err := s.store.UpdateJobVisibility(ctx, req.Msg.Queue, req.Msg.TaskToken, timeoutSeconds)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&v1.UpdateJobResponse{}), nil
}

func (s *JobServer) CompleteJob(ctx context.Context, req *connect.Request[v1.CompleteJobRequest]) (*connect.Response[v1.CompleteJobResponse], error) {
	err := s.store.CompleteJob(ctx, req.Msg.TaskToken, req.Msg.JobResult)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return connect.NewResponse(&v1.CompleteJobResponse{}), nil
}

func (s *JobServer) ListJobs(ctx context.Context, req *connect.Request[v1.ListJobsRequest]) (*connect.Response[v1.ListJobsResponse], error) {
	resp, err := s.store.ListJobs(ctx, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(resp), nil
}

// addJitter adds random jitter to a duration to prevent thundering herd.
// Returns a duration between base*(1-jitterFactor) and base*(1+jitterFactor).
// For jitterFactor=0.25, returns a value between 75% and 125% of base.
func addJitter(base time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 {
		return base
	}
	// Calculate jitter range: base * (1 - jitterFactor) to base * (1 + jitterFactor)
	min := float64(base) * (1.0 - jitterFactor)
	max := float64(base) * (1.0 + jitterFactor)
	//nolint:gosec // G404: Using math/rand for timing jitter is safe and appropriate
	jittered := min + rand.Float64()*(max-min)
	return time.Duration(jittered)
}
