package server

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
)

// Server-side polling configuration
const (
	// dequeuePollingInterval is the interval between polls when no messages are available.
	// With SQS long polling enabled (20s), this only applies when the queue is empty.
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

	// Polling with reduced frequency - SQS long polling handles the wait
	ticker := time.NewTicker(dequeuePollingInterval)
	defer ticker.Stop()

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

		// Wait for next poll or timeout
		select {
		case <-ticker.C:
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
