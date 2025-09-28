package server

import (
	"context"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
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

	// Long polling implementation - try multiple times
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Second) // 5 second timeout for the request

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
		case <-timeout:
			return nil // No jobs available
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
