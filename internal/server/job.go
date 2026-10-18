package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/store"
)

// Server-side polling configuration
const (
	// dequeuePollingInterval is the base interval between polls when no messages are available.
	// With SQS long polling enabled (20s), this only applies when the queue is empty.
	// Actual interval will have jitter applied (±25%) to prevent thundering herd.
	dequeuePollingInterval = 500 * time.Millisecond
)

// Visibility timeout limits, enforced at the RPC boundary only. The store accepts
// any positive value so tests can use short durations.
const (
	defaultVisibilityTimeoutSeconds = 300
	minVisibilityTimeoutSeconds     = 30
	maxVisibilityTimeoutSeconds     = 3600

	// releaseTimeout bounds each release issued after a dequeue delivery failure.
	releaseTimeout = 5 * time.Second
)

// validateVisibilityTimeout applies the default for 0 and rejects values outside
// [minVisibilityTimeoutSeconds, maxVisibilityTimeoutSeconds].
func validateVisibilityTimeout(seconds int32) (int, error) {
	if seconds == 0 {
		return defaultVisibilityTimeoutSeconds, nil
	}
	if seconds < minVisibilityTimeoutSeconds || seconds > maxVisibilityTimeoutSeconds {
		return 0, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("visibility_timeout_seconds must be between %d and %d", minVisibilityTimeoutSeconds, maxVisibilityTimeoutSeconds))
	}
	return int(seconds), nil
}

// releaseUnsent releases jobs that could not be delivered to the worker. Each release
// uses a fresh context detached from the (likely cancelled) request context.
func (s *JobServer) releaseUnsent(ctx context.Context, caller store.Caller, jobs []*store.JobWithToken) {
	for _, j := range jobs {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
		err := s.store.ReleaseJob(cctx, caller, j.TaskToken)
		cancel()
		if err != nil {
			log.Error().Err(err).Str("job_id", j.Job.JobId).Msg("Failed to release job after stream error")
		} else {
			log.Warn().Str("job_id", j.Job.JobId).Msg("Released job back to queue after stream failure")
		}
	}
}

var _ jobv1connect.JobServiceHandler = &JobServer{}

type JobServer struct {
	store store.JobStore
}

func NewJobServer(store store.JobStore) *JobServer {
	return &JobServer{
		store: store,
	}
}

// callerFromContext derives the store caller from the authenticated principal.
func callerFromContext(ctx context.Context) (store.Caller, error) {
	principal := auth.PrincipalFromContext(ctx)
	if principal == nil {
		return store.Caller{}, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	return store.Caller{OrgID: principal.OrgID, PrincipalID: principal.PrincipalID}, nil
}

func (s *JobServer) EnqueueJob(ctx context.Context, req *connect.Request[v1.EnqueueJobRequest]) (*connect.Response[v1.EnqueueJobResponse], error) {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := s.store.EnqueueJob(ctx, caller, req.Msg)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(resp), nil
}

func (s *JobServer) DequeueJob(ctx context.Context, req *connect.Request[v1.DequeueJobRequest], stream *connect.ServerStream[v1.DequeueJobResponse]) error {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return err
	}

	maxJobs := int(req.Msg.MaxJobs)
	if maxJobs <= 0 {
		maxJobs = 1
	}

	timeoutSeconds, err := validateVisibilityTimeout(req.Msg.VisibilityTimeoutSeconds)
	if err != nil {
		return err
	}

	// Polling with jitter to prevent thundering herd
	// SQS long polling handles the wait, this is for when queue is empty
	for {
		jobs, err := s.store.DequeueJobs(ctx, caller, req.Msg.Queue, maxJobs, timeoutSeconds)
		if err != nil {
			return toConnectError(err)
		}

		// Send jobs if found
		for i, jobWithToken := range jobs {
			resp := &v1.DequeueJobResponse{
				Job:       jobWithToken.Job,
				TaskToken: jobWithToken.TaskToken,

				VisibilityTimeoutSeconds: jobWithToken.VisibilityTimeoutSeconds,
			}
			if err := stream.Send(resp); err != nil {
				// Release the failed job and all remaining unsent jobs so they are not
				// stuck in RUNNING until the visibility timeout expires.
				s.releaseUnsent(ctx, caller, jobs[i:])
				return toConnectError(err)
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
	timeoutSeconds, err := validateVisibilityTimeout(req.Msg.VisibilityTimeoutSeconds)
	if err != nil {
		return nil, err
	}

	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	effective, err := s.store.UpdateJobVisibility(ctx, caller, req.Msg.TaskToken, timeoutSeconds)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&v1.UpdateJobResponse{VisibilityTimeoutSeconds: effective}), nil
}

func (s *JobServer) CompleteJob(ctx context.Context, req *connect.Request[v1.CompleteJobRequest]) (*connect.Response[v1.CompleteJobResponse], error) {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	err = s.store.CompleteJob(ctx, caller, req.Msg.TaskToken, req.Msg.JobResult, req.Msg.FinalEventSequence)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&v1.CompleteJobResponse{}), nil
}

func (s *JobServer) ListJobs(ctx context.Context, req *connect.Request[v1.ListJobsRequest]) (*connect.Response[v1.ListJobsResponse], error) {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := s.store.ListJobs(ctx, caller, req.Msg)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(resp), nil
}

// CancelJob cancels a SCHEDULED or RUNNING job. Cancelling a cancelled job succeeds.
func (s *JobServer) CancelJob(ctx context.Context, req *connect.Request[v1.CancelJobRequest]) (*connect.Response[v1.CancelJobResponse], error) {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.Msg.JobId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("job_id is required"))
	}

	state, err := s.store.CancelJob(ctx, caller, req.Msg.JobId)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&v1.CancelJobResponse{State: state}), nil
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
