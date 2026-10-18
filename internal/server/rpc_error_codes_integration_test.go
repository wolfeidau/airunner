//go:build integration

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
)

func TestRPCErrorCodes(t *testing.T) {
	stores := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, stores)
	other := postgrestest.SeedOrg(t, stores)

	handler := NewServer(stores.Jobs).Handler()
	userURL := principalServer(t, handler, fx.User, []string{"user"}, "user")
	workerURL := principalServer(t, handler, fx.Worker, []string{"worker"}, "worker")
	otherWorkerURL := principalServer(t, handler, other.Worker, []string{"worker"}, "worker")

	user := jobv1connect.NewJobServiceClient(http.DefaultClient, userURL)
	worker := jobv1connect.NewJobServiceClient(http.DefaultClient, workerURL)
	otherWorker := jobv1connect.NewJobServiceClient(http.DefaultClient, otherWorkerURL)
	userEvents := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, userURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	params := &jobv1.JobParams{Repository: "https://github.com/example/repo", Commit: "abc123", Branch: "main"}
	enqueue := func(queue string, maxAttempts *int32) (*connect.Response[jobv1.EnqueueJobResponse], error) {
		return user.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{
			RequestId: uuid.New().String(), Queue: queue, JobParams: params, MaxAttempts: maxAttempts,
		}))
	}
	dequeue := func(queue string) (*jobv1.Job, string) {
		t.Helper()
		stream, err := worker.DequeueJob(ctx, connect.NewRequest(&jobv1.DequeueJobRequest{Queue: queue, MaxJobs: 1}))
		require.NoError(t, err)
		defer stream.Close()
		require.True(t, stream.Receive(), "stream error: %v", stream.Err())
		return stream.Msg().Job, stream.Msg().TaskToken
	}

	t.Run("stale token FailedPrecondition", func(t *testing.T) {
		_, err := enqueue("stale", nil)
		require.NoError(t, err)
		job, token := dequeue("stale")
		result := &jobv1.JobResult{JobId: job.JobId, Success: true}

		_, err = worker.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{TaskToken: token, JobResult: result}))
		require.NoError(t, err)
		_, err = worker.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{TaskToken: token, JobResult: result}))
		require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	})

	t.Run("other org token FailedPrecondition", func(t *testing.T) {
		_, err := enqueue("crossorg", nil)
		require.NoError(t, err)
		job, token := dequeue("crossorg")

		_, err = otherWorker.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{
			TaskToken: token, JobResult: &jobv1.JobResult{JobId: job.JobId, Success: true},
		}))
		require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
	})

	t.Run("changed intent same request_id AlreadyExists", func(t *testing.T) {
		reqID := uuid.New().String()
		_, err := user.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{RequestId: reqID, Queue: "intent", JobParams: params}))
		require.NoError(t, err)
		_, err = user.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{RequestId: reqID, Queue: "other-queue", JobParams: params}))
		require.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	})

	t.Run("stream unknown job NotFound", func(t *testing.T) {
		stream, err := userEvents.StreamJobEvents(ctx, connect.NewRequest(&jobv1.StreamJobEventsRequest{JobId: uuid.New().String()}))
		if err == nil {
			defer stream.Close()
			for stream.Receive() {
			}
			err = stream.Err()
		}
		require.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})

	t.Run("stream existing job sends initial status", func(t *testing.T) {
		resp, err := enqueue("streamstatus", nil)
		require.NoError(t, err)
		streamCtx, cancelStream := context.WithCancel(ctx)
		defer cancelStream()
		stream, err := userEvents.StreamJobEvents(streamCtx, connect.NewRequest(&jobv1.StreamJobEventsRequest{JobId: resp.Msg.JobId}))
		require.NoError(t, err)
		defer stream.Close()
		require.True(t, stream.Receive(), "stream error: %v", stream.Err())
		require.Nil(t, stream.Msg().Event)
		require.GreaterOrEqual(t, stream.Msg().ResolvedAttempt, int32(1))
		require.False(t, stream.Msg().AttemptClosed)
	})

	t.Run("stream attempt beyond latest InvalidArgument", func(t *testing.T) {
		resp, err := enqueue("streamattempt", nil)
		require.NoError(t, err)
		stream, err := userEvents.StreamJobEvents(ctx, connect.NewRequest(&jobv1.StreamJobEventsRequest{JobId: resp.Msg.JobId, Attempt: 99}))
		if err == nil {
			defer stream.Close()
			for stream.Receive() {
			}
			err = stream.Err()
		}
		require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	})

	t.Run("max_attempts out of range InvalidArgument", func(t *testing.T) {
		for _, n := range []int32{0, 101} {
			_, err := enqueue("range", &n)
			require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err), "max_attempts=%d", n)
		}
	})

	t.Run("malformed token InvalidArgument", func(t *testing.T) {
		_, err := worker.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{
			TaskToken: "not-a-token", JobResult: &jobv1.JobResult{JobId: uuid.New().String()},
		}))
		require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	})
}
