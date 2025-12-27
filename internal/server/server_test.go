package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCompleteJobWorkflow(t *testing.T) {
	// Create test server
	memStore := memorystore.NewJobStore()
	require.NoError(t, memStore.Start())
	defer func() {
		require.NoError(t, memStore.Stop())
	}()

	server := NewServer(memStore)
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	// Create clients
	jobClient := jobv1connect.NewJobServiceClient(http.DefaultClient, testServer.URL)
	eventsClient := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, testServer.URL)

	ctx := context.Background()

	// 1. Enqueue a job
	enqueueReq := &jobv1.EnqueueJobRequest{
		RequestId: uuid.New().String(),
		Queue:     "test-queue",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Commit:     "abc123",
			Branch:     "main",
			Environment: map[string]string{
				"NODE_ENV": "test",
			},
			Owner: "test-user",
		},
	}

	enqueueResp, err := jobClient.EnqueueJob(ctx, connect.NewRequest(enqueueReq))
	require.NoError(t, err)
	require.NotEmpty(t, enqueueResp.Msg.JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, enqueueResp.Msg.State)

	jobID := enqueueResp.Msg.JobId

	// 2. Dequeue the job
	dequeueReq := &jobv1.DequeueJobRequest{
		Queue:                    "test-queue",
		MaxJobs:                  1,
		VisibilityTimeoutSeconds: 300,
	}

	dequeueStream, err := jobClient.DequeueJob(ctx, connect.NewRequest(dequeueReq))
	require.NoError(t, err)
	defer dequeueStream.Close()

	require.True(t, dequeueStream.Receive())
	dequeueResp := dequeueStream.Msg()
	require.Equal(t, jobID, dequeueResp.Job.JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, dequeueResp.Job.State)
	require.NotEmpty(t, dequeueResp.TaskToken)

	taskToken := dequeueResp.TaskToken

	// 3. Publish some events (simplified - no streaming verification for now)
	publishStream := eventsClient.PublishJobEvents(ctx)

	// Send a start event
	startEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
		EventData: &jobv1.JobEvent_ProcessStart{
			ProcessStart: &jobv1.ProcessStartEvent{
				Pid:       12345,
				StartedAt: timestamppb.Now(),
			},
		},
	}

	err = publishStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{startEvent},
	})
	require.NoError(t, err)

	// Close publish stream
	_, err = publishStream.CloseAndReceive()
	require.NoError(t, err)

	// 4. Update job visibility timeout
	updateReq := &jobv1.UpdateJobRequest{
		Queue:                    "test-queue",
		TaskToken:                taskToken,
		VisibilityTimeoutSeconds: 600,
	}

	_, err = jobClient.UpdateJob(ctx, connect.NewRequest(updateReq))
	require.NoError(t, err)

	// 5. Complete the job
	completeReq := &jobv1.CompleteJobRequest{
		TaskToken: taskToken,
		JobResult: &jobv1.JobResult{
			JobId:       jobID,
			Success:     true,
			ExitCode:    0,
			StartedAt:   timestamppb.Now(),
			CompletedAt: timestamppb.Now(),
		},
	}

	_, err = jobClient.CompleteJob(ctx, connect.NewRequest(completeReq))
	require.NoError(t, err)

	// 6. List jobs to verify completion
	listReq := &jobv1.ListJobsRequest{
		Queue:    "test-queue",
		State:    jobv1.JobState_JOB_STATE_COMPLETED,
		Page:     1,
		PageSize: 10,
	}

	listResp, err := jobClient.ListJobs(ctx, connect.NewRequest(listReq))
	require.NoError(t, err)
	require.Len(t, listResp.Msg.Jobs, 1)
	require.Equal(t, jobID, listResp.Msg.Jobs[0].JobId)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, listResp.Msg.Jobs[0].State)
}

func TestIdempotentJobEnqueue(t *testing.T) {
	// Create test server
	memStore := memorystore.NewJobStore()
	require.NoError(t, memStore.Start())
	defer func() {
		require.NoError(t, memStore.Stop())
	}()

	server := NewServer(memStore)
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	jobClient := jobv1connect.NewJobServiceClient(http.DefaultClient, testServer.URL)
	ctx := context.Background()

	requestID := uuid.New().String()

	// Enqueue the same job twice with the same request ID
	enqueueReq := &jobv1.EnqueueJobRequest{
		RequestId: requestID,
		Queue:     "test-queue",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Owner:      "test-user",
		},
	}

	// First enqueue
	resp1, err := jobClient.EnqueueJob(ctx, connect.NewRequest(enqueueReq))
	require.NoError(t, err)

	// Second enqueue with same request ID
	resp2, err := jobClient.EnqueueJob(ctx, connect.NewRequest(enqueueReq))
	require.NoError(t, err)

	// Should return the same job ID
	require.Equal(t, resp1.Msg.JobId, resp2.Msg.JobId)
}

func TestVisibilityTimeoutExpiry(t *testing.T) {
	// Skip this test for now since it requires long wait times
	t.Skip("Skipping visibility timeout test - requires long wait times")
}
