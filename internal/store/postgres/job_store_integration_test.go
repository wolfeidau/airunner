//go:build integration

package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func setupPostgresContainer(t *testing.T, ctx context.Context) (*JobStore, func()) {
	// Start postgres container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:18-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	connString := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())

	// Create store with auto-migrate enabled
	cfg := &JobStoreConfig{
		ConnString:         connString,
		TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
		AutoMigrate:        true, // Enable migrations for tests
	}

	store, err := NewJobStore(ctx, cfg)
	require.NoError(t, err)

	err = store.Start()
	require.NoError(t, err)

	cleanup := func() {
		store.Stop()
		_ = container.Terminate(ctx)
	}

	return store, cleanup
}

func TestIntegration_BasicJobLifecycle(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupPostgresContainer(t, ctx)
	defer cleanup()

	t.Run("enqueue job", func(t *testing.T) {
		req := &jobv1.EnqueueJobRequest{
			RequestId: "test-request-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/repo",
				Commit:     "abc123",
				Branch:     "main",
				Command:    "echo",
				Args:       []string{"hello", "world"},
			},
		}

		resp, err := store.EnqueueJob(ctx, req)
		require.NoError(t, err)
		require.NotEmpty(t, resp.JobId)
		require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, resp.State)
		require.NotNil(t, resp.CreatedAt)

		t.Logf("Enqueued job: %s", resp.JobId)
	})

	t.Run("enqueue idempotency", func(t *testing.T) {
		req := &jobv1.EnqueueJobRequest{
			RequestId: "test-request-idempotent",
			Queue:     "default",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/repo2",
				Commit:     "def456",
				Branch:     "main",
				Command:    "echo",
				Args:       []string{"test"},
			},
		}

		// First enqueue
		resp1, err := store.EnqueueJob(ctx, req)
		require.NoError(t, err)
		jobID1 := resp1.JobId

		// Second enqueue with same request_id
		resp2, err := store.EnqueueJob(ctx, req)
		require.NoError(t, err)
		require.Equal(t, jobID1, resp2.JobId, "Should return same job ID")

		t.Logf("Idempotency verified for job: %s", jobID1)
	})

	t.Run("dequeue and complete job", func(t *testing.T) {
		// Enqueue a job to a dedicated queue
		enqReq := &jobv1.EnqueueJobRequest{
			RequestId: "test-request-dequeue",
			Queue:     "dequeue-test-queue",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/repo3",
				Commit:     "ghi789",
				Branch:     "main",
				Command:    "sleep",
				Args:       []string{"1"},
			},
		}

		enqResp, err := store.EnqueueJob(ctx, enqReq)
		require.NoError(t, err)
		originalJobID := enqResp.JobId

		// Dequeue
		jobs, err := store.DequeueJobs(ctx, "dequeue-test-queue", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		require.Equal(t, originalJobID, jobs[0].Job.JobId)
		require.NotEmpty(t, jobs[0].TaskToken)
		require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, jobs[0].Job.State)

		t.Logf("Dequeued job: %s with token length: %d", jobs[0].Job.JobId, len(jobs[0].TaskToken))

		// Complete the job
		result := &jobv1.JobResult{
			JobId:   jobs[0].Job.JobId,
			Success: true,
			ExitCode: 0,
		}

		err = store.CompleteJob(ctx, jobs[0].TaskToken, result)
		require.NoError(t, err)

		t.Logf("Completed job: %s", jobs[0].Job.JobId)
	})

	t.Run("dequeue no jobs available", func(t *testing.T) {
		jobs, err := store.DequeueJobs(ctx, "empty-queue", 10, 300)
		require.NoError(t, err)
		require.Empty(t, jobs)
	})

	t.Run("update job visibility", func(t *testing.T) {
		// Enqueue and dequeue a job
		enqReq := &jobv1.EnqueueJobRequest{
			RequestId: "test-request-visibility",
			Queue:     "default",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/repo4",
				Commit:     "jkl012",
				Branch:     "main",
				Command:    "echo",
				Args:       []string{"visibility"},
			},
		}

		_, err := store.EnqueueJob(ctx, enqReq)
		require.NoError(t, err)

		jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)

		// Update visibility
		err = store.UpdateJobVisibility(ctx, "default", jobs[0].TaskToken, 600)
		require.NoError(t, err)

		t.Logf("Updated visibility for job: %s", jobs[0].Job.JobId)

		// Clean up - complete the job
		result := &jobv1.JobResult{
			JobId:   jobs[0].Job.JobId,
			Success: true,
		}
		err = store.CompleteJob(ctx, jobs[0].TaskToken, result)
		require.NoError(t, err)
	})

	t.Run("release job", func(t *testing.T) {
		// Enqueue and dequeue a job
		enqReq := &jobv1.EnqueueJobRequest{
			RequestId: "test-request-release",
			Queue:     "default",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/repo5",
				Commit:     "mno345",
				Branch:     "main",
				Command:    "echo",
				Args:       []string{"release"},
			},
		}

		_, err := store.EnqueueJob(ctx, enqReq)
		require.NoError(t, err)

		jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)

		// Release the job back to queue
		err = store.ReleaseJob(ctx, jobs[0].TaskToken)
		require.NoError(t, err)

		t.Logf("Released job: %s", jobs[0].Job.JobId)

		// Should be able to dequeue again
		jobs2, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs2, 1)
		require.Equal(t, jobs[0].Job.JobId, jobs2[0].Job.JobId)

		// Clean up
		result := &jobv1.JobResult{
			JobId:   jobs2[0].Job.JobId,
			Success: true,
		}
		err = store.CompleteJob(ctx, jobs2[0].TaskToken, result)
		require.NoError(t, err)
	})

	t.Run("list jobs", func(t *testing.T) {
		// Enqueue a few jobs
		for i := 0; i < 3; i++ {
			req := &jobv1.EnqueueJobRequest{
				RequestId: time.Now().Format("list-test-2006-01-02T15:04:05.000000"),
				Queue:     "list-queue",
				JobParams: &jobv1.JobParams{
					Repository: "https://github.com/test/list-repo",
					Commit:     "list123",
					Branch:     "main",
					Command:    "echo",
					Args:       []string{"test"},
				},
			}
			_, err := store.EnqueueJob(ctx, req)
			require.NoError(t, err)
			time.Sleep(10 * time.Millisecond) // Ensure different timestamps
		}

		// List jobs
		listReq := &jobv1.ListJobsRequest{
			Queue:    "list-queue",
			PageSize: 10,
		}

		resp, err := store.ListJobs(ctx, listReq)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(resp.Jobs), 3)

		t.Logf("Listed %d jobs from list-queue", len(resp.Jobs))
	})

	t.Run("publish and stream events", func(t *testing.T) {
		// Enqueue and dequeue a job
		enqReq := &jobv1.EnqueueJobRequest{
			RequestId: "test-request-events",
			Queue:     "default",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/events-repo",
				Commit:     "evt123",
				Branch:     "main",
				Command:    "echo",
				Args:       []string{"events"},
			},
		}

		_, err := store.EnqueueJob(ctx, enqReq)
		require.NoError(t, err)

		jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		jobID := jobs[0].Job.JobId

		// Publish some events
		events := []*jobv1.JobEvent{
			{
				Sequence:  1,
				EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
				EventData: &jobv1.JobEvent_ProcessStart{
					ProcessStart: &jobv1.ProcessStartEvent{
						Pid: 12345,
					},
				},
			},
			{
				Sequence:  2,
				EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
				EventData: &jobv1.JobEvent_Output{
					Output: &jobv1.OutputEvent{
						Output: []byte("hello from test"),
					},
				},
			},
			{
				Sequence:  3,
				EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
				EventData: &jobv1.JobEvent_ProcessEnd{
					ProcessEnd: &jobv1.ProcessEndEvent{
						Pid:      12345,
						ExitCode: 0,
					},
				},
			},
		}

		err = store.PublishEvents(ctx, jobs[0].TaskToken, events)
		require.NoError(t, err)

		t.Logf("Published %d events for job: %s", len(events), jobID)

		// Stream events with cancellable context
		streamCtx, cancelStream := context.WithCancel(ctx)
		defer cancelStream()

		eventCh, err := store.StreamEvents(streamCtx, jobID, 0, 0, nil)
		require.NoError(t, err)

		// Collect events
		var receivedEvents []*jobv1.JobEvent
		timeout := time.After(2 * time.Second)

	collectLoop:
		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					break collectLoop
				}
				receivedEvents = append(receivedEvents, event)
				if len(receivedEvents) >= 3 {
					break collectLoop
				}
			case <-timeout:
				break collectLoop
			}
		}

		// Cancel the stream context to clean up the goroutine
		cancelStream()

		require.GreaterOrEqual(t, len(receivedEvents), 3, "Should receive at least 3 events")
		t.Logf("Received %d events from stream", len(receivedEvents))

		// Clean up
		result := &jobv1.JobResult{
			JobId:   jobID,
			Success: true,
		}
		err = store.CompleteJob(ctx, jobs[0].TaskToken, result)
		require.NoError(t, err)
	})
}

func TestIntegration_ConcurrentDequeue(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupPostgresContainer(t, ctx)
	defer cleanup()

	// Enqueue 5 jobs
	jobIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		req := &jobv1.EnqueueJobRequest{
			RequestId: time.Now().Format("concurrent-2006-01-02T15:04:05.000000"),
			Queue:     "concurrent-queue",
			JobParams: &jobv1.JobParams{
				Repository: "https://github.com/test/concurrent",
				Commit:     "con123",
				Branch:     "main",
				Command:    "echo",
				Args:       []string{"concurrent"},
			},
		}
		resp, err := store.EnqueueJob(ctx, req)
		require.NoError(t, err)
		jobIDs[i] = resp.JobId
		time.Sleep(10 * time.Millisecond)
	}

	// Dequeue concurrently with 3 workers
	type dequeueResult struct {
		workerID int
		jobs     []string
		err      error
	}

	results := make(chan dequeueResult, 3)

	for w := 0; w < 3; w++ {
		workerID := w
		go func() {
			jobs, err := store.DequeueJobs(ctx, "concurrent-queue", 2, 300)
			var jobIDs []string
			for _, j := range jobs {
				jobIDs = append(jobIDs, j.Job.JobId)
			}
			results <- dequeueResult{
				workerID: workerID,
				jobs:     jobIDs,
				err:      err,
			}
		}()
	}

	// Collect results
	allDequeuedJobs := make(map[string]bool)
	for i := 0; i < 3; i++ {
		result := <-results
		require.NoError(t, result.err)
		t.Logf("Worker %d dequeued %d jobs: %v", result.workerID, len(result.jobs), result.jobs)

		for _, jobID := range result.jobs {
			require.False(t, allDequeuedJobs[jobID], "Job %s dequeued by multiple workers!", jobID)
			allDequeuedJobs[jobID] = true
		}
	}

	// Verify all 5 jobs were dequeued exactly once
	require.Equal(t, 5, len(allDequeuedJobs), "All jobs should be dequeued exactly once")
	t.Logf("✓ Concurrent dequeue test passed: 5 jobs dequeued by 3 workers with no duplicates")
}
