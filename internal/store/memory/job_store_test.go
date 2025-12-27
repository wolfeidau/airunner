package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
)

func TestJobStoreReleaseJob(t *testing.T) {
	ctx := context.Background()

	t.Run("release job returns it to queue", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue a job
		resp, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{
				Command: "echo",
				Args:    []string{"hello"},
			},
		})
		require.NoError(t, err)
		jobID := resp.JobId

		// Dequeue the job
		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		require.Equal(t, jobID, jobs[0].Job.JobId)
		require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, jobs[0].Job.State)
		taskToken := jobs[0].TaskToken

		// Verify queue is now empty
		jobs2, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Nil(t, jobs2)

		// Release the job
		err = st.ReleaseJob(ctx, taskToken)
		require.NoError(t, err)

		// Verify job state is back to SCHEDULED
		st.mu.RLock()
		job := st.jobs[jobID]
		st.mu.RUnlock()
		require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, job.State)

		// Dequeue again - should get the same job
		jobs3, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs3, 1)
		require.Equal(t, jobID, jobs3[0].Job.JobId)
	})

	t.Run("released job goes to front of queue", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue two jobs
		resp1, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "job1"},
		})
		require.NoError(t, err)
		jobID1 := resp1.JobId

		resp2, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-2",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "job2"},
		})
		require.NoError(t, err)
		jobID2 := resp2.JobId

		// Dequeue first job (job1)
		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Equal(t, jobID1, jobs[0].Job.JobId)
		taskToken1 := jobs[0].TaskToken

		// Release job1 - it should go to front of queue (before job2)
		err = st.ReleaseJob(ctx, taskToken1)
		require.NoError(t, err)

		// Dequeue again - should get job1 first (released jobs have priority)
		jobs2, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Equal(t, jobID1, jobs2[0].Job.JobId)

		// Complete job1
		err = st.CompleteJob(ctx, jobs2[0].TaskToken, &jobv1.JobResult{
			JobId:   jobID1,
			Success: true,
		})
		require.NoError(t, err)

		// Now dequeue should get job2
		jobs3, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Equal(t, jobID2, jobs3[0].Job.JobId)
	})

	t.Run("release with invalid token fails", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		err := st.ReleaseJob(ctx, "invalid-token")
		require.Error(t, err)
		require.ErrorIs(t, err, store.ErrInvalidTaskToken)
	})

	t.Run("release cleans up task token", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue and dequeue a job
		resp, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "echo"},
		})
		require.NoError(t, err)

		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		taskToken := jobs[0].TaskToken
		jobID := resp.JobId

		// Release the job
		err = st.ReleaseJob(ctx, taskToken)
		require.NoError(t, err)

		// Verify task token is cleaned up
		st.mu.RLock()
		_, tokenExists := st.taskTokens[taskToken]
		_, jobTokenExists := st.jobTokens[jobID]
		_, invisibleExists := st.invisibleJobs[jobID]
		st.mu.RUnlock()

		require.False(t, tokenExists, "task token should be deleted")
		require.False(t, jobTokenExists, "job token mapping should be deleted")
		require.False(t, invisibleExists, "invisible job entry should be deleted")

		// Using the old token again should fail
		err = st.ReleaseJob(ctx, taskToken)
		require.Error(t, err)
	})
}

func TestMemoryJobStoreCompleteJob(t *testing.T) {
	ctx := context.Background()

	t.Run("complete job marks it as completed", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue and dequeue a job
		resp, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "echo"},
		})
		require.NoError(t, err)
		jobID := resp.JobId

		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		taskToken := jobs[0].TaskToken

		// Complete the job
		err = st.CompleteJob(ctx, taskToken, &jobv1.JobResult{
			JobId:   jobID,
			Success: true,
		})
		require.NoError(t, err)

		// Verify job state is completed
		st.mu.RLock()
		job := st.jobs[jobID]
		st.mu.RUnlock()
		require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, job.State)
	})

	t.Run("complete job with invalid token fails", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		err := st.CompleteJob(ctx, "invalid-token", &jobv1.JobResult{
			JobId:   "job-123",
			Success: true,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, store.ErrInvalidTaskToken)
	})

	t.Run("complete job with mismatched job ID fails", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue and dequeue a job
		resp, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "echo"},
		})
		require.NoError(t, err)
		jobID := resp.JobId

		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		taskToken := jobs[0].TaskToken

		// Try to complete with wrong job ID
		err = st.CompleteJob(ctx, taskToken, &jobv1.JobResult{
			JobId:   "wrong-job-id",
			Success: true,
		})
		require.Error(t, err)
		require.ErrorIs(t, err, store.ErrJobIDMismatch)

		// Verify job state is still RUNNING (not changed)
		st.mu.RLock()
		job := st.jobs[jobID]
		st.mu.RUnlock()
		require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, job.State)
	})

	t.Run("complete job cleans up task token", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue and dequeue a job
		resp, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "echo"},
		})
		require.NoError(t, err)
		jobID := resp.JobId

		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		taskToken := jobs[0].TaskToken

		// Complete the job
		err = st.CompleteJob(ctx, taskToken, &jobv1.JobResult{
			JobId:   jobID,
			Success: true,
		})
		require.NoError(t, err)

		// Verify task token is cleaned up
		st.mu.RLock()
		_, tokenExists := st.taskTokens[taskToken]
		_, jobTokenExists := st.jobTokens[jobID]
		_, invisibleExists := st.invisibleJobs[jobID]
		st.mu.RUnlock()

		require.False(t, tokenExists, "task token should be deleted")
		require.False(t, jobTokenExists, "job token mapping should be deleted")
		require.False(t, invisibleExists, "invisible job entry should be deleted")
	})
}

func TestMemoryJobStorePublishAndStreamEvents(t *testing.T) {
	ctx := context.Background()

	t.Run("publish events to active streams", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		// Enqueue and dequeue a job
		resp, err := st.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "echo"},
		})
		require.NoError(t, err)
		jobID := resp.JobId

		jobs, err := st.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		taskToken := jobs[0].TaskToken

		// Create an event stream
		eventChan, err := st.StreamEvents(ctx, jobID, 0, 0, nil)
		require.NoError(t, err)

		// Publish events
		err = st.PublishEvents(ctx, taskToken, []*jobv1.JobEvent{
			{EventType: jobv1.EventType_EVENT_TYPE_UNSPECIFIED},
			{EventType: jobv1.EventType_EVENT_TYPE_UNSPECIFIED},
		})
		require.NoError(t, err)

		// Receive events
		event1 := <-eventChan
		require.NotNil(t, event1)
		event2 := <-eventChan
		require.NotNil(t, event2)
	})

	t.Run("stream events for non-existent job fails", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		_, err := st.StreamEvents(ctx, "non-existent-job-id", 0, 0, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, store.ErrJobNotFound)
	})

	t.Run("publish events with invalid token fails", func(t *testing.T) {
		st := NewJobStore()
		require.NoError(t, st.Start())
		defer func() { _ = st.Stop() }()

		err := st.PublishEvents(ctx, "invalid-token", []*jobv1.JobEvent{})
		require.Error(t, err)
		require.ErrorIs(t, err, store.ErrInvalidTaskToken)
	})
}

func TestMemoryJobStoreImplementsInterface(t *testing.T) {
	// Verify that MemoryJobStore implements JobStore interface
	var _ store.JobStore = (*JobStore)(nil)
}
