package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestMemoryJobStoreReleaseJob(t *testing.T) {
	ctx := context.Background()

	t.Run("release job returns it to queue", func(t *testing.T) {
		store := NewMemoryJobStore()
		require.NoError(t, store.Start())
		defer func() { _ = store.Stop() }()

		// Enqueue a job
		resp, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
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
		jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		require.Equal(t, jobID, jobs[0].Job.JobId)
		require.Equal(t, jobv1.JobState_JOB_STATE_RUNNING, jobs[0].Job.State)
		taskToken := jobs[0].TaskToken

		// Verify queue is now empty
		jobs2, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Nil(t, jobs2)

		// Release the job
		err = store.ReleaseJob(ctx, taskToken)
		require.NoError(t, err)

		// Verify job state is back to SCHEDULED
		store.mu.RLock()
		job := store.jobs[jobID]
		store.mu.RUnlock()
		require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, job.State)

		// Dequeue again - should get the same job
		jobs3, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Len(t, jobs3, 1)
		require.Equal(t, jobID, jobs3[0].Job.JobId)
	})

	t.Run("released job goes to front of queue", func(t *testing.T) {
		store := NewMemoryJobStore()
		require.NoError(t, store.Start())
		defer func() { _ = store.Stop() }()

		// Enqueue two jobs
		resp1, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "job1"},
		})
		require.NoError(t, err)
		jobID1 := resp1.JobId

		resp2, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-2",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "job2"},
		})
		require.NoError(t, err)
		jobID2 := resp2.JobId

		// Dequeue first job (job1)
		jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Equal(t, jobID1, jobs[0].Job.JobId)
		taskToken1 := jobs[0].TaskToken

		// Release job1 - it should go to front of queue (before job2)
		err = store.ReleaseJob(ctx, taskToken1)
		require.NoError(t, err)

		// Dequeue again - should get job1 first (released jobs have priority)
		jobs2, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Equal(t, jobID1, jobs2[0].Job.JobId)

		// Complete job1
		err = store.CompleteJob(ctx, jobs2[0].TaskToken, &jobv1.JobResult{
			JobId:   jobID1,
			Success: true,
		})
		require.NoError(t, err)

		// Now dequeue should get job2
		jobs3, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		require.Equal(t, jobID2, jobs3[0].Job.JobId)
	})

	t.Run("release with invalid token fails", func(t *testing.T) {
		store := NewMemoryJobStore()
		require.NoError(t, store.Start())
		defer func() { _ = store.Stop() }()

		err := store.ReleaseJob(ctx, "invalid-token")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid task token")
	})

	t.Run("release cleans up task token", func(t *testing.T) {
		store := NewMemoryJobStore()
		require.NoError(t, store.Start())
		defer func() { _ = store.Stop() }()

		// Enqueue and dequeue a job
		resp, err := store.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
			RequestId: "req-1",
			Queue:     "default",
			JobParams: &jobv1.JobParams{Command: "echo"},
		})
		require.NoError(t, err)

		jobs, err := store.DequeueJobs(ctx, "default", 1, 300)
		require.NoError(t, err)
		taskToken := jobs[0].TaskToken
		jobID := resp.JobId

		// Release the job
		err = store.ReleaseJob(ctx, taskToken)
		require.NoError(t, err)

		// Verify task token is cleaned up
		store.mu.RLock()
		_, tokenExists := store.taskTokens[taskToken]
		_, jobTokenExists := store.jobTokens[jobID]
		_, invisibleExists := store.invisibleJobs[jobID]
		store.mu.RUnlock()

		require.False(t, tokenExists, "task token should be deleted")
		require.False(t, jobTokenExists, "job token mapping should be deleted")
		require.False(t, invisibleExists, "invisible job entry should be deleted")

		// Using the old token again should fail
		err = store.ReleaseJob(ctx, taskToken)
		require.Error(t, err)
	})
}

func TestMemoryJobStoreImplementsInterface(t *testing.T) {
	// Verify that MemoryJobStore implements JobStore interface
	var _ JobStore = (*MemoryJobStore)(nil)
}
