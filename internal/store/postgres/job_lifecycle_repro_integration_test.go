//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func reproEnqueue(t *testing.T, ctx context.Context, store *JobStore, caller jobstore.Caller, requestID, queue string) {
	t.Helper()
	_, err := store.EnqueueJob(ctx, caller, &jobv1.EnqueueJobRequest{
		RequestId: requestID,
		Queue:     queue,
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/test/repro",
			Commit:     "abc123",
			Branch:     "main",
			Command:    "echo",
			Args:       []string{"repro"},
		},
	})
	require.NoError(t, err)
}

func TestRepro_ExpiredLeaseIsRedelivered(t *testing.T) {
	ctx := context.Background()
	store, fx := setupStore(t)

	reproEnqueue(t, ctx, store, fx.User, "repro-expired-lease", "repro-expired")

	first, err := store.DequeueJobs(ctx, fx.Worker, "repro-expired", 1, 1)
	require.NoError(t, err)
	require.Len(t, first, 1)

	// The reaper loop is covered separately; sweep directly once the 1s lease has expired.
	time.Sleep(1200 * time.Millisecond)
	n, err := store.ReapExpired(ctx, 100)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	second, err := store.DequeueJobs(ctx, fx.Worker, "repro-expired", 1, 300)
	require.NoError(t, err)
	require.Len(t, second, 1)

	require.Equal(t, first[0].Job.JobId, second[0].Job.JobId)
	require.NotEqual(t, first[0].TaskToken, second[0].TaskToken)
}

func TestRepro_StaleTokenCannotPublishEvents(t *testing.T) {
	ctx := context.Background()
	store, fx := setupStore(t)

	reproEnqueue(t, ctx, store, fx.User, "repro-stale-token", "repro-stale")

	jobs, err := store.DequeueJobs(ctx, fx.Worker, "repro-stale", 1, 300)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	token := jobs[0].TaskToken

	err = store.CompleteJob(ctx, fx.Worker, token, &jobv1.JobResult{JobId: jobs[0].Job.JobId, Success: true}, 0)
	require.NoError(t, err)

	_, err = store.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{{
		Sequence:  1,
		Timestamp: timestamppb.Now(),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{Output: &jobv1.OutputEvent{Output: []byte("late")}},
	}})
	require.ErrorIs(t, err, jobstore.ErrLeaseLost, "publishing with a token for a completed job must be rejected")
}

func TestRepro_DequeueIndexPredicateMatchesScheduledState(t *testing.T) {
	ctx := context.Background()
	store, _ := setupStore(t)

	var indexDef string
	err := store.pool.QueryRow(ctx,
		`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_jobs_dequeue'`).Scan(&indexDef)
	require.NoError(t, err)

	want := "state = 1"
	require.Contains(t, indexDef, want,
		"idx_jobs_dequeue must be partial on state = %d (SCHEDULED), got: %s",
		int32(jobv1.JobState_JOB_STATE_SCHEDULED), indexDef)
}
