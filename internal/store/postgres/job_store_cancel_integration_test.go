//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	jobstore "github.com/wolfeidau/airunner/internal/store"
)

func leaseColumnsNull(t *testing.T, js *JobStore, jobID string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, js.pool.QueryRow(context.Background(),
		`SELECT visibility_until IS NULL AND receipt_handle IS NULL AND leased_by IS NULL FROM jobs WHERE job_id = $1`,
		jobID).Scan(&ok))
	return ok
}

func TestCancel_Scheduled(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID := enqueueOnly(t, js, fx, "cancel-sched")

	state, err := js.CancelJob(ctx, fx.User, jobID)
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, state)

	jobs, err := js.DequeueJobs(ctx, fx.Worker, "cancel-sched", 1, 300)
	require.NoError(t, err)
	require.Empty(t, jobs)
	require.True(t, leaseColumnsNull(t, js, jobID))
}

func TestCancel_RunningFencesOldToken(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "cancel-run", 3, 300)

	state, err := js.CancelJob(ctx, fx.User, jobID)
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, state)
	require.True(t, leaseColumnsNull(t, js, jobID))

	assertCancelled := func(err error) {
		t.Helper()
		require.ErrorIs(t, err, jobstore.ErrJobCancelled)
		require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	}
	_, err = js.UpdateJobVisibility(ctx, fx.Worker, token, 300)
	assertCancelled(err)
	_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
	assertCancelled(err)
	assertCancelled(js.CompleteJob(ctx, fx.Worker, token, successResult(jobID), 0))
	assertCancelled(js.ReleaseJob(ctx, fx.Worker, token))

	s, _, _ := jobRow(t, js, jobID)
	require.EqualValues(t, jobv1.JobState_JOB_STATE_CANCELLED, s)
	require.Zero(t, countEvents(t, js, jobID))

	// The reaper must not resurrect it.
	n, err := js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestCancel_Idempotent(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID := enqueueOnly(t, js, fx, "cancel-idem")
	for range 2 {
		state, err := js.CancelJob(ctx, fx.User, jobID)
		require.NoError(t, err)
		require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, state)
	}
}

func TestCancel_TerminalStatesRejected(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	doneID, doneTok := leasedJob(t, js, fx, "cancel-done", 1, 300)
	require.NoError(t, js.CompleteJob(ctx, fx.Worker, doneTok, successResult(doneID), 0))
	failID, failTok := leasedJob(t, js, fx, "cancel-fail", 1, 300)
	require.NoError(t, js.CompleteJob(ctx, fx.Worker, failTok, &jobv1.JobResult{JobId: failID, Success: false}, 0))

	for id, want := range map[string]jobv1.JobState{
		doneID: jobv1.JobState_JOB_STATE_COMPLETED,
		failID: jobv1.JobState_JOB_STATE_FAILED,
	} {
		_, err := js.CancelJob(ctx, fx.User, id)
		require.ErrorIs(t, err, jobstore.ErrFailedPrecondition)
		s, _, _ := jobRow(t, js, id)
		require.EqualValues(t, want, s)
	}
}

func TestCancel_NotFound(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID := enqueueOnly(t, js, fx, "cancel-nf")

	other := jobstore.Caller{OrgID: uuid.New(), PrincipalID: uuid.New()}
	_, err := js.CancelJob(ctx, other, jobID)
	require.ErrorIs(t, err, jobstore.ErrJobNotFound)
	_, err = js.CancelJob(ctx, fx.User, uuid.NewString())
	require.ErrorIs(t, err, jobstore.ErrJobNotFound)
	_, err = js.CancelJob(ctx, fx.User, "not-a-uuid")
	require.ErrorIs(t, err, jobstore.ErrJobNotFound)

	s, _, _ := jobRow(t, js, jobID)
	require.EqualValues(t, jobv1.JobState_JOB_STATE_SCHEDULED, s)
}

func TestCancel_WaitsForRowLockThenFencesPublish(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "cancel-race", 3, 300)

	tx, err := js.pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	var s int32
	require.NoError(t, tx.QueryRow(ctx, `SELECT state FROM jobs WHERE job_id = $1 FOR UPDATE`, jobID).Scan(&s))

	done := make(chan error, 1)
	go func() {
		_, err := js.CancelJob(ctx, fx.User, jobID)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("CancelJob returned while the row was locked: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	require.NoError(t, tx.Commit(ctx))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("CancelJob did not finish after the lock was released")
	}

	_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
	require.ErrorIs(t, err, jobstore.ErrJobCancelled)
	require.Zero(t, countEvents(t, js, jobID))
}

func TestCancel_EndsStreams(t *testing.T) {
	ctx := context.Background()
	writer, streamer, fx := streamStores(t)

	schedID := enqueueOnly(t, writer, fx, "cancel-stream-s")
	sched := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: schedID}, nil)
	sched.waitCount(t, 1)

	runID, token := leasedJob(t, writer, fx, "cancel-stream-r", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 3)
	running := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: runID}, nil)
	running.waitCount(t, 4)

	_, err := writer.CancelJob(ctx, fx.User, schedID)
	require.NoError(t, err)
	_, err = writer.CancelJob(ctx, fx.User, runID)
	require.NoError(t, err)

	for _, run := range []*streamRun{sched, running} {
		require.NoError(t, run.wait(t))
		resps := run.responses()
		last := resps[len(resps)-1]
		require.True(t, last.AttemptClosed)
		require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, last.JobState)
	}
}

func TestCancel_Metrics(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	schedID := enqueueOnly(t, js, fx, "cancel-m-s")
	_, _ = leasedJob(t, js, fx, "cancel-m-r", 3, 300)
	var runID string
	require.NoError(t, js.pool.QueryRow(ctx, `SELECT job_id::text FROM jobs WHERE state = 2`).Scan(&runID))

	_, err := js.CancelJob(ctx, fx.User, schedID)
	require.NoError(t, err)
	_, err = js.CancelJob(ctx, fx.User, schedID) // idempotent, not counted
	require.NoError(t, err)
	_, err = js.CancelJob(ctx, fx.User, runID)
	require.NoError(t, err)

	require.EqualValues(t, 1, h.Sum(t, "jobs.cancelled", attr("from", "scheduled")))
	require.EqualValues(t, 1, h.Sum(t, "jobs.cancelled", attr("from", "running")))
}
