//go:build integration

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// leasedJob enqueues one job and leases it to the fixture worker.
func leasedJob(t *testing.T, js *JobStore, fx orgFixture, name string, maxAttempts int32, visibility int) (jobID, token string) {
	t.Helper()
	ctx := context.Background()
	req := contractReq(name, name, "echo")
	req.MaxAttempts = &maxAttempts
	_, err := js.EnqueueJob(ctx, fx.User, req)
	require.NoError(t, err)
	return dequeueOne(t, js, fx, name, visibility)
}

func dequeueOne(t *testing.T, js *JobStore, fx orgFixture, queue string, visibility int) (jobID, token string) {
	t.Helper()
	jobs, err := js.DequeueJobs(context.Background(), fx.Worker, queue, 1, visibility)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	return jobs[0].Job.JobId, jobs[0].TaskToken
}

func startEvent(seq int64) *jobv1.JobEvent {
	return &jobv1.JobEvent{Attempt: 1, Sequence: seq, Timestamp: timestamppb.Now(), EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START}
}

func outputItems(n int) []*jobv1.OutputItem {
	items := make([]*jobv1.OutputItem, n)
	for i := range items {
		items[i] = &jobv1.OutputItem{Output: []byte("x")}
	}
	return items
}

func batchEvent(start, end int64) *jobv1.JobEvent {
	return &jobv1.JobEvent{
		Attempt: 1, Sequence: start, Timestamp: timestamppb.Now(), EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		EventData: &jobv1.JobEvent_OutputBatch{OutputBatch: &jobv1.OutputBatchEvent{
			StartSequence: start, EndSequence: end, Outputs: outputItems(int(end - start + 1)),
		}},
	}
}

func expireLease(t *testing.T, js *JobStore, jobID string) {
	t.Helper()
	_, err := js.pool.Exec(context.Background(),
		`UPDATE jobs SET visibility_until = clock_timestamp() - INTERVAL '1 second' WHERE job_id = $1`, jobID)
	require.NoError(t, err)
}

func jobRow(t *testing.T, js *JobStore, jobID string) (state, attempt int32, lastSeq int64) {
	t.Helper()
	require.NoError(t, js.pool.QueryRow(context.Background(),
		`SELECT state, attempt, last_event_sequence FROM jobs WHERE job_id = $1`, jobID).Scan(&state, &attempt, &lastSeq))
	return state, attempt, lastSeq
}

func countEvents(t *testing.T, js *JobStore, jobID string) int {
	t.Helper()
	var n int
	require.NoError(t, js.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM job_events WHERE job_id = $1`, jobID).Scan(&n))
	return n
}

func successResult(jobID string) *jobv1.JobResult {
	return &jobv1.JobResult{JobId: jobID, Success: true}
}

func TestFencing_OldTokenAfterRedelivery(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, oldToken := leasedJob(t, js, fx, "redeliver", 3, 300)

	expireLease(t, js, jobID)
	n, err := js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, newToken := dequeueOne(t, js, fx, "redeliver", 300)
	require.NotEqual(t, oldToken, newToken)

	_, err = js.UpdateJobVisibility(ctx, fx.Worker, oldToken, 60)
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.CompleteJob(ctx, fx.Worker, oldToken, successResult(jobID), 0), jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.ReleaseJob(ctx, fx.Worker, oldToken), jobstore.ErrLeaseLost)
	_, err = js.PublishEvents(ctx, fx.Worker, oldToken, []*jobv1.JobEvent{startEvent(1)})
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	require.Zero(t, countEvents(t, js, jobID))

	// The new token still works.
	_, err = js.UpdateJobVisibility(ctx, fx.Worker, newToken, 60)
	require.NoError(t, err)
}

func TestFencing_SameOrgDifferentWorker(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "wrongworker", 3, 300)

	// Another principal in the same org (the user fixture) must not use the worker's token.
	_, err := js.UpdateJobVisibility(ctx, fx.User, token, 60)
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.CompleteJob(ctx, fx.User, token, successResult(jobID), 0), jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.ReleaseJob(ctx, fx.User, token), jobstore.ErrLeaseLost)
	_, err = js.PublishEvents(ctx, fx.User, token, []*jobv1.JobEvent{startEvent(1)})
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)

	state, _, _ := jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_RUNNING), state)
}

func TestFencing_ExpiredUnreapedLease(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "unreaped", 3, 300)
	expireLease(t, js, jobID)

	_, err := js.UpdateJobVisibility(ctx, fx.Worker, token, 60)
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.CompleteJob(ctx, fx.Worker, token, successResult(jobID), 0), jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.ReleaseJob(ctx, fx.Worker, token), jobstore.ErrLeaseLost)

	state, attempt, _ := jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_RUNNING), state)
	require.Equal(t, int32(1), attempt)
}

func TestFencing_ReleaseUntilExhausted(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "exhaust", 2, 300)

	require.NoError(t, js.ReleaseJob(ctx, fx.Worker, token))
	state, attempt, _ := jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_SCHEDULED), state)
	require.Equal(t, int32(1), attempt)

	_, token = dequeueOne(t, js, fx, "exhaust", 300)
	require.NoError(t, js.ReleaseJob(ctx, fx.Worker, token))

	state, attempt, _ = jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_FAILED), state)
	require.Equal(t, int32(2), attempt)

	var reason string
	require.NoError(t, js.pool.QueryRow(ctx, `SELECT result->>'reason' FROM jobs WHERE job_id = $1`, jobID).Scan(&reason))
	require.Equal(t, "delivery attempts exhausted", reason)
}

func TestFencing_FinalExpiryFails(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, _ := leasedJob(t, js, fx, "finalexpiry", 1, 300)

	n, err := js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Zero(t, n, "live lease must not be reaped")

	expireLease(t, js, jobID)
	n, err = js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	state, attempt, _ := jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_FAILED), state)
	require.Equal(t, int32(1), attempt)
}

func TestFencing_ReaperLoop(t *testing.T) {
	js, fx := setupStore(t)
	jobID, _ := leasedJob(t, js, fx, "loop", 3, 300)
	expireLease(t, js, jobID)

	require.NoError(t, js.Stop())

	js2, err := NewJobStore(js.pool, &JobStoreConfig{
		TokenSigningSecret:  js.cfg.TokenSigningSecret,
		LeaseReaperInterval: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, js2.Start())
	t.Cleanup(func() { _ = js2.Stop() })

	require.Eventually(t, func() bool {
		state, _, _ := jobRow(t, js, jobID)
		return state == int32(jobv1.JobState_JOB_STATE_SCHEDULED)
	}, 5*time.Second, 50*time.Millisecond)
}

func TestFencing_Publish(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T, name string) (*JobStore, orgFixture, string, string) {
		js, fx := setupStore(t)
		jobID, token := leasedJob(t, js, fx, name, 3, 300)
		return js, fx, jobID, token
	}

	t.Run("identical retry is a no-op with the same ack", func(t *testing.T) {
		js, fx, jobID, token := setup(t, "retry")
		events := []*jobv1.JobEvent{startEvent(1), batchEvent(2, 4)}
		first, err := js.PublishEvents(ctx, fx.Worker, token, events)
		require.NoError(t, err)
		require.Equal(t, int64(4), first.AcknowledgedThroughSequence)

		// Retry with a fresh copy of the same content.
		retry := []*jobv1.JobEvent{
			{Attempt: 1, Sequence: 1, Timestamp: events[0].Timestamp, EventType: events[0].EventType},
			{Attempt: 1, Sequence: 2, Timestamp: events[1].Timestamp, EventType: events[1].EventType, EventData: events[1].EventData},
		}
		second, err := js.PublishEvents(ctx, fx.Worker, token, retry)
		require.NoError(t, err)
		require.Equal(t, first, second)
		require.Equal(t, 2, countEvents(t, js, jobID))
		_, _, last := jobRow(t, js, jobID)
		require.Equal(t, int64(4), last)
	})

	t.Run("changed payload conflicts", func(t *testing.T) {
		js, fx, jobID, token := setup(t, "conflict")
		ts := timestamppb.Now()
		_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{
			{Attempt: 1, Sequence: 1, Timestamp: ts, EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
				EventData: &jobv1.JobEvent_Output{Output: &jobv1.OutputEvent{Output: []byte("a")}}},
		})
		require.NoError(t, err)
		_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{
			{Attempt: 1, Sequence: 1, Timestamp: ts, EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
				EventData: &jobv1.JobEvent_Output{Output: &jobv1.OutputEvent{Output: []byte("b")}}},
		})
		require.ErrorIs(t, err, jobstore.ErrConflict)
		require.Equal(t, 1, countEvents(t, js, jobID))
	})

	t.Run("gap is invalid and all-or-nothing", func(t *testing.T) {
		js, fx, jobID, token := setup(t, "gap")
		_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1), startEvent(3)})
		require.ErrorIs(t, err, jobstore.ErrInvalidArgument)
		require.Zero(t, countEvents(t, js, jobID))
		_, _, last := jobRow(t, js, jobID)
		require.Zero(t, last)
	})

	t.Run("overlap is invalid", func(t *testing.T) {
		js, fx, jobID, token := setup(t, "overlap")
		_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{batchEvent(1, 3)})
		require.NoError(t, err)
		_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{batchEvent(2, 4)})
		require.ErrorIs(t, err, jobstore.ErrInvalidArgument)
		require.Equal(t, 1, countEvents(t, js, jobID))
	})

	t.Run("output batch then next event advances the ack", func(t *testing.T) {
		js, fx, _, token := setup(t, "batchadvance")
		res, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{batchEvent(1, 3)})
		require.NoError(t, err)
		require.Equal(t, int64(3), res.AcknowledgedThroughSequence)
		res, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(4)})
		require.NoError(t, err)
		require.Equal(t, int64(4), res.AcknowledgedThroughSequence)
	})

	t.Run("invalid events", func(t *testing.T) {
		js, fx, jobID, token := setup(t, "invalid")
		wrongAttempt := startEvent(1)
		wrongAttempt.Attempt = 2
		noTimestamp := startEvent(1)
		noTimestamp.Timestamp = nil
		zeroSeq := startEvent(0)
		badBatch := batchEvent(1, 3)
		badBatch.GetOutputBatch().Outputs = outputItems(2)
		badStart := batchEvent(1, 3)
		badStart.Sequence = 2

		for name, ev := range map[string]*jobv1.JobEvent{
			"wrong attempt": wrongAttempt, "missing timestamp": noTimestamp, "zero sequence": zeroSeq,
			"output count": badBatch, "batch start mismatch": badStart,
		} {
			_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{ev})
			require.ErrorIs(t, err, jobstore.ErrInvalidArgument, name)
		}
		require.Zero(t, countEvents(t, js, jobID))

		// The matching attempt is accepted.
		ok := startEvent(1)
		ok.Attempt = 1
		_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{ok})
		require.NoError(t, err)
	})
}

func TestFencing_CompleteFinalSequence(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "finalseq", 3, 300)

	_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1), batchEvent(2, 3)})
	require.NoError(t, err)

	for _, wrong := range []int64{0, 2, 4} {
		require.ErrorIs(t, js.CompleteJob(ctx, fx.Worker, token, successResult(jobID), wrong), jobstore.ErrInvalidArgument)
	}
	state, _, _ := jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_RUNNING), state)

	require.NoError(t, js.CompleteJob(ctx, fx.Worker, token, successResult(jobID), 3))
	state, _, _ = jobRow(t, js, jobID)
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_COMPLETED), state)
}

// holdRowLock opens a transaction that holds FOR UPDATE on the job row until release is called.
func holdRowLock(t *testing.T, js *JobStore, jobID string, setSQL string) (release func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := js.pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT 1 FROM jobs WHERE job_id = $1 FOR UPDATE`, jobID)
	require.NoError(t, err)
	if setSQL != "" {
		_, err = tx.Exec(ctx, setSQL, jobID)
		require.NoError(t, err)
	}
	var once sync.Once
	release = func() { once.Do(func() { require.NoError(t, tx.Commit(ctx)) }) }
	t.Cleanup(func() { once.Do(func() { _ = tx.Rollback(ctx) }) })
	return release
}

// A publisher blocked on the row lock past lease expiry must validate against the time
// after the lock is acquired, not the (frozen) transaction start time.
func TestBarrier_PublishWaitsPastExpiry(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, token := leasedJob(t, js, fx, "barrier", 3, 300)

	release := holdRowLock(t, js, jobID,
		`UPDATE jobs SET visibility_until = clock_timestamp() + INTERVAL '1 second' WHERE job_id = $1`)

	errCh := make(chan error, 1)
	go func() {
		_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
		errCh <- err
	}()

	time.Sleep(1500 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("publish returned while the row lock was held: %v", err)
	default:
	}
	release()

	require.ErrorIs(t, <-errCh, jobstore.ErrLeaseLost)
	require.Zero(t, countEvents(t, js, jobID))
}

// ReapExpired skips rows locked by an in-flight operation (SKIP LOCKED) rather than waiting;
// a later sweep reclaims them.
func TestBarrier_ReaperSkipsLockedRow(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	jobID, _ := leasedJob(t, js, fx, "skiplocked", 3, 300)
	expireLease(t, js, jobID)

	release := holdRowLock(t, js, jobID, "")
	n, err := js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Zero(t, n)
	release()

	n, err = js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestBarrier_PublishVersusReapOrdering(t *testing.T) {
	ctx := context.Background()

	t.Run("reap first then publish fails", func(t *testing.T) {
		js, fx := setupStore(t)
		jobID, token := leasedJob(t, js, fx, "reapfirst", 3, 300)
		expireLease(t, js, jobID)
		n, err := js.ReapExpired(ctx, 10)
		require.NoError(t, err)
		require.Equal(t, 1, n)

		_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
		require.ErrorIs(t, err, jobstore.ErrLeaseLost)
		require.Zero(t, countEvents(t, js, jobID))
	})

	t.Run("publish first then reap keeps events", func(t *testing.T) {
		js, fx := setupStore(t)
		jobID, token := leasedJob(t, js, fx, "publishfirst", 3, 300)
		_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
		require.NoError(t, err)

		expireLease(t, js, jobID)
		n, err := js.ReapExpired(ctx, 10)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.Equal(t, 1, countEvents(t, js, jobID))
	})

	t.Run("concurrent publishers and reaper", func(t *testing.T) {
		js, fx := setupStore(t)
		jobID, token := leasedJob(t, js, fx, "concurrent", 3, 300)
		expireLease(t, js, jobID)

		var wg sync.WaitGroup
		pubErr := make(chan error, 1)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
			pubErr <- err
		}()
		go func() {
			defer wg.Done()
			_, _ = js.ReapExpired(ctx, 10)
		}()
		wg.Wait()

		// The lease was already expired, so the publish can never be accepted.
		require.ErrorIs(t, <-pubErr, jobstore.ErrLeaseLost)
		require.Zero(t, countEvents(t, js, jobID))
	})
}
