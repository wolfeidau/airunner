//go:build integration

package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	jobstore "github.com/wolfeidau/airunner/internal/store"
)

const (
	stateScheduledInt = 1
	stateRunningInt   = 2
	stateCompletedInt = 3
	stateFailedInt    = 4
	stateCancelledInt = 5
)

// seedJob enqueues a job, forces its state and age, and inserts n events for attempt 1.
func seedJob(t *testing.T, js *JobStore, fx orgFixture, name string, state int, age time.Duration, n int) string {
	t.Helper()
	ctx := context.Background()
	jobID := enqueueOnly(t, js, fx, name)
	if state == stateRunningInt {
		dequeueOne(t, js, fx, name, 300) // a real lease satisfies jobs_lease_consistency
	}
	_, err := js.pool.Exec(ctx, `UPDATE jobs SET state = $2, updated_at = clock_timestamp() - $3::interval WHERE job_id = $1`,
		jobID, state, age.String())
	require.NoError(t, err)
	if n > 0 {
		_, err = js.pool.Exec(ctx, `
			INSERT INTO job_events (job_id, attempt, sequence, end_sequence, timestamp, event_type, event_payload)
			SELECT $1, 1, g, g, now(), 1, '\x'::bytea FROM generate_series(1, $2::int) g`, jobID, n)
		require.NoError(t, err)
	}
	return jobID
}

func jobExists(t *testing.T, js *JobStore, jobID string) bool {
	t.Helper()
	var n int
	require.NoError(t, js.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM jobs WHERE job_id = $1`, jobID).Scan(&n))
	return n == 1
}

func cutoff(ago time.Duration) time.Time { return time.Now().Add(-ago) }

func TestRetention_PurgeEventsOnlyOldTerminal(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	old := []string{
		seedJob(t, js, fx, "o-completed", stateCompletedInt, 48*time.Hour, 3),
		seedJob(t, js, fx, "o-failed", stateFailedInt, 48*time.Hour, 3),
		seedJob(t, js, fx, "o-cancelled", stateCancelledInt, 48*time.Hour, 3),
	}
	recent := seedJob(t, js, fx, "recent", stateCompletedInt, time.Minute, 3)
	scheduled := seedJob(t, js, fx, "o-scheduled", stateScheduledInt, 48*time.Hour, 3)
	running := seedJob(t, js, fx, "o-running", stateRunningInt, 48*time.Hour, 3)

	n, err := js.PurgeEvents(ctx, cutoff(24*time.Hour), 1000)
	require.NoError(t, err)
	require.Equal(t, 9, n)

	for _, id := range old {
		require.Zero(t, countEvents(t, js, id))
		require.True(t, jobExists(t, js, id))
	}
	for _, id := range []string{recent, scheduled, running} {
		require.Equal(t, 3, countEvents(t, js, id))
	}
}

func TestRetention_PurgeEventsBatchLimit(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	// 2500 events across three old terminal jobs.
	seedJob(t, js, fx, "e1", stateCompletedInt, 48*time.Hour, 1000)
	seedJob(t, js, fx, "e2", stateFailedInt, 48*time.Hour, 1000)
	seedJob(t, js, fx, "e3", stateCancelledInt, 48*time.Hour, 500)

	for _, want := range []int{1000, 1000, 500, 0} {
		n, err := js.PurgeEvents(ctx, cutoff(24*time.Hour), 1000)
		require.NoError(t, err)
		require.Equal(t, want, n)
	}
}

func TestRetention_PurgeJobs(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	withEvents := seedJob(t, js, fx, "with-events", stateCompletedInt, 48*time.Hour, 2)
	recent := seedJob(t, js, fx, "recent", stateCompletedInt, time.Minute, 0)
	scheduled := seedJob(t, js, fx, "sched", stateScheduledInt, 48*time.Hour, 0)
	running := seedJob(t, js, fx, "run", stateRunningInt, 48*time.Hour, 0)

	n, err := js.PurgeJobs(ctx, cutoff(24*time.Hour), 1000)
	require.NoError(t, err)
	require.Zero(t, n)
	require.True(t, jobExists(t, js, withEvents))

	_, err = js.PurgeEvents(ctx, cutoff(24*time.Hour), 1000)
	require.NoError(t, err)

	n, err = js.PurgeJobs(ctx, cutoff(24*time.Hour), 1000)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.False(t, jobExists(t, js, withEvents))
	for _, id := range []string{recent, scheduled, running} {
		require.True(t, jobExists(t, js, id))
	}
}

// retentionStore builds a second store on the same pool with explicit retention config.
func retentionStore(t *testing.T, js *JobStore, cfg JobStoreConfig) *JobStore {
	t.Helper()
	cfg.TokenSigningSecret = []byte("test-secret-key-min-32-bytes-long")
	s, err := NewJobStore(js.pool, &cfg)
	require.NoError(t, err)
	return s
}

func TestRetention_EventRetentionZeroKeepsEventsWithJob(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	rs := retentionStore(t, js, JobStoreConfig{JobRetention: 24 * time.Hour})
	require.Zero(t, rs.cfg.EventRetention)

	young := seedJob(t, js, fx, "young", stateCompletedInt, 2*time.Hour, 3) // older than 0, younger than job cutoff
	aged := seedJob(t, js, fx, "aged", stateCompletedInt, 48*time.Hour, 3)  // past job cutoff

	rs.retentionTick(ctx)
	require.Equal(t, 3, countEvents(t, js, young))
	require.True(t, jobExists(t, js, young))

	// Events are purged first, then jobs in the same tick (one batch each), so one tick suffices
	// for small sets.
	require.False(t, jobExists(t, js, aged))
	require.Zero(t, countEvents(t, js, aged))
}

func TestRetention_EventRetentionShorterThanJob(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	rs := retentionStore(t, js, JobStoreConfig{JobRetention: 72 * time.Hour, EventRetention: 24 * time.Hour})

	id := seedJob(t, js, fx, "mid", stateCompletedInt, 36*time.Hour, 3)
	rs.retentionTick(ctx)
	require.Zero(t, countEvents(t, js, id))
	require.True(t, jobExists(t, js, id))
}

func TestRetention_ConcurrentPurgeExact(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	other := retentionStore(t, js, JobStoreConfig{})

	const jobs, perJob = 40, 50
	for i := range jobs {
		seedJob(t, js, fx, "c"+string(rune('a'+i/26))+string(rune('a'+i%26)), stateCompletedInt+i%3, 48*time.Hour, perJob)
	}

	var events, deleted atomic.Int64
	var wg sync.WaitGroup
	for _, s := range []*JobStore{js, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := s.PurgeEvents(ctx, cutoff(24*time.Hour), 77)
				if err != nil {
					t.Error(err)
					return
				}
				events.Add(int64(n))
				if n == 0 {
					// SKIP LOCKED may skip rows held by the peer; confirm nothing remains.
					var left int
					_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM job_events`).Scan(&left)
					if left == 0 {
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, jobs*perJob, events.Load())

	for _, s := range []*JobStore{js, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := s.PurgeJobs(ctx, cutoff(24*time.Hour), 3)
				if err != nil {
					t.Error(err)
					return
				}
				deleted.Add(int64(n))
				if n == 0 {
					var left int
					_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM jobs`).Scan(&left)
					if left == 0 {
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, jobs, deleted.Load())
}

func TestRetention_RequestIDReusableAfterDelete(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	req := contractReq("reuse", "q", "echo")
	first, err := js.EnqueueJob(ctx, fx.User, req)
	require.NoError(t, err)
	_, err = js.pool.Exec(ctx, `UPDATE jobs SET state = 3, updated_at = now() - INTERVAL '48 hours' WHERE job_id = $1`, first.JobId)
	require.NoError(t, err)

	n, err := js.PurgeJobs(ctx, cutoff(24*time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	second, err := js.EnqueueJob(ctx, fx.User, req)
	require.NoError(t, err)
	require.NotEqual(t, first.JobId, second.JobId)
}

func TestRetention_StreamAfterEventsPurged(t *testing.T) {
	ctx := context.Background()
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "purged", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 5)
	require.NoError(t, writer.CompleteJob(ctx, fx.Worker, token, successResult(jobID), 5))

	_, err := writer.pool.Exec(ctx, `UPDATE jobs SET updated_at = now() - INTERVAL '48 hours' WHERE job_id = $1`, jobID)
	require.NoError(t, err)
	n, err := writer.PurgeEvents(ctx, cutoff(24*time.Hour), 1000)
	require.NoError(t, err)
	require.Equal(t, 5, n)

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	require.NoError(t, run.wait(t))
	resps := run.responses()
	require.NotEmpty(t, resps)
	require.Empty(t, run.eventSeqs())
	require.Nil(t, resps[0].Event)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, resps[0].JobState)
	last := resps[len(resps)-1]
	require.Nil(t, last.Event)
	require.True(t, last.AttemptClosed)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, last.JobState)
}

func TestRetention_LoopPurgesAndStopsPromptly(t *testing.T) {
	js, fx := setupStore(t)
	id := seedJob(t, js, fx, "loop", stateCompletedInt, time.Hour, 3)

	rs := retentionStore(t, js, JobStoreConfig{JobRetention: time.Minute, RetentionInterval: 50 * time.Millisecond})
	require.NoError(t, rs.Start())

	require.Eventually(t, func() bool { return !jobExists(t, js, id) }, 10*time.Second, 20*time.Millisecond)

	start := time.Now()
	require.NoError(t, rs.Stop())
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestRetention_SweepRetentionUnstarted(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	id := seedJob(t, js, fx, "sweep", stateCompletedInt, time.Hour, 3)
	recent := seedJob(t, js, fx, "sweep-recent", stateCompletedInt, time.Second, 3)

	rs := retentionStore(t, js, JobStoreConfig{JobRetention: time.Minute, DisableRetentionLoop: true})

	report, err := rs.SweepRetention(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, RetentionReport{EventsDeleted: 3, JobsDeleted: 1, Complete: true}, report)
	require.False(t, jobExists(t, js, id))
	require.True(t, jobExists(t, js, recent))
	require.Equal(t, 3, countEvents(t, js, recent))
}

func TestRetention_SweepRetentionBounded(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	id := seedJob(t, js, fx, "bounded", stateCompletedInt, time.Hour, 2500)

	rs := retentionStore(t, js, JobStoreConfig{JobRetention: time.Minute, DisableRetentionLoop: true})

	report, err := rs.SweepRetention(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, 1000, report.EventsDeleted)
	require.Zero(t, report.JobsDeleted)
	require.False(t, report.Complete)
	require.True(t, jobExists(t, js, id))

	report, err = rs.SweepRetention(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, RetentionReport{EventsDeleted: 1500, JobsDeleted: 1, Complete: true}, report)
	require.False(t, jobExists(t, js, id))
}

func TestRetention_DisableRetentionLoop(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	id := seedJob(t, js, fx, "disabled", stateCompletedInt, time.Hour, 3)

	rs := retentionStore(t, js, JobStoreConfig{JobRetention: time.Minute, RetentionInterval: 10 * time.Millisecond, DisableRetentionLoop: true})
	require.NoError(t, rs.Start())
	t.Cleanup(func() { _ = rs.Stop() })

	time.Sleep(300 * time.Millisecond)
	require.True(t, jobExists(t, js, id))
	require.Equal(t, 3, countEvents(t, js, id))

	report, err := rs.SweepRetention(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, 1, report.JobsDeleted)
}
