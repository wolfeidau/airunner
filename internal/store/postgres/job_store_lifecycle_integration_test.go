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

// enqueueAndDequeue creates one job and returns its ID and task token.
func enqueueAndDequeue(t *testing.T, js *JobStore, fx orgFixture, queue string) (string, string) {
	t.Helper()
	ctx := context.Background()

	resp, err := js.EnqueueJob(ctx, fx.User, &jobv1.EnqueueJobRequest{
		RequestId: "lifecycle-" + queue,
		Queue:     queue,
		JobParams: &jobv1.JobParams{Repository: "https://github.com/test/repo", Command: "echo"},
	})
	require.NoError(t, err)

	jobs, err := js.DequeueJobs(ctx, fx.Worker, queue, 1, 300)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	return resp.JobId, jobs[0].TaskToken
}

func TestLifecycle_StartIdempotent(t *testing.T) {
	js, _ := setupStore(t)

	require.NoError(t, js.Start())
	require.NoError(t, js.Start())
	require.NoError(t, js.Stop())
}

func TestLifecycle_StopTwice(t *testing.T) {
	js, _ := setupStore(t)

	require.NoError(t, js.Stop())
	require.NoError(t, js.Stop())
}

func TestLifecycle_StopWithoutStart(t *testing.T) {
	js, _ := setupStore(t)
	require.NoError(t, js.Stop())

	fresh, err := NewJobStore(js.pool, &JobStoreConfig{TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long")})
	require.NoError(t, err)
	require.NoError(t, fresh.Stop())
	require.Error(t, fresh.Start())
}

func TestLifecycle_StartAfterStop(t *testing.T) {
	js, _ := setupStore(t)

	require.NoError(t, js.Stop())
	require.Error(t, js.Start())
}

func TestLifecycle_StreamEventsAfterStop(t *testing.T) {
	js, fx := setupStore(t)
	jobID, _ := enqueueAndDequeue(t, js, fx, "after-stop")

	require.NoError(t, js.Stop())

	err := js.StreamEvents(context.Background(), fx.User, jobstore.StreamRequest{JobID: jobID}, discardStream)
	require.Error(t, err)
}

func TestLifecycle_StopReleasesBlockedStream(t *testing.T) {
	js, fx := setupStore(t)
	jobID, _ := enqueueAndDequeue(t, js, fx, "release")

	// Context is never cancelled: only Stop can release the consumer.
	started := make(chan struct{})
	var once sync.Once
	done := make(chan error, 1)
	go func() {
		done <- js.StreamEvents(context.Background(), fx.User, jobstore.StreamRequest{JobID: jobID},
			func(*jobstore.StreamResponse) error {
				once.Do(func() { close(started) })
				return nil
			})
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not start")
	}

	start := time.Now()
	require.NoError(t, js.Stop())
	require.Less(t, time.Since(start), 2*time.Second)

	select {
	case err := <-done:
		require.ErrorIs(t, err, jobstore.ErrUnavailable)
	case <-time.After(2 * time.Second):
		t.Fatal("stream not released after Stop")
	}
}

func TestLifecycle_PoolUsableAfterStop(t *testing.T) {
	js, _ := setupStore(t)

	require.NoError(t, js.Stop())

	ctx := context.Background()
	require.NoError(t, js.pool.Ping(ctx))
	var n int
	require.NoError(t, js.pool.QueryRow(ctx, "SELECT 1").Scan(&n))
	require.Equal(t, 1, n)
}

func TestLifecycle_ConcurrentPublishStreamAndStop(t *testing.T) {
	js, fx := setupStore(t)
	jobID, token := enqueueAndDequeue(t, js, fx, "race")

	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)

	var wg sync.WaitGroup

	// Publisher: fans out to whatever streams are registered.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for seq := int64(1); seq <= 300 && time.Now().Before(deadline); seq++ {
			_, _ = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{{
				Attempt:   1,
				Sequence:  seq,
				Timestamp: timestamppb.Now(),
				EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
				EventData: &jobv1.JobEvent_Output{Output: &jobv1.OutputEvent{Output: []byte("x")}},
			}})
		}
	}()

	// Streams opened and cancelled in a loop.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50 && time.Now().Before(deadline); i++ {
				sctx, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
				_ = js.StreamEvents(sctx, fx.User, jobstore.StreamRequest{JobID: jobID}, discardStream)
				cancel()
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	require.NoError(t, js.Stop())
	wg.Wait()
}
