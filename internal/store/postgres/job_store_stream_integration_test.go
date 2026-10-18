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

const streamWait = 10 * time.Second

// discardStream is a send callback that ignores every response.
func discardStream(*jobstore.StreamResponse) error { return nil }

// streamStores returns the setup store, a second store on the same pool with a fast
// stream poll interval, and the seeded org.
func streamStores(t *testing.T) (writer, streamer *JobStore, fx orgFixture) {
	t.Helper()
	writer, fx = setupStore(t)
	streamer, err := NewJobStore(writer.pool, &JobStoreConfig{
		TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
		StreamPollInterval: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, streamer.Start())
	t.Cleanup(func() { _ = streamer.Stop() })
	return writer, streamer, fx
}

// streamRun runs StreamEvents in a goroutine and records every response.
type streamRun struct {
	mu    sync.Mutex
	resps []*jobstore.StreamResponse
	done  chan error
}

func startStream(t *testing.T, js *JobStore, caller jobstore.Caller, req jobstore.StreamRequest, perSend func()) *streamRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	r := &streamRun{done: make(chan error, 1)}
	go func() {
		r.done <- js.StreamEvents(ctx, caller, req, func(resp *jobstore.StreamResponse) error {
			r.mu.Lock()
			r.resps = append(r.resps, resp)
			r.mu.Unlock()
			if perSend != nil {
				perSend()
			}
			return nil
		})
	}()
	return r
}

func (r *streamRun) responses() []*jobstore.StreamResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*jobstore.StreamResponse(nil), r.resps...)
}

func (r *streamRun) waitCount(t *testing.T, n int) {
	t.Helper()
	require.Eventually(t, func() bool { return len(r.responses()) >= n }, streamWait, 10*time.Millisecond)
}

func (r *streamRun) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(streamWait):
		t.Fatal("stream did not finish")
		return nil
	}
}

// eventSeqs returns the start sequences of the event messages received so far.
func (r *streamRun) eventSeqs() []int64 {
	var seqs []int64
	for _, resp := range r.responses() {
		if resp.Event != nil {
			seqs = append(seqs, resp.Event.Sequence)
		}
	}
	return seqs
}

func seqRange(from, to int64) []int64 {
	var out []int64
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func outputEvent(attempt int32, seq int64) *jobv1.JobEvent {
	return &jobv1.JobEvent{
		Attempt: attempt, Sequence: seq, Timestamp: timestamppb.Now(),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{Output: &jobv1.OutputEvent{Output: []byte("x")}},
	}
}

func batchEventFor(attempt int32, start, end int64) *jobv1.JobEvent {
	e := batchEvent(start, end)
	e.Attempt = attempt
	return e
}

// publishOutputs publishes single-sequence output events from..to in calls of at most 50.
func publishOutputs(t *testing.T, js *JobStore, fx orgFixture, token string, attempt int32, from, to int64) {
	t.Helper()
	for seq := from; seq <= to; {
		var batch []*jobv1.JobEvent
		for ; seq <= to && len(batch) < 50; seq++ {
			batch = append(batch, outputEvent(attempt, seq))
		}
		_, err := js.PublishEvents(context.Background(), fx.Worker, token, batch)
		require.NoError(t, err)
	}
}

func enqueueOnly(t *testing.T, js *JobStore, fx orgFixture, queue string) string {
	t.Helper()
	resp, err := js.EnqueueJob(context.Background(), fx.User, contractReq(queue, queue, "echo"))
	require.NoError(t, err)
	return resp.JobId
}

func reapOne(t *testing.T, js *JobStore, jobID string) {
	t.Helper()
	expireLease(t, js, jobID)
	n, err := js.ReapExpired(context.Background(), 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestStream_SubscribeBeforeDequeue(t *testing.T) {
	ctx := context.Background()
	writer, streamer, fx := streamStores(t)
	jobID := enqueueOnly(t, writer, fx, "before")

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	run.waitCount(t, 1)
	first := run.responses()[0]
	require.Nil(t, first.Event)
	require.Equal(t, int32(1), first.Attempt)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, first.JobState)
	require.False(t, first.AttemptClosed)

	_, token := dequeueOne(t, writer, fx, "before", 300)
	publishOutputs(t, writer, fx, token, 1, 1, 5)
	run.waitCount(t, 6)
	require.Equal(t, seqRange(1, 5), run.eventSeqs())

	publishOutputs(t, writer, fx, token, 1, 6, 8)
	require.NoError(t, writer.CompleteJob(ctx, fx.Worker, token, successResult(jobID), 8))

	require.NoError(t, run.wait(t))
	require.Equal(t, seqRange(1, 8), run.eventSeqs())
	resps := run.responses()
	last := resps[len(resps)-1]
	require.Nil(t, last.Event)
	require.True(t, last.AttemptClosed)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, last.JobState)
	for _, r := range resps[:len(resps)-1] {
		require.False(t, r.AttemptClosed)
	}
}

func TestStream_LatestAttemptAfterRedelivery(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token1 := leasedJob(t, writer, fx, "redeliver", 3, 300)
	publishOutputs(t, writer, fx, token1, 1, 1, 2)

	reapOne(t, writer, jobID)
	_, token2 := dequeueOne(t, writer, fx, "redeliver", 300)
	publishOutputs(t, writer, fx, token2, 2, 1, 3)
	require.NoError(t, writer.CompleteJob(context.Background(), fx.Worker, token2, successResult(jobID), 3))

	latest := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	require.NoError(t, latest.wait(t))
	require.Equal(t, int32(2), latest.responses()[0].Attempt)
	require.Equal(t, seqRange(1, 3), latest.eventSeqs())

	// Historical attempt 1 only returns its own events, then closes.
	hist := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID, Attempt: 1}, nil)
	require.NoError(t, hist.wait(t))
	resps := hist.responses()
	require.Equal(t, seqRange(1, 2), hist.eventSeqs())
	for _, r := range resps {
		require.Equal(t, int32(1), r.Attempt)
		if r.Event != nil {
			require.Equal(t, int32(1), r.Event.Attempt)
		}
	}
	require.True(t, resps[0].AttemptClosed)
	require.True(t, resps[len(resps)-1].AttemptClosed)
}

func TestStream_InvalidAndForeignRequests(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID := enqueueOnly(t, writer, fx, "invalid")
	other := seedOrg(t, writer)
	ctx := context.Background()

	err := streamer.StreamEvents(ctx, fx.User, jobstore.StreamRequest{JobID: jobID, Attempt: 2}, discardStream)
	require.ErrorIs(t, err, jobstore.ErrInvalidArgument)

	err = streamer.StreamEvents(ctx, fx.User, jobstore.StreamRequest{JobID: jobID, Attempt: -1}, discardStream)
	require.ErrorIs(t, err, jobstore.ErrInvalidArgument)

	err = streamer.StreamEvents(ctx, other.User, jobstore.StreamRequest{JobID: jobID}, discardStream)
	require.ErrorIs(t, err, jobstore.ErrJobNotFound)

	err = streamer.StreamEvents(ctx, fx.User, jobstore.StreamRequest{JobID: "not-a-uuid"}, discardStream)
	require.ErrorIs(t, err, jobstore.ErrJobNotFound)
}

func TestStream_FromSequenceInsideBatch(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "batch", 3, 300)
	_, err := writer.PublishEvents(context.Background(), fx.Worker, token, []*jobv1.JobEvent{
		startEvent(1), batchEvent(2, 5), outputEvent(1, 6),
	})
	require.NoError(t, err)
	require.NoError(t, writer.CompleteJob(context.Background(), fx.Worker, token, successResult(jobID), 6))

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID, FromSequence: 4}, nil)
	require.NoError(t, run.wait(t))
	require.Equal(t, []int64{2, 6}, run.eventSeqs())
}

func TestStream_FilterMatchingNothingAdvancesCursor(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "filter", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 250)
	require.NoError(t, writer.CompleteJob(context.Background(), fx.Worker, token, successResult(jobID), 250))

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{
		JobID:       jobID,
		EventFilter: []jobv1.EventType{jobv1.EventType_EVENT_TYPE_PROCESS_START},
	}, nil)
	require.NoError(t, run.wait(t))

	resps := run.responses()
	require.Len(t, resps, 2)
	require.True(t, resps[0].AttemptClosed)
	require.True(t, resps[1].AttemptClosed)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, resps[1].JobState)
}

func TestStream_ManyEventsSlowConsumer(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "slow", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 250)
	require.NoError(t, writer.CompleteJob(context.Background(), fx.Worker, token, successResult(jobID), 250))

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, func() { time.Sleep(time.Millisecond) })
	require.NoError(t, run.wait(t))
	require.Equal(t, seqRange(1, 250), run.eventSeqs())
}

func TestStream_RetryWhileSubscribed(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "retry", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 3)

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID, Attempt: 1}, nil)
	run.waitCount(t, 4)
	require.False(t, run.responses()[0].AttemptClosed)

	reapOne(t, writer, jobID)
	require.NoError(t, run.wait(t))

	resps := run.responses()
	last := resps[len(resps)-1]
	require.True(t, last.AttemptClosed)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, last.JobState)
	require.Equal(t, seqRange(1, 3), run.eventSeqs())
}

func TestStream_CancelledBeforeStart(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID := enqueueOnly(t, writer, fx, "cancelled")

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	run.waitCount(t, 1)
	require.False(t, run.responses()[0].AttemptClosed)

	_, err := writer.pool.Exec(context.Background(), `UPDATE jobs SET state = 5 WHERE job_id = $1`, jobID)
	require.NoError(t, err)

	require.NoError(t, run.wait(t))
	resps := run.responses()
	last := resps[len(resps)-1]
	require.True(t, last.AttemptClosed)
	require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, last.JobState)
	require.Empty(t, run.eventSeqs())
}

func TestStream_PurgedEvents(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "purged", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 5)
	require.NoError(t, writer.CompleteJob(context.Background(), fx.Worker, token, successResult(jobID), 5))
	_, err := writer.pool.Exec(context.Background(), `DELETE FROM job_events WHERE job_id = $1`, jobID)
	require.NoError(t, err)

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	require.NoError(t, run.wait(t))
	resps := run.responses()
	require.Len(t, resps, 2)
	require.True(t, resps[0].AttemptClosed)
	require.True(t, resps[1].AttemptClosed)
}

func TestStream_JobDeletedMidStream(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "deleted", 3, 300)
	publishOutputs(t, writer, fx, token, 1, 1, 2)

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	run.waitCount(t, 3)

	_, err := writer.pool.Exec(context.Background(), `DELETE FROM jobs WHERE job_id = $1`, jobID)
	require.NoError(t, err)

	require.ErrorIs(t, run.wait(t), jobstore.ErrJobNotFound)
}

func TestStream_PublishViaOtherStore(t *testing.T) {
	writer, streamer, fx := streamStores(t)
	jobID, token := leasedJob(t, writer, fx, "twostores", 3, 300)

	run := startStream(t, streamer, fx.User, jobstore.StreamRequest{JobID: jobID}, nil)
	run.waitCount(t, 1)

	publishOutputs(t, writer, fx, token, 1, 1, 120)
	require.NoError(t, writer.CompleteJob(context.Background(), fx.Worker, token, successResult(jobID), 120))

	require.NoError(t, run.wait(t))
	require.Equal(t, seqRange(1, 120), run.eventSeqs())
}
