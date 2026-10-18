package wal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// fakeReceiver is a scripted EventSender modelling the server's commit semantics.
type fakeReceiver struct {
	mu        sync.Mutex
	script    []func(r *fakeReceiver, events []*jobv1.JobEvent) (Ack, error)
	committed []*jobv1.JobEvent // distinct committed events, in order
	calls     [][]int64         // sequences of each call
	attempt   int32
}

func newReceiver() *fakeReceiver { return &fakeReceiver{attempt: 1} }

// commit records the events (idempotently) and returns the correct ack.
func (r *fakeReceiver) commit(events []*jobv1.JobEvent) Ack {
	have := map[int64]bool{}
	for _, e := range r.committed {
		have[e.Sequence] = true
	}
	for _, e := range events {
		if !have[e.Sequence] {
			r.committed = append(r.committed, e)
		}
	}
	return Ack{Attempt: r.attempt, Through: coveredSequence(events[len(events)-1])}
}

func (r *fakeReceiver) Send(_ context.Context, events []*jobv1.JobEvent) (Ack, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seqs := make([]int64, len(events))
	for i, e := range events {
		seqs[i] = e.Sequence
	}
	r.calls = append(r.calls, seqs)
	if len(r.script) > 0 {
		step := r.script[0]
		r.script = r.script[1:]
		return step(r, events)
	}
	return r.commit(events), nil
}

func (r *fakeReceiver) callSizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	sizes := make([]int, len(r.calls))
	for i, c := range r.calls {
		sizes[i] = len(c)
	}
	return sizes
}

func testCfg(t *testing.T) *WALConfig {
	t.Helper()
	return &WALConfig{
		WALDir:            t.TempDir(),
		ArchiveDir:        t.TempDir(),
		FlushInterval:     10 * time.Millisecond,
		FlushPollInterval: 5 * time.Millisecond,
		RetryBackoff:      BackoffConfig{InitialInterval: 5 * time.Millisecond, MaxInterval: 20 * time.Millisecond, Multiplier: 2},
	}
}

func startWAL(t *testing.T, cfg *WALConfig, s EventSender) WAL {
	t.Helper()
	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Stop(context.Background()) })
	require.NoError(t, w.Start(context.Background(), s))
	return w
}

func appendSeqs(t *testing.T, w WAL, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		require.NoError(t, w.Append(context.Background(), &jobv1.JobEvent{Sequence: int64(i)}))
	}
}

func appendOutput(t *testing.T, w WAL, start, end int64, size int) {
	t.Helper()
	require.NoError(t, w.Append(context.Background(), &jobv1.JobEvent{
		Sequence:  start,
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		EventData: &jobv1.JobEvent_OutputBatch{OutputBatch: &jobv1.OutputBatchEvent{
			StartSequence: start,
			EndSequence:   end,
			Outputs:       []*jobv1.OutputItem{{Output: bytes.Repeat([]byte("x"), size)}},
		}},
	}))
}

func flush(t *testing.T, w WAL) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.Flush(ctx)
}

func TestSender_StampsAttempt(t *testing.T) {
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 7)
	require.NoError(t, err)
	defer func() { _ = w.Stop(context.Background()) }()

	r := newReceiver()
	r.attempt = 7
	require.NoError(t, w.Start(context.Background(), r))
	appendSeqs(t, w, 3)
	require.NoError(t, flush(t, w))
	for _, e := range r.committed {
		assert.Equal(t, int32(7), e.Attempt)
	}
	assert.Equal(t, int64(3), w.Acked())
	assert.Equal(t, 0, w.Pending())
}

func TestSender_CommitAndDropReply(t *testing.T) {
	r := newReceiver()
	var firstDrop sync.WaitGroup
	firstDrop.Add(1)
	r.script = []func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error){
		func(r *fakeReceiver, ev []*jobv1.JobEvent) (Ack, error) {
			r.commit(ev) // committed, reply lost
			defer firstDrop.Done()
			return Ack{}, errors.New("connection reset")
		},
	}
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 3)

	firstDrop.Wait()
	// Records must remain pending until a valid ack arrives.
	require.NoError(t, flush(t, w))
	assert.Len(t, r.committed, 3, "retry must not duplicate committed events")
	assert.GreaterOrEqual(t, len(r.callSizes()), 2)
	assert.Equal(t, int64(3), w.Acked())
}

func TestSender_FailBeforeCommitThenSucceed(t *testing.T) {
	r := newReceiver()
	fail := func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) { return Ack{}, errors.New("unavailable") }
	r.script = append(r.script, fail, fail, fail)
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 4)
	require.NoError(t, flush(t, w))
	assert.Len(t, r.committed, 4)
	assert.NoError(t, w.Err())
}

func TestSender_DuplicateAck(t *testing.T) {
	r := newReceiver()
	r.script = append(r.script, func(r *fakeReceiver, ev []*jobv1.JobEvent) (Ack, error) {
		r.commit(ev)
		return Ack{}, errors.New("timeout")
	})
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 2)
	require.NoError(t, flush(t, w))
	// The retry is acknowledged again with the same ack; nothing breaks.
	assert.NoError(t, w.Err())
	assert.Equal(t, int64(2), w.Acked())
}

func TestSender_BadAckIsPermanent(t *testing.T) {
	// Acks are derived from the batch actually sent: the sender may pick up a prefix
	// of the appended records before the rest arrive.
	tests := map[string]func(last int64) Ack{
		"wrong attempt": func(last int64) Ack { return Ack{Attempt: 2, Through: last} },
		"short through": func(last int64) Ack { return Ack{Attempt: 1, Through: last - 1} },
		"long through":  func(last int64) Ack { return Ack{Attempt: 1, Through: last + 1} },
	}
	for name, ack := range tests {
		t.Run(name, func(t *testing.T) {
			r := newReceiver()
			r.script = append(r.script, func(r *fakeReceiver, ev []*jobv1.JobEvent) (Ack, error) {
				r.commit(ev)
				return ack(ev[len(ev)-1].Sequence), nil
			})
			w := startWAL(t, testCfg(t), r)
			appendSeqs(t, w, 3)

			err := flush(t, w)
			require.ErrorIs(t, err, ErrAckMismatch)
			require.ErrorIs(t, err, ErrPermanent)
			assert.Equal(t, 3, w.Pending(), "records must not be marked sent")
			assert.Equal(t, int64(0), w.Acked())
			assert.Len(t, r.callSizes(), 1, "sender must stop")
		})
	}
}

func TestSender_LeaseLostReturnsImmediately(t *testing.T) {
	r := newReceiver()
	r.script = append(r.script, func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) {
		return Ack{}, fmt.Errorf("rpc: %w", ErrLeaseLost)
	})
	cfg := testCfg(t)
	cfg.FlushPollInterval = time.Hour // only the error wake-up can end Flush
	w := startWAL(t, cfg, r)
	appendSeqs(t, w, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	err := w.Flush(ctx)
	require.ErrorIs(t, err, ErrLeaseLost)
	assert.Less(t, time.Since(start), 3*time.Second)
	require.ErrorIs(t, w.Err(), ErrLeaseLost)
	assert.Equal(t, 2, w.Pending())

	// Subsequent flushes return immediately too.
	start = time.Now()
	require.ErrorIs(t, w.Flush(ctx), ErrLeaseLost)
	assert.Less(t, time.Since(start), time.Second)
}

func TestSender_FailedClosedOnLeaseLost(t *testing.T) {
	r := newReceiver()
	r.script = append(r.script, func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) {
		return Ack{}, fmt.Errorf("rpc: %w", ErrLeaseLost)
	})
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 1)
	select {
	case <-w.Failed():
	case <-time.After(5 * time.Second):
		t.Fatal("Failed not closed after lease loss")
	}
	require.ErrorIs(t, w.Err(), ErrLeaseLost)
}

func TestSender_FailedClosedOnPermanent(t *testing.T) {
	r := newReceiver()
	r.script = append(r.script, func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) {
		return Ack{}, fmt.Errorf("bad request: %w", ErrPermanent)
	})
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 1)
	select {
	case <-w.Failed():
	case <-time.After(5 * time.Second):
		t.Fatal("Failed not closed after permanent error")
	}
	require.ErrorIs(t, w.Err(), ErrPermanent)
}

func TestSender_FailedOpenDuringTransientRetries(t *testing.T) {
	r := newReceiver()
	for i := 0; i < 3; i++ {
		r.script = append(r.script, func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) {
			return Ack{}, context.DeadlineExceeded
		})
	}
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 1)
	require.NoError(t, flush(t, w))
	select {
	case <-w.Failed():
		t.Fatal("Failed closed by transient errors")
	default:
	}
	require.NoError(t, w.Err())
}

func TestSender_PermanentIsSticky(t *testing.T) {
	r := newReceiver()
	r.script = append(r.script, func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) {
		return Ack{}, fmt.Errorf("bad request: %w", ErrPermanent)
	})
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 2)
	require.ErrorIs(t, flush(t, w), ErrPermanent)
	time.Sleep(100 * time.Millisecond)
	assert.Len(t, r.callSizes(), 1, "no further sends after a permanent error")
}

func TestSender_TransientRetriedThenSucceeds(t *testing.T) {
	r := newReceiver()
	for i := 0; i < 3; i++ {
		r.script = append(r.script, func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) {
			return Ack{}, context.DeadlineExceeded
		})
	}
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 2)
	require.NoError(t, flush(t, w))
	assert.Len(t, r.callSizes(), 4)
}

func TestSender_SplitsByCount(t *testing.T) {
	r := newReceiver()
	w := startWAL(t, testCfg(t), r)
	appendSeqs(t, w, 120)
	require.NoError(t, flush(t, w))

	// Batches never exceed 50; sequences arrive in order without gaps.
	var seqs []int64
	for _, c := range r.calls {
		assert.LessOrEqual(t, len(c), 50)
		seqs = append(seqs, c...)
	}
	for i, s := range seqs[:120] {
		assert.Equal(t, int64(i+1), s)
	}
	assert.Equal(t, int64(120), w.Acked())
}

func TestSender_SplitsByCountExact(t *testing.T) {
	// Append before Start so the first drain sees the full backlog.
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	defer func() { _ = w.Stop(context.Background()) }()
	appendSeqs(t, w, 120)

	r := newReceiver()
	require.NoError(t, w.Start(context.Background(), r))
	require.NoError(t, flush(t, w))
	assert.Equal(t, []int{50, 50, 20}, r.callSizes())
}

func TestSender_SplitsByBytes(t *testing.T) {
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	defer func() { _ = w.Stop(context.Background()) }()

	// 5 x 300 KiB: three records would be 900 KiB plus overhead, so 2 per batch.
	for i := int64(1); i <= 5; i++ {
		appendOutput(t, w, i, i, 300*1024)
	}
	r := newReceiver()
	require.NoError(t, w.Start(context.Background(), r))
	require.NoError(t, flush(t, w))
	assert.Equal(t, []int{2, 2, 1}, r.callSizes())
	assert.Equal(t, int64(5), w.Acked())
}

func TestSender_OversizeRecordSentAlone(t *testing.T) {
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	defer func() { _ = w.Stop(context.Background()) }()

	appendOutput(t, w, 1, 1, 10)
	appendOutput(t, w, 2, 4, maxBatchBytes+1024) // one record over budget, covers 2..4
	appendOutput(t, w, 5, 5, 10)

	r := newReceiver()
	require.NoError(t, w.Start(context.Background(), r))
	require.NoError(t, flush(t, w))
	assert.Equal(t, []int{1, 1, 1}, r.callSizes())
	assert.Equal(t, int64(5), w.Acked())
	require.Len(t, r.committed[1].GetOutputBatch().GetOutputs(), 1)
	assert.Len(t, r.committed[1].GetOutputBatch().GetOutputs()[0].GetOutput(), maxBatchBytes+1024)
}

func TestSender_AckThroughUsesOutputBatchEnd(t *testing.T) {
	r := newReceiver()
	w := startWAL(t, testCfg(t), r)
	appendOutput(t, w, 1, 10, 10)
	require.NoError(t, flush(t, w))
	assert.Equal(t, int64(10), w.Acked())
}

func TestJitterBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := jitter(time.Second)
		assert.GreaterOrEqual(t, d, 800*time.Millisecond)
		assert.LessOrEqual(t, d, 1200*time.Millisecond)
	}
}

func TestNewWAL_HeaderMismatchRejected(t *testing.T) {
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	require.NoError(t, w.Append(context.Background(), &jobv1.JobEvent{Sequence: 1}))
	require.NoError(t, w.Stop(context.Background()))

	// Move attempt 1's file into attempt 2's path.
	src := filepath.Join(cfg.WALDir, testJob, "1.wal")
	dst := filepath.Join(cfg.WALDir, testJob, "2.wal")
	require.NoError(t, os.Rename(src, dst))

	_, err = NewWAL(cfg, testJob, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "header mismatch")
}

func TestNewWAL_InvalidArgs(t *testing.T) {
	cfg := testCfg(t)
	_, err := NewWAL(cfg, "not-a-uuid", 1)
	require.Error(t, err)
	_, err = NewWAL(cfg, testJob, 0)
	require.Error(t, err)
}

func TestNewWAL_SecondOpenLocked(t *testing.T) {
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)

	_, err = NewWAL(cfg, testJob, 1)
	require.ErrorIs(t, err, ErrWALLocked)

	// A different attempt is independent.
	w2, err := NewWAL(cfg, testJob, 2)
	require.NoError(t, err)
	require.NoError(t, w2.Stop(context.Background()))

	// Stop releases the lock.
	require.NoError(t, w.Stop(context.Background()))
	w3, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	require.NoError(t, w3.Stop(context.Background()))
}

func TestWAL_Discard(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(fmt.Sprintf("keep=%v", keep), func(t *testing.T) {
			cfg := testCfg(t)
			// A sender that blocks proves Discard does not wait on or send more.
			block := make(chan struct{})
			w, err := NewWAL(cfg, testJob, 3)
			require.NoError(t, err)
			require.NoError(t, w.Start(context.Background(), senderFunc(func(ctx context.Context, _ []*jobv1.JobEvent) (Ack, error) {
				select {
				case <-block:
				case <-ctx.Done():
				}
				return Ack{}, ctx.Err()
			})))
			appendSeqs(t, w, 2)
			time.Sleep(50 * time.Millisecond)

			require.NoError(t, w.Discard(keep))
			close(block)

			_, err = os.Stat(filepath.Join(cfg.WALDir, testJob, "3.wal"))
			assert.True(t, os.IsNotExist(err))
			_, err = os.Stat(filepath.Join(cfg.WALDir, testJob))
			assert.True(t, os.IsNotExist(err), "empty job dir removed")
			_, err = os.Stat(filepath.Join(cfg.WALDir, "failed", testJob+"-3.wal"))
			assert.Equal(t, keep, err == nil)

			// Lock released.
			w2, err := NewWAL(cfg, testJob, 3)
			require.NoError(t, err)
			require.NoError(t, w2.Stop(context.Background()))
		})
	}
}

type senderFunc func(ctx context.Context, events []*jobv1.JobEvent) (Ack, error)

func (f senderFunc) Send(ctx context.Context, events []*jobv1.JobEvent) (Ack, error) {
	return f(ctx, events)
}

func TestCleanupStale(t *testing.T) {
	cfg := testCfg(t)
	jobA := "aaaaaaaa-2222-3333-4444-555555555555"
	jobB := "bbbbbbbb-2222-3333-4444-555555555555"

	// Locked file held by a "live" WAL.
	live, err := NewWAL(cfg, jobA, 1)
	require.NoError(t, err)
	defer func() { _ = live.Stop(context.Background()) }()

	// Stale file with pending records (crash leftover): create then close.
	stale, err := NewWAL(cfg, jobB, 2)
	require.NoError(t, err)
	appendSeqs(t, stale, 3)
	require.NoError(t, stale.Stop(context.Background()))

	// Legacy flat files.
	require.NoError(t, os.WriteFile(filepath.Join(cfg.WALDir, jobB+".wal"), []byte("legacy"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.WALDir, jobB+"-3.wal"), []byte("legacy"), 0o644))

	report, err := CleanupStale(cfg, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, report.LegacyDeleted)
	assert.Equal(t, 1, report.Deleted)
	assert.Equal(t, 1, report.SkippedLocked)
	assert.Zero(t, report.Moved)

	assert.FileExists(t, filepath.Join(cfg.WALDir, jobA, "1.wal"))
	assert.NoFileExists(t, filepath.Join(cfg.WALDir, jobB, "2.wal"))
	assert.NoDirExists(t, filepath.Join(cfg.WALDir, jobB), "empty job dir removed")
	assert.NoFileExists(t, filepath.Join(cfg.WALDir, jobB+".wal"))
	assert.NoFileExists(t, filepath.Join(cfg.WALDir, jobB+"-3.wal"))
}

func TestCleanupStale_KeepFailed(t *testing.T) {
	cfg := testCfg(t)
	job := "bbbbbbbb-2222-3333-4444-555555555555"

	stale, err := NewWAL(cfg, job, 2)
	require.NoError(t, err)
	appendSeqs(t, stale, 2)
	require.NoError(t, stale.Stop(context.Background()))

	// An old failed file that must be pruned.
	failedDir := filepath.Join(cfg.WALDir, "failed")
	require.NoError(t, os.MkdirAll(failedDir, 0o755))
	old := filepath.Join(failedDir, "old-1.wal")
	require.NoError(t, os.WriteFile(old, []byte("x"), 0o644))
	past := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(old, past, past))

	report, err := CleanupStale(cfg, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Moved)
	assert.Equal(t, 1, report.PrunedFailed)
	assert.FileExists(t, filepath.Join(failedDir, job+"-2.wal"))
	assert.NoFileExists(t, old)
	assert.NoFileExists(t, filepath.Join(cfg.WALDir, job, "2.wal"))

	// keepFailed == 0 empties failed/.
	report, err = CleanupStale(cfg, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, report.PrunedFailed)
	assert.NoFileExists(t, filepath.Join(failedDir, job+"-2.wal"))
}

func TestCleanupStale_MissingDir(t *testing.T) {
	report, err := CleanupStale(&WALConfig{WALDir: filepath.Join(t.TempDir(), "nope")}, 0)
	require.NoError(t, err)
	assert.Equal(t, CleanupReport{}, report)
}

func TestWAL_ArchiveIncludesAttempt(t *testing.T) {
	cfg := testCfg(t)
	w, err := NewWAL(cfg, testJob, 4)
	require.NoError(t, err)
	appendSeqs(t, w, 2)
	require.NoError(t, w.Stop(context.Background()))
	require.NoError(t, w.Archive(context.Background(), ""))
	assert.FileExists(t, filepath.Join(cfg.ArchiveDir, testJob+"-4.wal.zst"))
	assert.NoDirExists(t, filepath.Join(cfg.WALDir, testJob))
}
