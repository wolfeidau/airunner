package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestEventBatcherAddOutput(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10, // Long interval so timer doesn't fire
				MaxBatchSize:           5,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add 3 outputs - should not flush yet
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line3\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	require.Empty(t, publishedEvents, "Should not publish until batch is full")

	// Add 2 more to reach max batch size
	require.NoError(t, batcher.AddOutput([]byte("line4\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line5\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	require.Len(t, publishedEvents, 1, "Should publish batch when max size reached")

	// Verify batch event structure
	event := publishedEvents[0]
	require.Equal(t, jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH, event.EventType)
	batch := event.GetOutputBatch()
	require.NotNil(t, batch)
	require.Equal(t, int64(1), batch.StartSequence)
	require.Equal(t, int64(5), batch.EndSequence)
	require.Len(t, batch.Outputs, 5)

	// Verify sequence assignment
	require.Equal(t, int64(1), event.Sequence)

	// Verify items are preserved
	require.Equal(t, []byte("line1\n"), batch.Outputs[0].Output)
	require.Equal(t, []byte("line5\n"), batch.Outputs[4].Output)

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherMaxBytes(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	// Very small max bytes to trigger flush quickly
	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          100, // 100 bytes max
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add outputs until we exceed max bytes
	largeOutput := make([]byte, 40) // 40 bytes per item
	for i := 0; i < 3; i++ {
		require.NoError(t, batcher.AddOutput(largeOutput, jobv1.StreamType_STREAM_TYPE_STDOUT))
	}

	// Third output should trigger flush
	require.NotEmpty(t, publishedEvents, "Should flush when max bytes exceeded")

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherTimer(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   1, // 1 second flush interval
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add one output
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.Empty(t, publishedEvents, "Should not publish immediately")

	// Wait for timer to fire
	time.Sleep(1500 * time.Millisecond)

	require.Len(t, publishedEvents, 1, "Should publish after timer fires")

	event := publishedEvents[0]
	batch := event.GetOutputBatch()
	require.Len(t, batch.Outputs, 1)

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherNonOutputEvent(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           50,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add some outputs
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.Empty(t, publishedEvents)

	// Add a non-output event (heartbeat)
	heartbeatEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_HEARTBEAT,
		EventData: &jobv1.JobEvent_Heartbeat{
			Heartbeat: &jobv1.HeartbeatEvent{
				ProcessAlive: true,
			},
		},
	}

	require.NoError(t, batcher.AddEvent(heartbeatEvent))

	// Should have published: 1 batch + 1 heartbeat
	require.Len(t, publishedEvents, 2)

	// First should be batch
	require.Equal(t, jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH, publishedEvents[0].EventType)

	// Second should be heartbeat with correct sequence
	require.Equal(t, jobv1.EventType_EVENT_TYPE_HEARTBEAT, publishedEvents[1].EventType)
	require.Equal(t, int64(3), publishedEvents[1].Sequence, "Heartbeat sequence should be 3 (after 2 outputs)")

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherExplicitFlush(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add 3 outputs
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line3\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	require.Empty(t, publishedEvents)

	// Explicit flush
	require.NoError(t, batcher.Flush())

	require.Len(t, publishedEvents, 1)
	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 3)
	require.Equal(t, int64(1), batch.StartSequence)
	require.Equal(t, int64(3), batch.EndSequence)

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherSequenceMonotonicity(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           3,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add multiple batches
	for i := 0; i < 10; i++ {
		require.NoError(t, batcher.AddOutput([]byte("line\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	}

	// Should have 3 batches (3+3+3 = 9, plus 1 in buffer)
	require.Len(t, publishedEvents, 3)

	// Check sequence numbering
	// Batch 1: sequences 1-3
	batch1 := publishedEvents[0].GetOutputBatch()
	require.Equal(t, int64(1), batch1.StartSequence)
	require.Equal(t, int64(3), batch1.EndSequence)

	// Batch 2: sequences 4-6
	batch2 := publishedEvents[1].GetOutputBatch()
	require.Equal(t, int64(4), batch2.StartSequence)
	require.Equal(t, int64(6), batch2.EndSequence)

	// Batch 3: sequences 7-9
	batch3 := publishedEvents[2].GetOutputBatch()
	require.Equal(t, int64(7), batch3.StartSequence)
	require.Equal(t, int64(9), batch3.EndSequence)

	// Final flush should get sequence 10
	require.NoError(t, batcher.Flush())
	require.Len(t, publishedEvents, 4)
	batch4 := publishedEvents[3].GetOutputBatch()
	require.Equal(t, int64(10), batch4.StartSequence)
	require.Equal(t, int64(10), batch4.EndSequence)

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherTimestampDeltas(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add output, wait, add another
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	require.NoError(t, batcher.Flush())

	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 2)

	// First item should have delta ~0
	require.InDelta(t, 0, batch.Outputs[0].TimestampDeltaMs, 10, "First item should have small delta")

	// Second item should have delta ~100ms
	require.InDelta(t, 100, batch.Outputs[1].TimestampDeltaMs, 20, "Second item should have ~100ms delta")

	require.NoError(t, batcher.Stop())
}

func TestEventBatcherStop(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add outputs
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Stop should flush remaining events
	require.NoError(t, batcher.Stop())

	require.Len(t, publishedEvents, 1)
	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 2)

	// After stop, AddOutput should fail
	err := batcher.AddOutput([]byte("line3\n"), jobv1.StreamType_STREAM_TYPE_STDOUT)
	require.Error(t, err)
}

func TestEventBatcherConcurrentOperations(t *testing.T) {
	var publishCount int64
	publishedEvents := make([]*jobv1.JobEvent, 0)
	mu := &sync.Mutex{}

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   1,
				MaxBatchSize:           50,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			atomic.AddInt64(&publishCount, 1)
			mu.Lock()
			publishedEvents = append(publishedEvents, event)
			mu.Unlock()
			return nil
		},
	)

	// Simulate concurrent output from multiple goroutines
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func(workerID int) {
			for j := 0; j < 20; j++ {
				output := []byte("line\n")
				if err := batcher.AddOutput(output, jobv1.StreamType_STREAM_TYPE_STDOUT); err != nil {
					t.Errorf("worker %d: failed to add output: %v", workerID, err)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all workers to finish
	for i := 0; i < 3; i++ {
		<-done
	}

	// Stop and collect remaining
	require.NoError(t, batcher.Stop())

	// Should have published at least 1 event (multiple possible with timer)
	mu.Lock()
	eventCount := len(publishedEvents)
	mu.Unlock()
	require.Positive(t, eventCount)

	// Total items across all batches should be 60 (3 workers * 20 items)
	totalItems := 0
	for _, event := range publishedEvents {
		batch := event.GetOutputBatch()
		totalItems += len(batch.Outputs)
	}
	require.Equal(t, 60, totalItems)
}

// TestEventBatcherDefensiveCopy verifies that defensive copying prevents external mutation
func TestEventBatcherDefensiveCopy(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Create a mutable buffer
	output := []byte("original")
	require.NoError(t, batcher.AddOutput(output, jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Mutate the original buffer
	output[0] = 'X'

	// Flush and verify the buffered data was not mutated
	require.NoError(t, batcher.Flush())

	batch := publishedEvents[0].GetOutputBatch()
	require.Equal(t, []byte("original"), batch.Outputs[0].Output, "Defensive copy should prevent external mutation")

	require.NoError(t, batcher.Stop())
}

// TestEventBatcherConcurrentStop verifies that concurrent Stop() calls don't panic
func TestEventBatcherConcurrentStop(t *testing.T) {
	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			return nil
		},
	)

	// Add some data
	require.NoError(t, batcher.AddOutput([]byte("test\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Call Stop() concurrently from multiple goroutines
	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_ = batcher.Stop()
			done <- true
		}()
	}

	// Wait for all goroutines to finish
	for i := 0; i < 5; i++ {
		<-done
	}

	// If we got here without panic, test passed
	// Additional Stop() calls should be no-op
	require.NoError(t, batcher.Stop())
}

// TestEventBatcherErrorPropagation verifies error propagation from onFlush callback
func TestEventBatcherErrorPropagation(t *testing.T) {
	expectedErr := errors.New("publish failed")

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           2,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			return expectedErr
		},
	)

	// Add outputs to trigger flush
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	err := batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT) // This should trigger flush and return error

	require.Error(t, err, "Should propagate error from onFlush callback")
	require.ErrorIs(t, err, expectedErr, "Should preserve original error")

	_ = batcher.Stop()
}

// TestEventBatcherTimerCancelledOnShutdown verifies timer is properly cancelled during shutdown
func TestEventBatcherTimerCancelledOnShutdown(t *testing.T) {
	publishCount := int64(0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   1, // Short interval
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			atomic.AddInt64(&publishCount, 1)
			return nil
		},
	)

	// Add output to start timer
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Stop immediately (before timer fires)
	require.NoError(t, batcher.Stop())

	// Wait longer than flush interval
	time.Sleep(1500 * time.Millisecond)

	// Should have published exactly once (during Stop), not from timer
	count := atomic.LoadInt64(&publishCount)
	require.Equal(t, int64(1), count, "Timer should not fire after Stop()")
}

// TestEventBatcherContextCancellation verifies context cancellation stops operations
func TestEventBatcherContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	batcher := NewEventBatcherWithContext(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           2,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(ctx context.Context, event *jobv1.JobEvent) error {
			// Simulate slow publish that respects context
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				return nil
			}
		},
	)

	// Add first output
	require.NoError(t, batcher.AddOutputContext(ctx, []byte("line1\n"), 0))

	// Cancel context
	cancel()

	// Try to flush with cancelled context - should fail
	err := batcher.FlushContext(ctx)
	require.Error(t, err, "Flush should fail with cancelled context")
	require.ErrorIs(t, err, context.Canceled)

	_ = batcher.Stop()
}

// TestEventBatcherZeroLengthOutput verifies handling of zero-length output
func TestEventBatcherZeroLengthOutput(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add zero-length output
	require.NoError(t, batcher.AddOutput([]byte{}, jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Add normal output
	require.NoError(t, batcher.AddOutput([]byte("data"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	require.NoError(t, batcher.Flush())

	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 2)
	require.Empty(t, batch.Outputs[0].Output, "Should handle zero-length output")
	require.Equal(t, []byte("data"), batch.Outputs[1].Output)

	require.NoError(t, batcher.Stop())
}

// TestEventBatcherTimerFlushRace verifies race between timer fire and manual flush
func TestEventBatcherTimerFlushRace(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)
	mu := &sync.Mutex{}

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   1, // Short interval to increase race likelihood
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			mu.Lock()
			publishedEvents = append(publishedEvents, event)
			mu.Unlock()
			return nil
		},
	)

	// Add output to start timer
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Immediately flush manually (racing with timer)
	require.NoError(t, batcher.Flush())

	// Wait for timer to potentially fire
	time.Sleep(1500 * time.Millisecond)

	// Should have published exactly once (duplicate flush should be no-op)
	mu.Lock()
	count := len(publishedEvents)
	mu.Unlock()
	require.Equal(t, 1, count, "Should not double-flush on timer race")

	require.NoError(t, batcher.Stop())
}

// TestEventBatcherMaxTimestampDelta verifies handling of maximum timestamp delta edge case
func TestEventBatcherMaxTimestampDelta(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add first output
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	// Add second output (timestamp delta will be small, but we're testing the delta calculation)
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))

	require.NoError(t, batcher.Flush())

	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 2)

	// Verify timestamp delta is reasonable
	delta := batch.Outputs[1].TimestampDeltaMs
	require.GreaterOrEqual(t, delta, int32(0), "Delta should be non-negative")
	require.Less(t, delta, int32(1000), "Delta should be less than 1 second")

	require.NoError(t, batcher.Stop())
}

// TestEventBatcherStopFlushesBeforeReturning verifies Stop() flushes all pending data
func TestEventBatcherStopFlushesBeforeReturning(t *testing.T) {
	publishedEvents := make([]*jobv1.JobEvent, 0)

	batcher := NewEventBatcher(
		&jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   10,
				MaxBatchSize:           100,
				MaxBatchBytes:          1000000,
				PlaybackIntervalMillis: 50,
			},
		},
		func(event *jobv1.JobEvent) error {
			publishedEvents = append(publishedEvents, event)
			return nil
		},
	)

	// Add multiple outputs
	for i := 0; i < 10; i++ {
		require.NoError(t, batcher.AddOutput([]byte("line\n"), jobv1.StreamType_STREAM_TYPE_STDOUT))
	}

	require.Empty(t, publishedEvents, "Should not publish before Stop()")

	// Stop should flush all pending data
	require.NoError(t, batcher.Stop())

	require.Len(t, publishedEvents, 1, "Stop() should flush pending data")
	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 10, "All outputs should be flushed")
}
