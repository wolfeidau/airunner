package worker

import (
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
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line3\n"), 0))

	require.Empty(t, publishedEvents, "Should not publish until batch is full")

	// Add 2 more to reach max batch size
	require.NoError(t, batcher.AddOutput([]byte("line4\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line5\n"), 0))

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
		require.NoError(t, batcher.AddOutput(largeOutput, 0))
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
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), 0))
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
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), 0))
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
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line3\n"), 0))

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
		require.NoError(t, batcher.AddOutput([]byte("line\n"), 0))
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
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), 0))
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), 0))

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
	require.NoError(t, batcher.AddOutput([]byte("line1\n"), 0))
	require.NoError(t, batcher.AddOutput([]byte("line2\n"), 0))

	// Stop should flush remaining events
	require.NoError(t, batcher.Stop())

	require.Len(t, publishedEvents, 1)
	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 2)

	// After stop, AddOutput should fail
	err := batcher.AddOutput([]byte("line3\n"), 0)
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
				if err := batcher.AddOutput(output, 0); err != nil {
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
