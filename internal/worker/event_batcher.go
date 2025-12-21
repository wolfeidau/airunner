package worker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventBatcher buffers output events and flushes them into OutputBatchEvent messages
// based on timers and size/byte thresholds.
//
// Thread Safety:
// All public methods are safe for concurrent use. The batcher uses internal locking
// to ensure atomic operations and ordering guarantees.
//
// Sequence Numbers:
// Sequence numbers are monotonically increasing starting from 1. Each OutputItem
// consumes one sequence number. Batch events use the sequence number of their first item.
//
// Flush Callback:
// The onFlush callback must be non-blocking and reasonably fast. It is called while
// holding the internal lock. Network I/O should be buffered (e.g., sent to a channel).
//
// Shutdown:
// Call Stop() to gracefully shutdown. This flushes pending items and stops the timer.
// After Stop(), AddOutput and AddEvent will return errors. Stop() is idempotent and
// safe to call multiple times concurrently.
type EventBatcher struct {
	mu sync.Mutex

	// Configuration
	flushInterval    time.Duration // Timer-based flush
	maxBatchSize     int32         // Max output items per batch
	maxBatchBytes    int64         // Max bytes per batch
	playbackInterval int32         // Playback interval for client replay timing

	// Buffering state
	buffer           []*jobv1.OutputItem
	bufferBytes      int64
	bufferStartTime  time.Time
	batchStartSeq    int64 // Sequence number of first item in buffer
	currentSeq       int64 // Current sequence counter
	firstTimestampMs int64 // Absolute timestamp of first item in buffer

	// Timer management
	flushTimer *time.Timer
	stopCh     chan struct{}
	stopOnce   sync.Once // Ensures Stop() is idempotent

	// Callback for publishing batches
	onFlush func(context.Context, *jobv1.JobEvent) error
}

// NewEventBatcher creates a new event batcher with the given configuration.
// The onFlush callback is wrapped to accept context for backwards compatibility.
// For new code, consider using NewEventBatcherWithContext.
func NewEventBatcher(config *jobv1.ExecutionConfig, onFlush func(*jobv1.JobEvent) error) *EventBatcher {
	// Wrap the callback to add context support
	onFlushWithCtx := func(ctx context.Context, event *jobv1.JobEvent) error {
		return onFlush(event)
	}
	return NewEventBatcherWithContext(config, onFlushWithCtx)
}

// NewEventBatcherWithContext creates a new event batcher with context-aware callback.
// The onFlush callback receives a context that can be used for cancellation and tracing.
func NewEventBatcherWithContext(config *jobv1.ExecutionConfig, onFlush func(context.Context, *jobv1.JobEvent) error) *EventBatcher {
	if config == nil || config.Batching == nil {
		// Use sensible defaults
		config = &jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   2,
				MaxBatchSize:           50,
				MaxBatchBytes:          1048576,
				PlaybackIntervalMillis: 50,
			},
			HeartbeatIntervalSeconds: 30,
		}
	}

	return &EventBatcher{
		flushInterval:    time.Duration(config.Batching.FlushIntervalSeconds) * time.Second,
		maxBatchSize:     config.Batching.MaxBatchSize,
		maxBatchBytes:    config.Batching.MaxBatchBytes,
		playbackInterval: config.Batching.PlaybackIntervalMillis,
		buffer:           make([]*jobv1.OutputItem, 0, config.Batching.MaxBatchSize),
		stopCh:           make(chan struct{}),
		onFlush:          onFlush,
		currentSeq:       1, // Start at sequence 1
	}
}

// AddOutput buffers a single output line with stream type.
// Returns error if flush fails or if batcher is stopped.
// For new code, use AddOutputContext for cancellation support.
func (eb *EventBatcher) AddOutput(output []byte, streamType jobv1.StreamType) error {
	return eb.AddOutputContext(context.Background(), output, streamType)
}

// AddOutputContext buffers a single output line with stream type and context.
// The context is used for flush operations and can cancel ongoing flushes.
// Returns error if flush fails or if batcher is stopped.
func (eb *EventBatcher) AddOutputContext(ctx context.Context, output []byte, streamType jobv1.StreamType) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Check if batcher is stopped
	select {
	case <-eb.stopCh:
		return fmt.Errorf("event batcher is stopped")
	default:
	}

	// CRITICAL FIX: Make defensive copy to prevent external mutation
	outputCopy := make([]byte, len(output))
	copy(outputCopy, output)

	// Calculate item size: output bytes + field overhead (rough estimate)
	itemSize := int64(len(output) + 16) // 16 bytes for stream_type and timestamp_delta_ms fields

	// Determine timestamp
	now := time.Now()
	nowMs := now.UnixMilli()

	// Initialize batch if empty
	if len(eb.buffer) == 0 {
		eb.bufferStartTime = now
		eb.batchStartSeq = eb.currentSeq
		eb.firstTimestampMs = nowMs

		// Start flush timer
		eb.startFlushTimer()
	}

	// Calculate timestamp delta from first item in batch
	timeDeltaMs := util.AsInt32FromInt64(nowMs - eb.firstTimestampMs)

	// Add item to buffer (using defensive copy)
	item := &jobv1.OutputItem{
		Output:           outputCopy,
		StreamType:       streamType,
		TimestampDeltaMs: timeDeltaMs,
	}
	eb.buffer = append(eb.buffer, item)
	eb.bufferBytes += itemSize
	eb.currentSeq++

	// Check flush conditions
	shouldFlush := false
	reason := ""

	if util.AsInt32(len(eb.buffer)) >= eb.maxBatchSize {
		shouldFlush = true
		reason = "max_batch_size"
	} else if eb.bufferBytes >= eb.maxBatchBytes {
		shouldFlush = true
		reason = "max_batch_bytes"
	}

	if shouldFlush {
		return eb.flushLocked(ctx, reason)
	}

	return nil
}

// AddEvent flushes current batch and publishes a non-output event directly.
// This ensures ordering: all buffered outputs are flushed before the new event.
// For new code, use AddEventContext for cancellation support.
func (eb *EventBatcher) AddEvent(event *jobv1.JobEvent) error {
	return eb.AddEventContext(context.Background(), event)
}

// AddEventContext flushes current batch and publishes a non-output event directly.
// The context is used for flush and publish operations.
// This ensures ordering: all buffered outputs are flushed before the new event.
func (eb *EventBatcher) AddEventContext(ctx context.Context, event *jobv1.JobEvent) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Check if batcher is stopped
	select {
	case <-eb.stopCh:
		return fmt.Errorf("event batcher is stopped")
	default:
	}

	// Flush any buffered outputs first
	if len(eb.buffer) > 0 {
		if err := eb.flushLocked(ctx, "manual_flush_before_event"); err != nil {
			return fmt.Errorf("failed to flush batch before event: %w", err)
		}
	}

	// Assign sequence and timestamp to non-output event
	event.Sequence = eb.currentSeq
	eb.currentSeq++
	if event.Timestamp == nil {
		event.Timestamp = timestamppb.Now()
	}

	// Publish event directly
	return eb.onFlush(ctx, event)
}

// Flush flushes any buffered outputs immediately.
// This is safe to call concurrently.
// For new code, use FlushContext for cancellation support.
func (eb *EventBatcher) Flush() error {
	return eb.FlushContext(context.Background())
}

// FlushContext flushes any buffered outputs immediately with context.
// This is safe to call concurrently.
func (eb *EventBatcher) FlushContext(ctx context.Context) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if len(eb.buffer) == 0 {
		return nil
	}

	return eb.flushLocked(ctx, "manual_flush")
}

// Stop gracefully shuts down the batcher and flushes any pending outputs.
// Stop is idempotent and safe to call multiple times concurrently.
// For new code, use StopContext to pass a context for the final flush.
func (eb *EventBatcher) Stop() error {
	return eb.StopContext(context.Background())
}

// StopContext gracefully shuts down the batcher and flushes any pending outputs.
// The context is used for the final flush operation.
// Stop is idempotent and safe to call multiple times concurrently.
func (eb *EventBatcher) StopContext(ctx context.Context) error {
	var flushErr error

	// CRITICAL FIX: Use sync.Once to ensure Stop is idempotent
	eb.stopOnce.Do(func() {
		// Close stop channel to signal shutdown
		close(eb.stopCh)

		// Acquire lock for final flush
		eb.mu.Lock()
		defer eb.mu.Unlock()

		// CRITICAL FIX: Properly stop timer with channel drain
		if eb.flushTimer != nil {
			if !eb.flushTimer.Stop() {
				// Timer already fired but callback may not have run yet
				// Drain the channel to prevent the callback from executing
				select {
				case <-eb.flushTimer.C:
				default:
				}
			}
			eb.flushTimer = nil
		}

		// Flush any remaining buffered outputs
		if len(eb.buffer) > 0 {
			flushErr = eb.flushLocked(ctx, "shutdown")
		}
	})

	return flushErr
}

// flushLocked flushes the current buffer and publishes a batch event
// Must be called with lock held
func (eb *EventBatcher) flushLocked(ctx context.Context, reason string) error {
	if len(eb.buffer) == 0 {
		// Stop timer if no more items
		if eb.flushTimer != nil {
			// CRITICAL FIX: Properly stop timer before clearing
			if !eb.flushTimer.Stop() {
				// Timer already fired, drain channel
				select {
				case <-eb.flushTimer.C:
				default:
				}
			}
			eb.flushTimer = nil
		}
		return nil
	}

	// Create batch event
	startSeq := eb.batchStartSeq
	endSeq := startSeq + int64(len(eb.buffer)) - 1

	batchEvent := &jobv1.JobEvent{
		Sequence:  startSeq, // Batch event's sequence is the start_sequence
		Timestamp: timestamppb.Now(),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		EventData: &jobv1.JobEvent_OutputBatch{
			OutputBatch: &jobv1.OutputBatchEvent{
				Outputs:                eb.buffer,
				StartSequence:          startSeq,
				EndSequence:            endSeq,
				FirstTimestampMs:       eb.firstTimestampMs,
				PlaybackIntervalMillis: eb.playbackInterval,
			},
		},
	}

	// Log batch info with duration
	log.Debug().
		Int64("start_seq", startSeq).
		Int64("end_seq", endSeq).
		Int("item_count", len(eb.buffer)).
		Int64("bytes", eb.bufferBytes).
		Dur("batch_duration", time.Since(eb.bufferStartTime)).
		Str("reason", reason).
		Msg("Flushing output batch")

	// Publish batch with context
	err := eb.onFlush(ctx, batchEvent)

	// CRITICAL FIX: Stop timer before resetting buffer
	if eb.flushTimer != nil {
		if !eb.flushTimer.Stop() {
			select {
			case <-eb.flushTimer.C:
			default:
			}
		}
		eb.flushTimer = nil
	}

	// Reset buffer
	eb.buffer = make([]*jobv1.OutputItem, 0, eb.maxBatchSize)
	eb.bufferBytes = 0

	return err
}

// startFlushTimer starts or restarts the flush timer
// Must be called with lock held
func (eb *EventBatcher) startFlushTimer() {
	// CRITICAL FIX: Stop existing timer properly with channel drain
	if eb.flushTimer != nil {
		if !eb.flushTimer.Stop() {
			// Timer already fired but callback may not have run yet
			// Try to drain the channel to prevent the old callback from executing
			select {
			case <-eb.flushTimer.C:
				// Channel drained, old callback won't execute
			default:
				// Channel empty, timer was stopped or callback already ran
			}
		}
	}

	// Start new timer
	eb.flushTimer = time.AfterFunc(eb.flushInterval, func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		// Check if batcher was stopped (race condition check)
		select {
		case <-eb.stopCh:
			return
		default:
		}

		// Flush if buffer still has items
		if len(eb.buffer) > 0 {
			ctx := context.Background()
			if err := eb.flushLocked(ctx, "timer"); err != nil {
				log.Error().Err(err).Msg("Failed to flush batch on timer")
				// Continue - don't fail the whole operation
			}
		}
	})
}
