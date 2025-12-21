package worker

import (
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

	// Callback for publishing batches
	onFlush func(*jobv1.JobEvent) error
}

// NewEventBatcher creates a new event batcher with the given configuration
func NewEventBatcher(config *jobv1.ExecutionConfig, onFlush func(*jobv1.JobEvent) error) *EventBatcher {
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

// AddOutput buffers a single output line with stream type
// Returns error if flush fails or if batcher is stopped
func (eb *EventBatcher) AddOutput(output []byte, streamType int32) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Check if batcher is stopped
	select {
	case <-eb.stopCh:
		return fmt.Errorf("event batcher is stopped")
	default:
	}

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

	// Add item to buffer
	item := &jobv1.OutputItem{
		Output:           output,
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
		return eb.flushLocked(reason)
	}

	return nil
}

// AddEvent flushes current batch and publishes a non-output event directly
// This ensures ordering: all buffered outputs are flushed before the new event
func (eb *EventBatcher) AddEvent(event *jobv1.JobEvent) error {
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
		if err := eb.flushLocked("manual_flush_before_event"); err != nil {
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
	return eb.onFlush(event)
}

// Flush flushes any buffered outputs immediately
// This is safe to call concurrently
func (eb *EventBatcher) Flush() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if len(eb.buffer) == 0 {
		return nil
	}

	return eb.flushLocked("manual_flush")
}

// Stop gracefully shuts down the batcher and flushes any pending outputs
func (eb *EventBatcher) Stop() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Only close if not already closed
	select {
	case <-eb.stopCh:
		// Already closed
		return nil
	default:
		close(eb.stopCh)
	}

	// Stop timer if running
	if eb.flushTimer != nil {
		eb.flushTimer.Stop()
	}

	// Flush any remaining buffered outputs
	if len(eb.buffer) > 0 {
		return eb.flushLocked("shutdown")
	}

	return nil
}

// flushLocked flushes the current buffer and publishes a batch event
// Must be called with lock held
func (eb *EventBatcher) flushLocked(reason string) error {
	if len(eb.buffer) == 0 {
		// Stop timer if no more items
		if eb.flushTimer != nil {
			eb.flushTimer.Stop()
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

	// Log batch info
	log.Debug().
		Int64("start_seq", startSeq).
		Int64("end_seq", endSeq).
		Int("item_count", len(eb.buffer)).
		Int64("bytes", eb.bufferBytes).
		Str("reason", reason).
		Msg("Flushing output batch")

	// Publish batch
	err := eb.onFlush(batchEvent)

	// Reset buffer
	eb.buffer = make([]*jobv1.OutputItem, 0, eb.maxBatchSize)
	eb.bufferBytes = 0
	eb.flushTimer = nil

	return err
}

// startFlushTimer starts or restarts the flush timer
// Must be called with lock held
func (eb *EventBatcher) startFlushTimer() {
	// Stop existing timer if any
	if eb.flushTimer != nil {
		eb.flushTimer.Stop()
	}

	// Start new timer
	eb.flushTimer = time.AfterFunc(eb.flushInterval, func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		// Check if still stopped (race condition check)
		select {
		case <-eb.stopCh:
			return
		default:
		}

		// Flush if buffer still has items
		if len(eb.buffer) > 0 {
			if err := eb.flushLocked("timer"); err != nil {
				log.Error().Err(err).Msg("Failed to flush batch on timer")
				// Continue - don't fail the whole operation
			}
		}
	})
}
