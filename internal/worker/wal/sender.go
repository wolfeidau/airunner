package wal

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// asyncSender retries failed sends with exponential backoff
type asyncSender struct {
	wal              *walImpl
	sender           EventSender
	flushInterval    time.Duration
	backoff          BackoffConfig
	retryAttempts    map[int64]int
	stopChan         chan struct{}
	done             chan struct{}
	lastRetryBackoff map[int64]time.Duration
}

// newAsyncSender creates new async sender
func newAsyncSender(wal *walImpl, sender EventSender, flushInterval time.Duration, backoff BackoffConfig) *asyncSender {
	return &asyncSender{
		wal:              wal,
		sender:           sender,
		flushInterval:    flushInterval,
		backoff:          backoff,
		retryAttempts:    make(map[int64]int),
		stopChan:         make(chan struct{}),
		done:             make(chan struct{}),
		lastRetryBackoff: make(map[int64]time.Duration),
	}
}

// start runs the async sender loop
func (as *asyncSender) start(ctx context.Context) {
	defer close(as.done)

	ticker := time.NewTicker(as.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-as.stopChan:
			// Final flush before exit
			as.flush(ctx)
			return

		case <-ctx.Done():
			return

		case <-ticker.C:
			as.flush(ctx)
		}
	}
}

// stop stops the async sender
func (as *asyncSender) stop(ctx context.Context) error {
	close(as.stopChan)

	// Wait for done or timeout
	select {
	case <-as.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("async sender stop timeout")
	}
}

// flush sends all unsent records
func (as *asyncSender) flush(ctx context.Context) {
	unsent := as.wal.getUnsent()
	if len(unsent) == 0 {
		return
	}

	// Collect events to send
	events := make([]*jobv1.JobEvent, 0, len(unsent))
	sequences := make([]int64, 0, len(unsent))

	for _, rec := range unsent {
		// Check if we should retry this record
		if !as.shouldRetry(rec.sequence) {
			continue
		}

		// Read event from file
		event, err := as.readRecord(rec)
		if err != nil {
			log.Error().
				Err(err).
				Int64("sequence", rec.sequence).
				Msg("failed to read record")
			continue
		}

		events = append(events, event)
		sequences = append(sequences, rec.sequence)
	}

	if len(events) == 0 {
		return
	}

	// Send events
	if err := as.sender.Send(ctx, events); err != nil {
		// Increment retry attempts
		for _, seq := range sequences {
			as.retryAttempts[seq]++
			if as.retryAttempts[seq] > 100 {
				// Too many retries, mark as failed
				// This prevents infinite retries but still keeps data
				_ = as.wal.markSent(seq) // Mark as sent to stop retrying
			}
		}

		log.Error().
			Err(err).
			Int("count", len(events)).
			Msg("failed to send events")
		return
	}

	// Mark as sent
	if err := as.wal.markSent(sequences...); err != nil {
		log.Error().
			Err(err).
			Msg("failed to mark records as sent")
		return
	}

	// Clear retry tracking
	for _, seq := range sequences {
		delete(as.retryAttempts, seq)
		delete(as.lastRetryBackoff, seq)
	}

	log.Debug().
		Int("count", len(events)).
		Msg("sent events from WAL")
}

// shouldRetry checks if we should retry this record based on exponential backoff
func (as *asyncSender) shouldRetry(sequence int64) bool {
	attempts := as.retryAttempts[sequence]
	if attempts == 0 {
		// First attempt, always try
		return true
	}

	// Calculate backoff
	backoff := as.calculateBackoff(attempts)

	// Check if enough time has passed since last retry
	if lastBackoff, ok := as.lastRetryBackoff[sequence]; ok {
		if time.Since(time.Now().Add(-lastBackoff)) < backoff {
			return false
		}
	}

	// Update last backoff time
	as.lastRetryBackoff[sequence] = backoff

	return true
}

// calculateBackoff calculates exponential backoff with jitter
func (as *asyncSender) calculateBackoff(attempt int) time.Duration {
	// exponential: initial * (multiplier ^ (attempt - 1))
	backoff := as.backoff.InitialInterval
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * as.backoff.Multiplier)
		if backoff > as.backoff.MaxInterval {
			backoff = as.backoff.MaxInterval
			break
		}
	}

	// Add 50% jitter to prevent thundering herd
	// #nosec G404 - jitter is non-cryptographic and only used for backoff delays
	jitter := time.Duration(rand.Int63n(int64(backoff)))
	return backoff + jitter/2
}

// readRecord reads an event from the WAL file
func (as *asyncSender) readRecord(rec *walRecord) (*jobv1.JobEvent, error) {
	as.wal.mu.RLock()
	file := as.wal.file
	as.wal.mu.RUnlock()

	if file == nil {
		return nil, fmt.Errorf("WAL file is closed")
	}

	// Read record from file
	walRec, err := readRecordAt(file, rec.offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read record at offset %d: %w", rec.offset, err)
	}

	// Extract payload from the record buffer
	// Record structure: length(4) + sequence(8) + status(1) + reserved(3) + timestamp(8) + payload + crc(8)
	// walRec.length already includes all bytes: 4 + data + 8
	if _, err = file.Seek(rec.offset, 0); err != nil {
		return nil, err
	}

	recordBuf := make([]byte, walRec.length)
	if _, err = file.Read(recordBuf); err != nil {
		return nil, err
	}

	// Extract payload (skip length + sequence + status + reserved + timestamp)
	payloadStart := 4 + 8 + 1 + 3 + 8
	payloadEnd := len(recordBuf) - 8 // Exclude CRC

	if payloadStart >= payloadEnd {
		return nil, fmt.Errorf("invalid record structure")
	}

	payload := recordBuf[payloadStart:payloadEnd]

	// Unmarshal event
	event, err := unmarshalEvent(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return event, nil
}

// Utility function to cap retry attempts (avoid overflow)
// Currently unused but kept for future overflow prevention
// nolint:unused
func (as *asyncSender) capRetryAttempts(seq int64) {
	if as.retryAttempts[seq] > 1000 {
		as.retryAttempts[seq] = 1000
	}
}
