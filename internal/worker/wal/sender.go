package wal

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// asyncSender manages background sending of WAL records with retry logic
type asyncSender struct {
	wal    *walImpl
	sender EventSender
	cfg    *WALConfig

	stopCh  chan struct{}
	doneCh  chan struct{}
	flushCh chan struct{}
}

// newAsyncSender creates a new async sender
func newAsyncSender(wal *walImpl, sender EventSender, cfg *WALConfig) *asyncSender {
	return &asyncSender{
		wal:     wal,
		sender:  sender,
		cfg:     cfg,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		flushCh: make(chan struct{}, 1), // Buffered so trigger doesn't block
	}
}

// sendLoop is the main goroutine that periodically tries to send unsent records
func (s *asyncSender) sendLoop(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	log.Debug().
		Str("job_id", s.wal.jobID).
		Dur("flush_interval", s.cfg.FlushInterval).
		Msg("Async sender loop started")

	for {
		select {
		case <-ticker.C:
			s.trySend(ctx)

		case <-s.flushCh:
			log.Debug().Str("job_id", s.wal.jobID).Msg("Flush triggered, attempting immediate send")
			s.trySend(ctx)

		case <-s.stopCh:
			log.Debug().Str("job_id", s.wal.jobID).Msg("Async sender stopping, final flush")
			s.trySend(ctx) // Final flush
			return

		case <-ctx.Done():
			log.Debug().Str("job_id", s.wal.jobID).Msg("Async sender context cancelled")
			return
		}
	}
}

// trySend attempts to send all unsent records with exponential backoff retry
func (s *asyncSender) trySend(ctx context.Context) {
	unsent := s.wal.index.GetUnsent()
	if len(unsent) == 0 {
		return
	}

	log.Debug().
		Str("job_id", s.wal.jobID).
		Int("unsent_count", len(unsent)).
		Msg("Attempting to send unsent records")

	// Read events from WAL file
	events, validRecords, err := s.readRecords(unsent)
	if err != nil {
		log.Error().
			Err(err).
			Str("job_id", s.wal.jobID).
			Msg("Failed to read records from WAL")
		return
	}

	if len(events) == 0 {
		log.Debug().
			Str("job_id", s.wal.jobID).
			Msg("No valid events to send")
		return
	}

	// Retry with exponential backoff
	var sendErr error
	interval := s.cfg.RetryBackoff.InitialInterval
	attempt := 0

	for {
		attempt++

		sendErr = s.sender.Send(ctx, events)
		if sendErr == nil {
			// Success!
			log.Info().
				Str("job_id", s.wal.jobID).
				Int("event_count", len(events)).
				Int("attempts", attempt).
				Msg("Successfully sent events")
			break
		}

		log.Warn().
			Err(sendErr).
			Str("job_id", s.wal.jobID).
			Int("event_count", len(events)).
			Int("attempt", attempt).
			Dur("next_retry", interval).
			Msg("Failed to send events, will retry")

		// Wait with exponential backoff
		select {
		case <-time.After(interval):
			// Increase interval for next retry
			interval = time.Duration(float64(interval) * s.cfg.RetryBackoff.Multiplier)
			if interval > s.cfg.RetryBackoff.MaxInterval {
				interval = s.cfg.RetryBackoff.MaxInterval
			}

		case <-s.flushCh:
			log.Debug().
				Str("job_id", s.wal.jobID).
				Msg("Flush triggered during retry backoff, retrying immediately")
			// Don't increase interval, retry immediately with same backoff

		case <-ctx.Done():
			log.Debug().
				Str("job_id", s.wal.jobID).
				Msg("Context cancelled during retry backoff")
			return

		case <-s.stopCh:
			log.Debug().
				Str("job_id", s.wal.jobID).
				Msg("Stop requested during retry backoff")
			return
		}
	}

	// Update record status
	if sendErr == nil {
		s.wal.index.MarkSent(validRecords)
		log.Debug().
			Str("job_id", s.wal.jobID).
			Int("marked_sent", len(validRecords)).
			Msg("Marked records as sent")
	} else {
		s.wal.index.MarkFailed(validRecords)
		log.Warn().
			Str("job_id", s.wal.jobID).
			Int("marked_failed", len(validRecords)).
			Msg("Marked records as failed")
	}
}

// readRecords reads events from the WAL file for the given record metadata
// Returns the events, valid records (that could be read), and any error
func (s *asyncSender) readRecords(records []walRecord) ([]*jobv1.JobEvent, []walRecord, error) {
	events := make([]*jobv1.JobEvent, 0, len(records))
	validRecords := make([]walRecord, 0, len(records))

	for _, rec := range records {
		event, err := s.wal.readRecordAt(rec.offset)
		if err != nil {
			log.Warn().
				Err(err).
				Str("job_id", s.wal.jobID).
				Int64("sequence", rec.sequence).
				Int64("offset", rec.offset).
				Msg("Failed to read record, skipping")
			continue
		}

		events = append(events, event)
		validRecords = append(validRecords, rec)
	}

	if len(validRecords) == 0 && len(records) > 0 {
		return nil, nil, fmt.Errorf("failed to read any records")
	}

	return events, validRecords, nil
}

// triggerFlush signals the sender to try sending immediately
func (s *asyncSender) triggerFlush() {
	select {
	case s.flushCh <- struct{}{}:
		// Signal sent
	default:
		// Channel already has a pending signal, skip
	}
}

// stop signals the sender to stop
func (s *asyncSender) stop() {
	close(s.stopCh)
	// Wait for sender to finish (with timeout)
	select {
	case <-s.doneCh:
		log.Debug().Msg("Async sender stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Warn().Msg("Async sender stop timeout")
	}
}
