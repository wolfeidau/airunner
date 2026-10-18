package wal

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// maxBatchEvents is the server's per-request event limit.
	maxBatchEvents = 50

	// maxBatchBytes is the encoded event budget per request. The server accepts
	// 1 MiB per request; the remainder is headroom for the request envelope.
	maxBatchBytes = 900 * 1024

	stopTimeout = 5 * time.Second
)

// asyncSender manages background sending of WAL records with retry logic
type asyncSender struct {
	wal    *walImpl
	sender EventSender
	cfg    *WALConfig

	ctx    context.Context
	cancel context.CancelFunc

	stopCh   chan struct{}
	doneCh   chan struct{}
	flushCh  chan struct{}
	stopOnce sync.Once
}

// newAsyncSender creates a new async sender bound to ctx
func newAsyncSender(ctx context.Context, wal *walImpl, sender EventSender, cfg *WALConfig) *asyncSender {
	sctx, cancel := context.WithCancel(ctx)
	return &asyncSender{
		wal:     wal,
		sender:  sender,
		cfg:     cfg,
		ctx:     sctx,
		cancel:  cancel,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		flushCh: make(chan struct{}, 1), // Buffered so trigger doesn't block
	}
}

// sendLoop is the main goroutine that periodically tries to send unsent records
func (s *asyncSender) sendLoop() {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.drain(true)
		case <-s.flushCh:
			s.drain(true)
		case <-s.stopCh:
			// Final best-effort pass without retries.
			s.drain(false)
			return
		case <-s.ctx.Done():
			return
		}
	}
}

// drain sends batches in sequence order until nothing is pending, the sender
// is stopped, or a sticky error is recorded. With retry set, transient errors
// are retried with capped exponential backoff; otherwise drain returns.
func (s *asyncSender) drain(retry bool) {
	for {
		if s.ctx.Err() != nil || s.wal.Err() != nil {
			return
		}

		events, recs, err := s.nextBatch()
		if err != nil {
			if !errors.Is(err, errWALClosed) {
				s.wal.setErr(err)
			}
			return
		}
		if len(events) == 0 {
			return
		}

		if !s.sendBatch(events, recs, retry) {
			return
		}
	}
}

// sendBatch sends one batch until it is acknowledged. It returns false when
// the caller should stop draining.
func (s *asyncSender) sendBatch(events []*jobv1.JobEvent, recs []walRecord, retry bool) bool {
	through := coveredSequence(events[len(events)-1])
	backoff := s.initialInterval()

	for sendAttempt := 1; ; sendAttempt++ {
		sentAt := time.Now()
		ack, err := s.sender.Send(s.ctx, events)
		if err == nil {
			if ack.Attempt != s.wal.attempt || ack.Through != through {
				s.wal.setErr(fmt.Errorf("%w: got attempt=%d through=%d, want attempt=%d through=%d",
					ErrAckMismatch, ack.Attempt, ack.Through, s.wal.attempt, through))
				return false
			}
			s.wal.index.MarkSent(recs)
			s.wal.setAcked(through)
			s.cfg.metrics().PublishAckLatency.Record(s.ctx, time.Since(sentAt).Seconds())
			s.recordPending()
			log.Debug().
				Str("job_id", s.wal.jobID).
				Int("event_count", len(events)).
				Int64("through", through).
				Int("send_attempts", sendAttempt).
				Msg("Batch acknowledged")
			return true
		}

		if errors.Is(err, ErrLeaseLost) || errors.Is(err, ErrPermanent) {
			s.wal.setErr(err)
			s.recordPending()
			return false
		}
		if s.ctx.Err() != nil || !retry {
			s.recordPending()
			return false
		}
		s.cfg.metrics().PublishRetries.Add(s.ctx, 1)
		s.recordPending()

		wait := jitter(backoff)
		log.Warn().
			Err(err).
			Str("job_id", s.wal.jobID).
			Int("event_count", len(events)).
			Int("send_attempt", sendAttempt).
			Dur("next_retry", wait).
			Msg("Failed to send events, will retry")

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			backoff = s.nextInterval(backoff)
		case <-s.ctx.Done():
			timer.Stop()
			return false
		case <-s.stopCh:
			timer.Stop()
			return false
		}
	}
}

// recordPending reports the current number of unacknowledged records.
func (s *asyncSender) recordPending() {
	s.cfg.metrics().WALPendingRecords.Record(context.Background(), int64(s.wal.index.CountPending()))
}

// nextBatch reads the next batch of pending records in sequence order.
// A batch holds at most maxBatchEvents records and maxBatchBytes of encoded
// events. A record is never split; a lone record over the byte budget is sent
// by itself. An unreadable record is a permanent failure: later records are
// never sent past it.
func (s *asyncSender) nextBatch() ([]*jobv1.JobEvent, []walRecord, error) {
	unsent := s.wal.index.GetUnsent()

	var (
		events []*jobv1.JobEvent
		recs   []walRecord
		total  int
	)
	for _, rec := range unsent {
		if len(events) >= maxBatchEvents {
			break
		}
		event, err := s.wal.readRecordAt(rec.offset)
		if err != nil {
			if errors.Is(err, errWALClosed) {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("%w: unreadable WAL record sequence=%d offset=%d: %w",
				ErrPermanent, rec.sequence, rec.offset, err)
		}
		size := proto.Size(event)
		if len(events) > 0 && total+size > maxBatchBytes {
			break
		}
		events = append(events, event)
		recs = append(recs, rec)
		total += size
	}
	return events, recs, nil
}

// coveredSequence is the last sequence an event covers: the end of an output
// batch, otherwise the event's own sequence.
func coveredSequence(event *jobv1.JobEvent) int64 {
	if ob := event.GetOutputBatch(); ob != nil {
		return ob.GetEndSequence()
	}
	return event.GetSequence()
}

func (s *asyncSender) initialInterval() time.Duration {
	if s.cfg.RetryBackoff.InitialInterval <= 0 {
		return 100 * time.Millisecond
	}
	return s.cfg.RetryBackoff.InitialInterval
}

func (s *asyncSender) nextInterval(cur time.Duration) time.Duration {
	mult := s.cfg.RetryBackoff.Multiplier
	if mult < 1 {
		mult = 2
	}
	next := time.Duration(float64(cur) * mult)
	if maxI := s.cfg.RetryBackoff.MaxInterval; maxI > 0 && next > maxI {
		next = maxI
	}
	return next
}

// jitter spreads d by +/-20%.
func jitter(d time.Duration) time.Duration {
	//nolint:gosec // jitter does not need a cryptographic source
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// triggerFlush signals the sender to try sending immediately
func (s *asyncSender) triggerFlush() {
	select {
	case s.flushCh <- struct{}{}:
	default:
	}
}

// stop signals the sender to stop and waits for it. With discard set, any
// in-flight Send is cancelled and nothing further is sent; otherwise one final
// best-effort pass runs.
func (s *asyncSender) stop(discard bool) {
	s.stopOnce.Do(func() {
		if discard {
			s.cancel()
		}
		close(s.stopCh)
	})
	select {
	case <-s.doneCh:
	case <-time.After(stopTimeout):
		log.Warn().Str("job_id", s.wal.jobID).Msg("Async sender stop timeout")
	}
	s.cancel()
}
