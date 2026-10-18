package postgres

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/store"
)

// RunSessionSweeper deletes expired sessions immediately and then every interval, in up to
// maxBatches batches of batch rows per tick. It returns when ctx is done.
// onDeleted, if non-nil, is called with the number deleted per tick.
func RunSessionSweeper(ctx context.Context, sessions store.SessionStore, interval time.Duration, batch, maxBatches int, onDeleted func(int)) {
	sweep := func() {
		total, _, err := SweepExpiredSessions(ctx, sessions, batch, maxBatches)
		if err != nil && ctx.Err() == nil {
			log.Error().Err(err).Msg("Session sweep failed")
		}
		if total > 0 {
			log.Info().Int("count", total).Msg("Session sweep deleted expired sessions")
			if onDeleted != nil {
				onDeleted(total)
			}
		}
	}

	sweep()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// SweepExpiredSessions deletes expired sessions in up to maxBatches batches of batch rows.
// It returns the number deleted, whether it drained (finished on a short batch), and the
// first error.
func SweepExpiredSessions(ctx context.Context, sessions store.SessionStore, batch, maxBatches int) (int, bool, error) {
	total := 0
	for range maxBatches {
		if err := ctx.Err(); err != nil {
			return total, false, err
		}
		n, err := sessions.DeleteExpired(ctx, batch)
		total += n
		if err != nil {
			return total, false, err
		}
		if n < batch {
			return total, true, nil
		}
	}
	return total, false, nil
}
