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
		total := 0
		for i := 0; i < maxBatches && ctx.Err() == nil; i++ {
			n, err := sessions.DeleteExpired(ctx, batch)
			total += n
			if err != nil {
				if ctx.Err() == nil {
					log.Error().Err(err).Msg("Session sweep failed")
				}
				break
			}
			if n < batch {
				break
			}
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
