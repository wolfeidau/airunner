package auth

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/store"
)

// RevocationCheckerImpl implements RevocationChecker by periodically polling
// the PrincipalStore for revoked credentials.
type RevocationCheckerImpl struct {
	principalStore store.PrincipalStore

	mu              sync.RWMutex
	revokedSet      map[string]bool
	refreshInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRevocationChecker creates a new revocation checker that polls every refreshInterval.
// The checker starts a background goroutine that runs until Stop() is called.
func NewRevocationChecker(
	ctx context.Context,
	principalStore store.PrincipalStore,
	refreshInterval time.Duration,
) *RevocationCheckerImpl {
	checkerCtx, cancel := context.WithCancel(ctx)

	rc := &RevocationCheckerImpl{
		principalStore:  principalStore,
		revokedSet:      make(map[string]bool),
		refreshInterval: refreshInterval,
		ctx:             checkerCtx,
		cancel:          cancel,
	}

	// Start background refresh goroutine
	rc.wg.Add(1)
	go rc.refreshLoop()

	// Do initial refresh synchronously
	if err := rc.refresh(ctx); err != nil {
		log.Error().Err(err).Msg("Initial revocation list refresh failed")
	}

	return rc
}

// IsRevoked checks if a worker credential fingerprint is revoked.
func (rc *RevocationCheckerImpl) IsRevoked(ctx context.Context, fingerprint string) bool {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	return rc.revokedSet[fingerprint]
}

// Stop gracefully stops the background refresh goroutine.
func (rc *RevocationCheckerImpl) Stop() {
	rc.cancel()
	rc.wg.Wait()
}

// refreshLoop periodically refreshes the revocation list.
func (rc *RevocationCheckerImpl) refreshLoop() {
	defer rc.wg.Done()

	ticker := time.NewTicker(rc.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rc.ctx.Done():
			log.Info().Msg("Revocation checker stopped")
			return

		case <-ticker.C:
			if err := rc.refresh(rc.ctx); err != nil {
				log.Error().Err(err).Msg("Failed to refresh revocation list")
			}
		}
	}
}

// refresh fetches the revocation list from the PrincipalStore.
func (rc *RevocationCheckerImpl) refresh(ctx context.Context) error {
	log.Debug().Msg("Refreshing revocation list")

	// Get all revoked principals from the store
	revoked, err := rc.principalStore.ListRevoked(ctx)
	if err != nil {
		return err
	}

	// Build new revoked set from fingerprints
	newSet := make(map[string]bool, len(revoked))
	for _, p := range revoked {
		if p.Fingerprint != "" {
			newSet[p.Fingerprint] = true
		}
	}

	// Atomically replace the revoked set
	rc.mu.Lock()
	rc.revokedSet = newSet
	rc.mu.Unlock()

	log.Info().Int("count", len(newSet)).Msg("Refreshed revocation list")
	return nil
}
