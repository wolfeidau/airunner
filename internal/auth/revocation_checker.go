package auth

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	principalv1 "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
)

// RevocationCheckerImpl implements RevocationChecker by periodically polling
// the PrincipalService.ListRevokedPrincipals RPC endpoint.
type RevocationCheckerImpl struct {
	client principalv1connect.PrincipalServiceClient

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
	client principalv1connect.PrincipalServiceClient,
	refreshInterval time.Duration,
) *RevocationCheckerImpl {
	checkerCtx, cancel := context.WithCancel(ctx)

	rc := &RevocationCheckerImpl{
		client:          client,
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

// refresh fetches the revocation list from the PrincipalService.
func (rc *RevocationCheckerImpl) refresh(ctx context.Context) error {
	log.Debug().Msg("Refreshing revocation list")

	req := connect.NewRequest(&principalv1.ListRevokedPrincipalsRequest{})
	resp, err := rc.client.ListRevokedPrincipals(ctx, req)
	if err != nil {
		return err
	}

	fingerprints := resp.Msg.Fingerprints

	// Build new revoked set
	newSet := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		newSet[fp] = true
	}

	// Atomically replace the revoked set
	rc.mu.Lock()
	rc.revokedSet = newSet
	rc.mu.Unlock()

	log.Info().Int("count", len(fingerprints)).Msg("Refreshed revocation list")
	return nil
}
