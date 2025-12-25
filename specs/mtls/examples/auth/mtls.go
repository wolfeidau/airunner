package auth

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/authn"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/store"
)

// PrincipalInfo contains authenticated principal information
type PrincipalInfo struct {
	PrincipalID  string
	Type         store.PrincipalType
	SerialNumber string
	Fingerprint  string
}

// MTLSAuthenticator handles mTLS authentication with principal and cert validation
type MTLSAuthenticator struct {
	principalStore store.PrincipalStore
	certStore      store.CertificateStore
	cache          *authCache
}

// NewMTLSAuthenticator creates a new mTLS authenticator
func NewMTLSAuthenticator(ps store.PrincipalStore, cs store.CertificateStore) *MTLSAuthenticator {
	return &MTLSAuthenticator{
		principalStore: ps,
		certStore:      cs,
		cache:          newAuthCache(5 * time.Minute),
	}
}

// AuthFunc returns an authn.AuthFunc for Connect RPC middleware
func (a *MTLSAuthenticator) AuthFunc() authn.AuthFunc {
	return func(ctx context.Context, req *http.Request) (any, error) {
		// Get TLS connection state
		tlsState := req.TLS
		if tlsState == nil {
			return nil, authn.Errorf("TLS required")
		}

		// Ensure client certificate was verified
		if len(tlsState.VerifiedChains) == 0 || len(tlsState.VerifiedChains[0]) == 0 {
			return nil, authn.Errorf("valid client certificate required")
		}

		// Extract client certificate (leaf cert from verified chain)
		cert := tlsState.VerifiedChains[0][0]
		serialNumber := cert.SerialNumber.Text(16)

		// Check cache first
		if info, found := a.cache.Get(serialNumber); found {
			if info.err != nil {
				return nil, info.err
			}
			return info.principal, nil
		}

		// Validate principal and certificate
		principalInfo, err := a.validate(ctx, cert)

		// Cache result (both success and failure)
		a.cache.Set(serialNumber, principalInfo, err)

		if err != nil {
			return nil, err
		}

		log.Debug().
			Str("principal_id", principalInfo.PrincipalID).
			Str("type", string(principalInfo.Type)).
			Str("serial", serialNumber).
			Msg("mTLS authentication successful")

		return principalInfo, nil
	}
}

func (a *MTLSAuthenticator) validate(ctx context.Context, cert *x509.Certificate) (*PrincipalInfo, error) {
	serialNumber := cert.SerialNumber.Text(16)

	// Extract principal type and ID from custom OID extensions
	// Note: Replace with actual pki package calls:
	// principalType, err := pki.ExtractPrincipalType(cert)
	// principalID, err := pki.ExtractPrincipalID(cert)
	principalType := ""
	principalID := ""
	var err error

	if principalType == "" {
		log.Warn().Err(err).Msg("failed to extract principal type from certificate")
		return nil, authn.Errorf("invalid certificate: missing principal type")
	}

	if err != nil {
		// Fall back to CN if principal ID extension not found
		principalID = cert.Subject.CommonName
	}

	// Validate principal type
	if !isValidPrincipalType(store.PrincipalType(principalType)) {
		log.Warn().
			Str("principal_id", principalID).
			Str("type", string(principalType)).
			Msg("invalid principal type in certificate")
		return nil, authn.Errorf("invalid principal type: %s", principalType)
	}

	// Check principal status in database
	principal, err := a.principalStore.Get(ctx, principalID)
	if err != nil {
		if errors.Is(err, store.ErrPrincipalNotFound) {
			log.Warn().
				Str("principal_id", principalID).
				Str("serial", serialNumber).
				Msg("principal not found")
			return nil, authn.Errorf("principal not found: %s", principalID)
		}
		log.Error().Err(err).Str("principal_id", principalID).Msg("failed to get principal")
		return nil, authn.Errorf("authentication error")
	}

	// Check principal status
	switch principal.Status {
	case store.PrincipalStatusSuspended:
		log.Warn().
			Str("principal_id", principalID).
			Str("reason", principal.SuspendedReason).
			Msg("suspended principal rejected")
		return nil, authn.Errorf("principal suspended: %s", principal.SuspendedReason)
	case store.PrincipalStatusDeleted:
		log.Warn().Str("principal_id", principalID).Msg("deleted principal rejected")
		return nil, authn.Errorf("principal deleted")
	}

	// Verify type matches
	if principal.Type != store.PrincipalType(principalType) {
		log.Warn().
			Str("principal_id", principalID).
			Str("cert_type", string(principalType)).
			Str("db_type", string(principal.Type)).
			Msg("principal type mismatch")
		return nil, authn.Errorf("principal type mismatch")
	}

	// Check certificate revocation
	certMeta, err := a.certStore.Get(ctx, serialNumber)
	if err != nil {
		if errors.Is(err, store.ErrCertNotFound) {
			// Certificate not registered - this is allowed
			// (supports certificates issued before tracking was enabled)
			log.Debug().
				Str("serial", serialNumber).
				Str("principal_id", principalID).
				Msg("certificate not registered, allowing")
		} else {
			log.Error().Err(err).Str("serial", serialNumber).Msg("failed to check certificate")
			return nil, authn.Errorf("authentication error")
		}
	} else if certMeta.Revoked {
		log.Warn().
			Str("serial", serialNumber).
			Str("principal_id", principalID).
			Str("reason", certMeta.RevocationReason).
			Msg("revoked certificate rejected")
		return nil, authn.Errorf("certificate revoked: %s", certMeta.RevocationReason)
	}

	// Build fingerprint for logging/auditing
	fingerprint := ""
	if certMeta != nil {
		fingerprint = certMeta.Fingerprint
	}

	return &PrincipalInfo{
		PrincipalID:  principalID,
		Type:         store.PrincipalType(principalType),
		SerialNumber: serialNumber,
		Fingerprint:  fingerprint,
	}, nil
}

func isValidPrincipalType(t store.PrincipalType) bool {
	switch t {
	case store.PrincipalTypeAdmin, store.PrincipalTypeWorker,
		store.PrincipalTypeUser, store.PrincipalTypeService:
		return true
	}
	return false
}

// GetPrincipalInfo extracts PrincipalInfo from context (set by authn middleware)
func GetPrincipalInfo(ctx context.Context) (*PrincipalInfo, bool) {
	info := authn.GetInfo(ctx)
	if info == nil {
		return nil, false
	}
	pi, ok := info.(*PrincipalInfo)
	return pi, ok
}

// authCache caches authentication results
type authCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	principal *PrincipalInfo
	err       error
	cachedAt  time.Time
}

func newAuthCache(ttl time.Duration) *authCache {
	c := &authCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
	// Start cleanup goroutine
	go c.cleanup()
	return c
}

func (c *authCache) Get(serialNumber string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[serialNumber]
	if !exists {
		return nil, false
	}
	if time.Since(entry.cachedAt) > c.ttl {
		return nil, false
	}
	return entry, true
}

func (c *authCache) Set(serialNumber string, principal *PrincipalInfo, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[serialNumber] = &cacheEntry{
		principal: principal,
		err:       err,
		cachedAt:  time.Now(),
	}
}

func (c *authCache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.entries {
			if now.Sub(v.cachedAt) > c.ttl {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}
