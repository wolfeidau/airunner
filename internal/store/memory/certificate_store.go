package memory

import (
	"context"
	"sync"
	"time"

	"github.com/wolfeidau/airunner/internal/store"
)

// CertificateStore is an in-memory implementation of CertificateStore for development and testing
type CertificateStore struct {
	mu                 sync.RWMutex
	certs              map[string]*store.CertMetadata   // indexed by serial number
	certsByPrincipal   map[string][]*store.CertMetadata // indexed by principal ID
	certsByFingerprint map[string]*store.CertMetadata   // indexed by fingerprint
}

// NewMemoryCertificateStore creates a new in-memory certificate store
func NewCertificateStore() *CertificateStore {
	return &CertificateStore{
		certs:              make(map[string]*store.CertMetadata),
		certsByPrincipal:   make(map[string][]*store.CertMetadata),
		certsByFingerprint: make(map[string]*store.CertMetadata),
	}
}

// Get retrieves certificate metadata by serial number
func (s *CertificateStore) Get(ctx context.Context, serialNumber string) (*store.CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, exists := s.certs[serialNumber]
	if !exists {
		return nil, store.ErrCertNotFound
	}

	// Return a copy to avoid external modifications
	return s.copyCert(cert), nil
}

// GetByPrincipal retrieves all certificates for a principal
func (s *CertificateStore) GetByPrincipal(ctx context.Context, principalID string) ([]*store.CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certs, exists := s.certsByPrincipal[principalID]
	if !exists {
		return []*store.CertMetadata{}, nil
	}

	// Return copies
	result := make([]*store.CertMetadata, len(certs))
	for i, cert := range certs {
		result[i] = s.copyCert(cert)
	}

	return result, nil
}

// GetByFingerprint retrieves certificate by SHA-256 fingerprint
func (s *CertificateStore) GetByFingerprint(ctx context.Context, fingerprint string) (*store.CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, exists := s.certsByFingerprint[fingerprint]
	if !exists {
		return nil, store.ErrCertNotFound
	}

	// Return a copy to avoid external modifications
	return s.copyCert(cert), nil
}

// Register stores certificate metadata
func (s *CertificateStore) Register(ctx context.Context, cert *store.CertMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.certs[cert.SerialNumber]; exists {
		return store.ErrCertAlreadyExists
	}

	// Store a copy
	copy := s.copyCert(cert)

	// Index by serial number
	s.certs[cert.SerialNumber] = copy

	// Index by fingerprint
	s.certsByFingerprint[cert.Fingerprint] = copy

	// Index by principal ID
	s.certsByPrincipal[cert.PrincipalID] = append(s.certsByPrincipal[cert.PrincipalID], copy)

	return nil
}

// Revoke marks a certificate as revoked
func (s *CertificateStore) Revoke(ctx context.Context, serialNumber string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cert, exists := s.certs[serialNumber]
	if !exists {
		return store.ErrCertNotFound
	}

	now := time.Now()
	cert.Revoked = true
	cert.RevokedAt = &now
	cert.RevocationReason = reason

	return nil
}

// List returns all registered certificates
func (s *CertificateStore) List(ctx context.Context, opts store.ListCertificatesOptions) ([]*store.CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.CertMetadata

	// If filtering by principal, use the index
	if opts.PrincipalID != "" {
		certs, exists := s.certsByPrincipal[opts.PrincipalID]
		if !exists {
			return []*store.CertMetadata{}, nil
		}

		for _, cert := range certs {
			// Skip revoked certs if not requested
			if cert.Revoked && !opts.IncludeRevoked {
				continue
			}

			result = append(result, s.copyCert(cert))

			// Apply limit
			if opts.Limit > 0 && len(result) >= opts.Limit {
				break
			}
		}

		return result, nil
	}

	// Otherwise iterate all certs
	for _, cert := range s.certs {
		// Skip revoked certs if not requested
		if cert.Revoked && !opts.IncludeRevoked {
			continue
		}

		result = append(result, s.copyCert(cert))

		// Apply limit
		if opts.Limit > 0 && len(result) >= opts.Limit {
			break
		}
	}

	return result, nil
}

// copyCert creates a deep copy of a certificate metadata
func (s *CertificateStore) copyCert(cert *store.CertMetadata) *store.CertMetadata {
	copy := *cert
	if cert.RevokedAt != nil {
		t := *cert.RevokedAt
		copy.RevokedAt = &t
	}
	return &copy
}
