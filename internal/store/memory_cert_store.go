package store

import (
	"context"
	"sync"
	"time"
)

// MemoryCertificateStore is an in-memory implementation of CertificateStore for development and testing
type MemoryCertificateStore struct {
	mu                 sync.RWMutex
	certs              map[string]*CertMetadata   // indexed by serial number
	certsByPrincipal   map[string][]*CertMetadata // indexed by principal ID
	certsByFingerprint map[string]*CertMetadata   // indexed by fingerprint
}

// NewMemoryCertificateStore creates a new in-memory certificate store
func NewMemoryCertificateStore() *MemoryCertificateStore {
	return &MemoryCertificateStore{
		certs:              make(map[string]*CertMetadata),
		certsByPrincipal:   make(map[string][]*CertMetadata),
		certsByFingerprint: make(map[string]*CertMetadata),
	}
}

// Get retrieves certificate metadata by serial number
func (s *MemoryCertificateStore) Get(ctx context.Context, serialNumber string) (*CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, exists := s.certs[serialNumber]
	if !exists {
		return nil, ErrCertNotFound
	}

	// Return a copy to avoid external modifications
	return s.copyCert(cert), nil
}

// GetByPrincipal retrieves all certificates for a principal
func (s *MemoryCertificateStore) GetByPrincipal(ctx context.Context, principalID string) ([]*CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certs, exists := s.certsByPrincipal[principalID]
	if !exists {
		return []*CertMetadata{}, nil
	}

	// Return copies
	result := make([]*CertMetadata, len(certs))
	for i, cert := range certs {
		result[i] = s.copyCert(cert)
	}

	return result, nil
}

// GetByFingerprint retrieves certificate by SHA-256 fingerprint
func (s *MemoryCertificateStore) GetByFingerprint(ctx context.Context, fingerprint string) (*CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, exists := s.certsByFingerprint[fingerprint]
	if !exists {
		return nil, ErrCertNotFound
	}

	// Return a copy to avoid external modifications
	return s.copyCert(cert), nil
}

// Register stores certificate metadata
func (s *MemoryCertificateStore) Register(ctx context.Context, cert *CertMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.certs[cert.SerialNumber]; exists {
		return ErrCertAlreadyExists
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
func (s *MemoryCertificateStore) Revoke(ctx context.Context, serialNumber string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cert, exists := s.certs[serialNumber]
	if !exists {
		return ErrCertNotFound
	}

	now := time.Now()
	cert.Revoked = true
	cert.RevokedAt = &now
	cert.RevocationReason = reason

	return nil
}

// List returns all registered certificates
func (s *MemoryCertificateStore) List(ctx context.Context, opts ListCertificatesOptions) ([]*CertMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*CertMetadata

	// If filtering by principal, use the index
	if opts.PrincipalID != "" {
		certs, exists := s.certsByPrincipal[opts.PrincipalID]
		if !exists {
			return []*CertMetadata{}, nil
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
func (s *MemoryCertificateStore) copyCert(cert *CertMetadata) *CertMetadata {
	copy := *cert
	if cert.RevokedAt != nil {
		t := *cert.RevokedAt
		copy.RevokedAt = &t
	}
	return &copy
}
