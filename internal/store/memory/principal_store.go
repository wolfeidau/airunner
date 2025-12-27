package memory

import (
	"context"
	"sync"
	"time"

	"github.com/wolfeidau/airunner/internal/store"
)

// MemoryPrincipalStore is an in-memory implementation of PrincipalStore for development and testing
type PrincipalStore struct {
	mu         sync.RWMutex
	principals map[string]*store.PrincipalMetadata
}

// NewMemoryPrincipalStore creates a new in-memory principal store
func NewPrincipalStore() *PrincipalStore {
	return &PrincipalStore{
		principals: make(map[string]*store.PrincipalMetadata),
	}
}

// Get retrieves principal metadata by ID
func (s *PrincipalStore) Get(ctx context.Context, principalID string) (*store.PrincipalMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return nil, store.ErrPrincipalNotFound
	}

	// Return a copy to avoid external modifications
	copy := *principal
	if principal.SuspendedAt != nil {
		t := *principal.SuspendedAt
		copy.SuspendedAt = &t
	}
	if principal.Metadata != nil {
		copy.Metadata = make(map[string]string)
		for k, v := range principal.Metadata {
			copy.Metadata[k] = v
		}
	}

	return &copy, nil
}

// Create creates a new principal
func (s *PrincipalStore) Create(ctx context.Context, principal *store.PrincipalMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.principals[principal.PrincipalID]; exists {
		return store.ErrPrincipalAlreadyExists
	}

	// Store a copy to avoid external modifications
	copy := *principal
	if principal.SuspendedAt != nil {
		t := *principal.SuspendedAt
		copy.SuspendedAt = &t
	}
	if principal.Metadata != nil {
		copy.Metadata = make(map[string]string)
		for k, v := range principal.Metadata {
			copy.Metadata[k] = v
		}
	}

	s.principals[principal.PrincipalID] = &copy
	return nil
}

// Update updates principal metadata
func (s *PrincipalStore) Update(ctx context.Context, principal *store.PrincipalMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.principals[principal.PrincipalID]; !exists {
		return store.ErrPrincipalNotFound
	}

	// Store a copy to avoid external modifications
	copy := *principal
	if principal.SuspendedAt != nil {
		t := *principal.SuspendedAt
		copy.SuspendedAt = &t
	}
	if principal.Metadata != nil {
		copy.Metadata = make(map[string]string)
		for k, v := range principal.Metadata {
			copy.Metadata[k] = v
		}
	}

	s.principals[principal.PrincipalID] = &copy
	return nil
}

// Suspend suspends a principal
func (s *PrincipalStore) Suspend(ctx context.Context, principalID string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return store.ErrPrincipalNotFound
	}

	now := time.Now()
	principal.Status = store.PrincipalStatusSuspended
	principal.SuspendedAt = &now
	principal.SuspendedReason = reason

	return nil
}

// Activate activates a suspended principal
func (s *PrincipalStore) Activate(ctx context.Context, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return store.ErrPrincipalNotFound
	}

	principal.Status = store.PrincipalStatusActive
	principal.SuspendedAt = nil
	principal.SuspendedReason = ""

	return nil
}

// Delete soft-deletes a principal
func (s *PrincipalStore) Delete(ctx context.Context, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return store.ErrPrincipalNotFound
	}

	principal.Status = store.PrincipalStatusDeleted

	return nil
}

// List returns principals matching filters
func (s *PrincipalStore) List(ctx context.Context, opts store.ListPrincipalsOptions) ([]*store.PrincipalMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*store.PrincipalMetadata

	for _, principal := range s.principals {
		// Apply filters
		if opts.Type != "" && principal.Type != opts.Type {
			continue
		}
		if opts.Status != "" && principal.Status != opts.Status {
			continue
		}

		// Create a copy
		copy := *principal
		if principal.SuspendedAt != nil {
			t := *principal.SuspendedAt
			copy.SuspendedAt = &t
		}
		if principal.Metadata != nil {
			copy.Metadata = make(map[string]string)
			for k, v := range principal.Metadata {
				copy.Metadata[k] = v
			}
		}

		result = append(result, &copy)

		// Apply limit
		if opts.Limit > 0 && len(result) >= opts.Limit {
			break
		}
	}

	return result, nil
}
