package store

import (
	"context"
	"sync"
	"time"
)

// MemoryPrincipalStore is an in-memory implementation of PrincipalStore for development and testing
type MemoryPrincipalStore struct {
	mu         sync.RWMutex
	principals map[string]*PrincipalMetadata
}

// NewMemoryPrincipalStore creates a new in-memory principal store
func NewMemoryPrincipalStore() *MemoryPrincipalStore {
	return &MemoryPrincipalStore{
		principals: make(map[string]*PrincipalMetadata),
	}
}

// Get retrieves principal metadata by ID
func (s *MemoryPrincipalStore) Get(ctx context.Context, principalID string) (*PrincipalMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return nil, ErrPrincipalNotFound
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
func (s *MemoryPrincipalStore) Create(ctx context.Context, principal *PrincipalMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.principals[principal.PrincipalID]; exists {
		return ErrPrincipalAlreadyExists
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
func (s *MemoryPrincipalStore) Update(ctx context.Context, principal *PrincipalMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.principals[principal.PrincipalID]; !exists {
		return ErrPrincipalNotFound
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
func (s *MemoryPrincipalStore) Suspend(ctx context.Context, principalID string, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return ErrPrincipalNotFound
	}

	now := time.Now()
	principal.Status = PrincipalStatusSuspended
	principal.SuspendedAt = &now
	principal.SuspendedReason = reason

	return nil
}

// Activate activates a suspended principal
func (s *MemoryPrincipalStore) Activate(ctx context.Context, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return ErrPrincipalNotFound
	}

	principal.Status = PrincipalStatusActive
	principal.SuspendedAt = nil
	principal.SuspendedReason = ""

	return nil
}

// Delete soft-deletes a principal
func (s *MemoryPrincipalStore) Delete(ctx context.Context, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return ErrPrincipalNotFound
	}

	principal.Status = PrincipalStatusDeleted

	return nil
}

// List returns principals matching filters
func (s *MemoryPrincipalStore) List(ctx context.Context, opts ListPrincipalsOptions) ([]*PrincipalMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*PrincipalMetadata

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
