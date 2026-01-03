package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// PrincipalStore implements store.PrincipalStore using in-memory storage.
// This implementation is for testing only - data is lost on restart.
type PrincipalStore struct {
	mu sync.RWMutex

	principals         map[uuid.UUID]*models.Principal // principal_id -> Principal
	principalsByGitHub map[string]*models.Principal    // github_id -> Principal
	principalsByFprint map[string]*models.Principal    // fingerprint -> Principal
}

// NewPrincipalStore creates a new in-memory principal store.
func NewPrincipalStore() *PrincipalStore {
	return &PrincipalStore{
		principals:         make(map[uuid.UUID]*models.Principal),
		principalsByGitHub: make(map[string]*models.Principal),
		principalsByFprint: make(map[string]*models.Principal),
	}
}

// Create creates a new principal in memory.
func (s *PrincipalStore) Create(ctx context.Context, principal *models.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if principal already exists
	if _, exists := s.principals[principal.PrincipalID]; exists {
		return store.ErrPrincipalAlreadyExists
	}

	// Check for duplicate fingerprint
	if principal.Fingerprint != "" {
		if _, exists := s.principalsByFprint[principal.Fingerprint]; exists {
			return store.ErrPrincipalAlreadyExists
		}
	}

	// Check for duplicate GitHub ID
	if principal.GitHubID != nil {
		if _, exists := s.principalsByGitHub[*principal.GitHubID]; exists {
			return store.ErrPrincipalAlreadyExists
		}
	}

	// Clone to avoid external modifications
	clone := *principal
	s.principals[principal.PrincipalID] = &clone

	// Update indexes
	if clone.Fingerprint != "" {
		s.principalsByFprint[clone.Fingerprint] = &clone
	}
	if clone.GitHubID != nil {
		s.principalsByGitHub[*clone.GitHubID] = &clone
	}

	return nil
}

// Get retrieves a principal by ID.
func (s *PrincipalStore) Get(ctx context.Context, principalID uuid.UUID) (*models.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principal, exists := s.principals[principalID]
	if !exists {
		return nil, store.ErrPrincipalNotFound
	}

	// Clone to avoid external modifications
	clone := *principal
	return &clone, nil
}

// GetByFingerprint retrieves a non-revoked worker/service principal by fingerprint.
func (s *PrincipalStore) GetByFingerprint(ctx context.Context, fingerprint string) (*models.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principal, exists := s.principalsByFprint[fingerprint]
	if !exists || principal.DeletedAt != nil {
		return nil, store.ErrPrincipalNotFound
	}

	// Clone to avoid external modifications
	clone := *principal
	return &clone, nil
}

// GetByGitHubID retrieves a non-revoked user principal by GitHub ID.
func (s *PrincipalStore) GetByGitHubID(ctx context.Context, githubID string) (*models.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principal, exists := s.principalsByGitHub[githubID]
	if !exists || principal.DeletedAt != nil {
		return nil, store.ErrPrincipalNotFound
	}

	// Clone to avoid external modifications
	clone := *principal
	return &clone, nil
}

// Update updates an existing principal.
func (s *PrincipalStore) Update(ctx context.Context, principal *models.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.principals[principal.PrincipalID]
	if !exists {
		return store.ErrPrincipalNotFound
	}

	// Update timestamps
	principal.UpdatedAt = time.Now()

	// Remove old indexes
	if existing.Fingerprint != "" && existing.Fingerprint != principal.Fingerprint {
		delete(s.principalsByFprint, existing.Fingerprint)
	}
	if existing.GitHubID != nil && (principal.GitHubID == nil || *existing.GitHubID != *principal.GitHubID) {
		delete(s.principalsByGitHub, *existing.GitHubID)
	}

	// Clone and store
	clone := *principal
	s.principals[principal.PrincipalID] = &clone

	// Update indexes
	if clone.Fingerprint != "" {
		s.principalsByFprint[clone.Fingerprint] = &clone
	}
	if clone.GitHubID != nil {
		s.principalsByGitHub[*clone.GitHubID] = &clone
	}

	return nil
}

// Delete soft-deletes a principal by setting deleted_at timestamp.
func (s *PrincipalStore) Delete(ctx context.Context, principalID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists || principal.DeletedAt != nil {
		return store.ErrPrincipalNotFound
	}

	// Update the principal with deleted timestamp
	now := time.Now()
	principal.DeletedAt = &now
	principal.UpdatedAt = now

	return nil
}

// ListByOrg returns all non-revoked principals for a given organization.
func (s *PrincipalStore) ListByOrg(ctx context.Context, orgID uuid.UUID, principalType *string) ([]*models.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.Principal
	for _, p := range s.principals {
		// Filter by org
		if p.OrgID != orgID {
			continue
		}

		// Skip deleted principals
		if p.DeletedAt != nil {
			continue
		}

		// Filter by type if specified
		if principalType != nil && p.Type != *principalType {
			continue
		}

		// Clone to avoid external modifications
		clone := *p
		result = append(result, &clone)
	}

	return result, nil
}

// ListRevoked returns all revoked principals (deleted_at IS NOT NULL).
func (s *PrincipalStore) ListRevoked(ctx context.Context) ([]*models.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.Principal
	for _, p := range s.principals {
		if p.DeletedAt != nil {
			// Clone to avoid external modifications
			clone := *p
			result = append(result, &clone)
		}
	}

	return result, nil
}

// UpdateLastUsed updates the last_used_at timestamp for a principal.
func (s *PrincipalStore) UpdateLastUsed(ctx context.Context, principalID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	principal, exists := s.principals[principalID]
	if !exists || principal.DeletedAt != nil {
		return store.ErrPrincipalNotFound
	}

	now := time.Now()
	principal.LastUsedAt = &now

	return nil
}
