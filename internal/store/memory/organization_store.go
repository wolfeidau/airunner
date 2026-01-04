package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// OrganizationStore implements store.OrganizationStore using in-memory storage.
// This implementation is for testing only - data is lost on restart.
type OrganizationStore struct {
	mu sync.RWMutex

	organizations map[uuid.UUID]*models.Organization // org_id -> Organization
}

// NewOrganizationStore creates a new in-memory organization store.
func NewOrganizationStore() *OrganizationStore {
	return &OrganizationStore{
		organizations: make(map[uuid.UUID]*models.Organization),
	}
}

// Create creates a new organization in memory.
func (s *OrganizationStore) Create(ctx context.Context, org *models.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if organization already exists
	if _, exists := s.organizations[org.OrgID]; exists {
		return store.ErrOrganizationAlreadyExists
	}

	// Clone to avoid external modifications
	clone := *org
	s.organizations[org.OrgID] = &clone

	return nil
}

// Get retrieves an organization by ID.
func (s *OrganizationStore) Get(ctx context.Context, orgID uuid.UUID) (*models.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	org, exists := s.organizations[orgID]
	if !exists {
		return nil, store.ErrOrganizationNotFound
	}

	// Clone to avoid external modifications
	clone := *org
	return &clone, nil
}

// Update updates an existing organization.
func (s *OrganizationStore) Update(ctx context.Context, org *models.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.organizations[org.OrgID]; !exists {
		return store.ErrOrganizationNotFound
	}

	// Update timestamp
	org.UpdatedAt = time.Now()

	// Clone and store
	clone := *org
	s.organizations[org.OrgID] = &clone

	return nil
}

// Delete deletes an organization by ID.
// Note: In-memory implementation doesn't enforce cascade delete of principals.
// In real usage, this should be combined with deleting all principals first.
func (s *OrganizationStore) Delete(ctx context.Context, orgID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.organizations[orgID]; !exists {
		return store.ErrOrganizationNotFound
	}

	delete(s.organizations, orgID)

	return nil
}

// ListByOwner returns all organizations owned by a specific principal.
func (s *OrganizationStore) ListByOwner(ctx context.Context, ownerPrincipalID uuid.UUID) ([]*models.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.Organization
	for _, org := range s.organizations {
		if org.OwnerPrincipalID == ownerPrincipalID {
			// Clone to avoid external modifications
			clone := *org
			result = append(result, &clone)
		}
	}

	return result, nil
}
