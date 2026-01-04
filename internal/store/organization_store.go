package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/wolfeidau/airunner/internal/models"
)

// Sentinel errors for organization store operations
var (
	ErrOrganizationNotFound      = errors.New("organization not found")
	ErrOrganizationAlreadyExists = errors.New("organization already exists")
)

// OrganizationStore defines the interface for organization storage operations.
// Organizations represent tenants in the system, with each org containing multiple principals.
type OrganizationStore interface {
	// Create creates a new organization in the store.
	// Returns ErrOrganizationAlreadyExists if an organization with the same ID already exists.
	Create(ctx context.Context, org *models.Organization) error

	// Get retrieves an organization by ID.
	// Returns ErrOrganizationNotFound if the organization doesn't exist.
	Get(ctx context.Context, orgID uuid.UUID) (*models.Organization, error)

	// Update updates an existing organization.
	// Returns ErrOrganizationNotFound if the organization doesn't exist.
	Update(ctx context.Context, org *models.Organization) error

	// Delete deletes an organization by ID.
	// This will cascade-delete all principals belonging to the organization (via FK constraint).
	// Returns ErrOrganizationNotFound if the organization doesn't exist.
	Delete(ctx context.Context, orgID uuid.UUID) error

	// ListByOwner returns all organizations owned by a specific principal.
	// This is used to show all orgs a user has created.
	ListByOwner(ctx context.Context, ownerPrincipalID uuid.UUID) ([]*models.Organization, error)
}
