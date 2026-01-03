package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/wolfeidau/airunner/internal/models"
)

// Sentinel errors for principal store operations
var (
	ErrPrincipalNotFound      = errors.New("principal not found")
	ErrPrincipalAlreadyExists = errors.New("principal already exists")
	ErrInvalidPrincipalType   = errors.New("invalid principal type")
)

// PrincipalStore defines the interface for principal storage operations.
// Principals represent identities in the system (users, workers, services).
type PrincipalStore interface {
	// Create creates a new principal in the store.
	// Returns ErrPrincipalAlreadyExists if a principal with the same ID already exists.
	Create(ctx context.Context, principal *models.Principal) error

	// Get retrieves a principal by ID.
	// Returns ErrPrincipalNotFound if the principal doesn't exist.
	Get(ctx context.Context, principalID uuid.UUID) (*models.Principal, error)

	// GetByFingerprint retrieves a worker/service principal by public key fingerprint.
	// Returns ErrPrincipalNotFound if the principal doesn't exist.
	// Only matches non-revoked principals (deleted_at IS NULL).
	GetByFingerprint(ctx context.Context, fingerprint string) (*models.Principal, error)

	// GetByGitHubID retrieves a user principal by GitHub user ID.
	// Returns ErrPrincipalNotFound if the principal doesn't exist.
	// Only matches non-revoked principals (deleted_at IS NULL).
	GetByGitHubID(ctx context.Context, githubID string) (*models.Principal, error)

	// Update updates an existing principal.
	// Returns ErrPrincipalNotFound if the principal doesn't exist.
	Update(ctx context.Context, principal *models.Principal) error

	// Delete soft-deletes a principal by setting deleted_at timestamp.
	// This is used for revocation tracking.
	// Returns ErrPrincipalNotFound if the principal doesn't exist.
	Delete(ctx context.Context, principalID uuid.UUID) error

	// ListByOrg returns all principals for a given organization.
	// If principalType is provided, filters by type ("user", "worker", "service").
	// Only returns non-revoked principals (deleted_at IS NULL).
	ListByOrg(ctx context.Context, orgID uuid.UUID, principalType *string) ([]*models.Principal, error)

	// ListRevoked returns all revoked principals (deleted_at IS NOT NULL).
	// Used by PrincipalService.ListRevokedPrincipals for revocation list.
	ListRevoked(ctx context.Context) ([]*models.Principal, error)

	// UpdateLastUsed updates the last_used_at timestamp for a principal.
	// This is called during authentication to track principal activity.
	UpdateLastUsed(ctx context.Context, principalID uuid.UUID) error
}
