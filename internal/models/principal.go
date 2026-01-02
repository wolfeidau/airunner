package models

import (
	"time"

	"github.com/google/uuid"
)

// PrincipalType represents the type of principal.
const (
	PrincipalTypeUser    = "user"    // Human user authenticated via GitHub OAuth
	PrincipalTypeWorker  = "worker"  // Worker/agent with public key credential
	PrincipalTypeService = "service" // Service account with public key credential
)

// Principal represents an identity in the system (user, worker, or service).
// Principals belong to an organization and have roles for authorization.
type Principal struct {
	PrincipalID uuid.UUID // UUIDv7
	OrgID       uuid.UUID // UUIDv7, FK to organizations
	Type        string    // "user", "worker", "service"
	Name        string    // Display name (e.g., "production-workers", "Jane Doe")

	// For user principals (GitHub OAuth)
	GitHubID    *string // GitHub user ID (numeric, as string)
	GitHubLogin *string // GitHub username (for org name, display)
	Email       *string // Primary email address
	AvatarURL   *string // GitHub avatar URL

	// For worker/service principals
	PublicKey    string // PEM format (for display/export)
	PublicKeyDER []byte // DER format (for JWT verification)
	Fingerprint  string // Base58-encoded SHA256(PublicKeyDER)

	// Authorization
	Roles []string // ["admin", "worker", "user", "readonly"]

	// Metadata
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
	DeletedAt  *time.Time // Soft delete for revocation tracking
}

// IsRevoked returns true if the principal has been soft-deleted (revoked).
func (p *Principal) IsRevoked() bool {
	return p.DeletedAt != nil
}
