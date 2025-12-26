package store

import (
	"context"
	"errors"
	"time"
)

// Errors
var (
	ErrPrincipalNotFound      = errors.New("principal not found")
	ErrPrincipalAlreadyExists = errors.New("principal already exists")
	ErrPrincipalSuspended     = errors.New("principal is suspended")
	ErrPrincipalDeleted       = errors.New("principal is deleted")
)

// PrincipalType represents the type of principal
type PrincipalType string

const (
	PrincipalTypeAdmin   PrincipalType = "admin"
	PrincipalTypeWorker  PrincipalType = "worker"
	PrincipalTypeUser    PrincipalType = "user"
	PrincipalTypeService PrincipalType = "service"
)

// PrincipalStatus represents the status of a principal
type PrincipalStatus string

const (
	PrincipalStatusActive    PrincipalStatus = "active"
	PrincipalStatusSuspended PrincipalStatus = "suspended"
	PrincipalStatusDeleted   PrincipalStatus = "deleted"
)

// PrincipalMetadata represents metadata about a principal
type PrincipalMetadata struct {
	PrincipalID     string            `dynamodbav:"principal_id"`
	Type            PrincipalType     `dynamodbav:"type"`
	Status          PrincipalStatus   `dynamodbav:"status"`
	CreatedAt       time.Time         `dynamodbav:"created_at"`
	CreatedBy       string            `dynamodbav:"created_by"`
	SuspendedAt     *time.Time        `dynamodbav:"suspended_at,omitempty"`
	SuspendedReason string            `dynamodbav:"suspended_reason,omitempty"`
	Email           string            `dynamodbav:"email,omitempty"`
	Description     string            `dynamodbav:"description,omitempty"`
	MaxCertificates int               `dynamodbav:"max_certificates,omitempty"`
	Metadata        map[string]string `dynamodbav:"metadata,omitempty"`
}

// PrincipalStore manages principal metadata
type PrincipalStore interface {
	// Get retrieves principal metadata by ID
	Get(ctx context.Context, principalID string) (*PrincipalMetadata, error)

	// Create creates a new principal
	Create(ctx context.Context, principal *PrincipalMetadata) error

	// Update updates principal metadata
	Update(ctx context.Context, principal *PrincipalMetadata) error

	// Suspend suspends a principal
	Suspend(ctx context.Context, principalID string, reason string) error

	// Activate activates a suspended principal
	Activate(ctx context.Context, principalID string) error

	// Delete soft-deletes a principal
	Delete(ctx context.Context, principalID string) error

	// List returns principals matching filters
	List(ctx context.Context, opts ListPrincipalsOptions) ([]*PrincipalMetadata, error)
}

// ListPrincipalsOptions specifies filters for listing principals
type ListPrincipalsOptions struct {
	Type   PrincipalType   // Filter by type (empty = all)
	Status PrincipalStatus // Filter by status (empty = all)
	Limit  int             // Max results (0 = default)
}
