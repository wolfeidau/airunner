package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// OrganizationStore implements store.OrganizationStore using PostgreSQL.
type OrganizationStore struct {
	pool *pgxpool.Pool
}

// NewOrganizationStore creates a new PostgreSQL-backed organization store.
// It shares the connection pool with other stores.
func NewOrganizationStore(pool *pgxpool.Pool) *OrganizationStore {
	return &OrganizationStore{
		pool: pool,
	}
}

// Create creates a new organization in the database.
func (s *OrganizationStore) Create(ctx context.Context, org *models.Organization) error {
	query := `
		INSERT INTO organizations (
			org_id, name, owner_principal_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5
		)
	`

	_, err := s.pool.Exec(ctx, query,
		org.OrgID,
		org.Name,
		org.OwnerPrincipalID,
		org.CreatedAt,
		org.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrOrganizationAlreadyExists
		}
		return fmt.Errorf("failed to create organization: %w", err)
	}

	log.Debug().
		Str("org_id", org.OrgID.String()).
		Str("name", org.Name).
		Msg("Created organization")

	return nil
}

// Get retrieves an organization by ID.
func (s *OrganizationStore) Get(ctx context.Context, orgID uuid.UUID) (*models.Organization, error) {
	query := `
		SELECT org_id, name, owner_principal_id, created_at, updated_at
		FROM organizations
		WHERE org_id = $1
	`

	var org models.Organization
	err := s.pool.QueryRow(ctx, query, orgID).Scan(
		&org.OrgID,
		&org.Name,
		&org.OwnerPrincipalID,
		&org.CreatedAt,
		&org.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	return &org, nil
}

// Update updates an existing organization.
func (s *OrganizationStore) Update(ctx context.Context, org *models.Organization) error {
	org.UpdatedAt = time.Now()

	query := `
		UPDATE organizations SET
			name = $2,
			owner_principal_id = $3,
			updated_at = $4
		WHERE org_id = $1
	`

	result, err := s.pool.Exec(ctx, query,
		org.OrgID,
		org.Name,
		org.OwnerPrincipalID,
		org.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrOrganizationNotFound
	}

	log.Debug().
		Str("org_id", org.OrgID.String()).
		Msg("Updated organization")

	return nil
}

// Delete deletes an organization by ID.
// This will cascade-delete all principals via FK constraint.
func (s *OrganizationStore) Delete(ctx context.Context, orgID uuid.UUID) error {
	query := `DELETE FROM organizations WHERE org_id = $1`

	result, err := s.pool.Exec(ctx, query, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrOrganizationNotFound
	}

	log.Info().
		Str("org_id", orgID.String()).
		Msg("Deleted organization (and cascade-deleted all principals)")

	return nil
}

// ListByOwner returns all organizations owned by a specific principal.
func (s *OrganizationStore) ListByOwner(ctx context.Context, ownerPrincipalID uuid.UUID) ([]*models.Organization, error) {
	query := `
		SELECT org_id, name, owner_principal_id, created_at, updated_at
		FROM organizations
		WHERE owner_principal_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query, ownerPrincipalID)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*models.Organization
	for rows.Next() {
		var org models.Organization
		err := rows.Scan(
			&org.OrgID,
			&org.Name,
			&org.OwnerPrincipalID,
			&org.CreatedAt,
			&org.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}
		orgs = append(orgs, &org)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating organizations: %w", err)
	}

	return orgs, nil
}
