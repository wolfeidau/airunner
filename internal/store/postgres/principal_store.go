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

// PrincipalStore implements store.PrincipalStore using PostgreSQL.
type PrincipalStore struct {
	pool *pgxpool.Pool
}

// NewPrincipalStore creates a new PostgreSQL-backed principal store.
// It shares the connection pool with other stores.
func NewPrincipalStore(pool *pgxpool.Pool) *PrincipalStore {
	return &PrincipalStore{
		pool: pool,
	}
}

// Create creates a new principal in the database.
func (s *PrincipalStore) Create(ctx context.Context, principal *models.Principal) error {
	query := `
		INSERT INTO principals (
			principal_id, org_id, type, name,
			github_id, github_login, email, avatar_url,
			public_key, public_key_der, fingerprint,
			roles, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`

	// Convert empty strings to NULL for optional fields (to satisfy DB constraints)
	var publicKey, fingerprint any
	if principal.PublicKey == "" {
		publicKey = nil
	} else {
		publicKey = principal.PublicKey
	}
	if principal.Fingerprint == "" {
		fingerprint = nil
	} else {
		fingerprint = principal.Fingerprint
	}

	var publicKeyDER any
	if len(principal.PublicKeyDER) == 0 {
		publicKeyDER = nil
	} else {
		publicKeyDER = principal.PublicKeyDER
	}

	_, err := s.pool.Exec(ctx, query,
		principal.PrincipalID,
		principal.OrgID,
		principal.Type,
		principal.Name,
		principal.GitHubID,
		principal.GitHubLogin,
		principal.Email,
		principal.AvatarURL,
		publicKey,
		publicKeyDER,
		fingerprint,
		principal.Roles,
		principal.CreatedAt,
		principal.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrPrincipalAlreadyExists
		}
		return fmt.Errorf("failed to create principal: %w", err)
	}

	log.Debug().
		Str("principal_id", principal.PrincipalID.String()).
		Str("type", principal.Type).
		Str("org_id", principal.OrgID.String()).
		Msg("Created principal")

	return nil
}

// Get retrieves a principal by ID.
func (s *PrincipalStore) Get(ctx context.Context, principalID uuid.UUID) (*models.Principal, error) {
	query := `
		SELECT
			principal_id, org_id, type, name,
			github_id, github_login, email, avatar_url,
			public_key, public_key_der, fingerprint,
			roles, created_at, updated_at, last_used_at, deleted_at
		FROM principals
		WHERE principal_id = $1
	`

	var p models.Principal
	var publicKey, publicKeyDER, fingerprint any
	err := s.pool.QueryRow(ctx, query, principalID).Scan(
		&p.PrincipalID,
		&p.OrgID,
		&p.Type,
		&p.Name,
		&p.GitHubID,
		&p.GitHubLogin,
		&p.Email,
		&p.AvatarURL,
		&publicKey,
		&publicKeyDER,
		&fingerprint,
		&p.Roles,
		&p.CreatedAt,
		&p.UpdatedAt,
		&p.LastUsedAt,
		&p.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	// Convert NULL values from database to Go zero values
	if publicKey != nil {
		p.PublicKey = publicKey.(string)
	}
	if publicKeyDER != nil {
		p.PublicKeyDER = publicKeyDER.([]byte)
	}
	if fingerprint != nil {
		p.Fingerprint = fingerprint.(string)
	}

	return &p, nil
}

// GetByFingerprint retrieves a non-revoked worker/service principal by fingerprint.
func (s *PrincipalStore) GetByFingerprint(ctx context.Context, fingerprint string) (*models.Principal, error) {
	query := `
		SELECT
			principal_id, org_id, type, name,
			github_id, github_login, email, avatar_url,
			public_key, public_key_der, fingerprint,
			roles, created_at, updated_at, last_used_at, deleted_at
		FROM principals
		WHERE fingerprint = $1 AND deleted_at IS NULL
	`

	var p models.Principal
	var publicKey, publicKeyDER, fingerprint_val any
	err := s.pool.QueryRow(ctx, query, fingerprint).Scan(
		&p.PrincipalID,
		&p.OrgID,
		&p.Type,
		&p.Name,
		&p.GitHubID,
		&p.GitHubLogin,
		&p.Email,
		&p.AvatarURL,
		&publicKey,
		&publicKeyDER,
		&fingerprint_val,
		&p.Roles,
		&p.CreatedAt,
		&p.UpdatedAt,
		&p.LastUsedAt,
		&p.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("failed to get principal by fingerprint: %w", err)
	}

	// Convert NULL values from database to Go zero values
	if publicKey != nil {
		p.PublicKey = publicKey.(string)
	}
	if publicKeyDER != nil {
		p.PublicKeyDER = publicKeyDER.([]byte)
	}
	if fingerprint_val != nil {
		p.Fingerprint = fingerprint_val.(string)
	}

	return &p, nil
}

// GetByGitHubID retrieves a non-revoked user principal by GitHub ID.
func (s *PrincipalStore) GetByGitHubID(ctx context.Context, githubID string) (*models.Principal, error) {
	query := `
		SELECT
			principal_id, org_id, type, name,
			github_id, github_login, email, avatar_url,
			public_key, public_key_der, fingerprint,
			roles, created_at, updated_at, last_used_at, deleted_at
		FROM principals
		WHERE github_id = $1 AND deleted_at IS NULL
	`

	var p models.Principal
	var publicKey, publicKeyDER, fingerprint any
	err := s.pool.QueryRow(ctx, query, githubID).Scan(
		&p.PrincipalID,
		&p.OrgID,
		&p.Type,
		&p.Name,
		&p.GitHubID,
		&p.GitHubLogin,
		&p.Email,
		&p.AvatarURL,
		&publicKey,
		&publicKeyDER,
		&fingerprint,
		&p.Roles,
		&p.CreatedAt,
		&p.UpdatedAt,
		&p.LastUsedAt,
		&p.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("failed to get principal by GitHub ID: %w", err)
	}

	// Convert NULL values from database to Go zero values
	if publicKey != nil {
		p.PublicKey = publicKey.(string)
	}
	if publicKeyDER != nil {
		p.PublicKeyDER = publicKeyDER.([]byte)
	}
	if fingerprint != nil {
		p.Fingerprint = fingerprint.(string)
	}

	return &p, nil
}

// Update updates an existing principal.
func (s *PrincipalStore) Update(ctx context.Context, principal *models.Principal) error {
	principal.UpdatedAt = time.Now()

	query := `
		UPDATE principals SET
			org_id = $2,
			type = $3,
			name = $4,
			github_id = $5,
			github_login = $6,
			email = $7,
			avatar_url = $8,
			public_key = $9,
			public_key_der = $10,
			fingerprint = $11,
			roles = $12,
			updated_at = $13,
			last_used_at = $14,
			deleted_at = $15
		WHERE principal_id = $1
	`

	// Convert empty strings to NULL for optional fields (to satisfy DB constraints)
	var publicKey, fingerprint any
	if principal.PublicKey == "" {
		publicKey = nil
	} else {
		publicKey = principal.PublicKey
	}
	if principal.Fingerprint == "" {
		fingerprint = nil
	} else {
		fingerprint = principal.Fingerprint
	}

	var publicKeyDER any
	if len(principal.PublicKeyDER) == 0 {
		publicKeyDER = nil
	} else {
		publicKeyDER = principal.PublicKeyDER
	}

	result, err := s.pool.Exec(ctx, query,
		principal.PrincipalID,
		principal.OrgID,
		principal.Type,
		principal.Name,
		principal.GitHubID,
		principal.GitHubLogin,
		principal.Email,
		principal.AvatarURL,
		publicKey,
		publicKeyDER,
		fingerprint,
		principal.Roles,
		principal.UpdatedAt,
		principal.LastUsedAt,
		principal.DeletedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update principal: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrPrincipalNotFound
	}

	log.Debug().
		Str("principal_id", principal.PrincipalID.String()).
		Msg("Updated principal")

	return nil
}

// Delete soft-deletes a principal by setting deleted_at timestamp.
func (s *PrincipalStore) Delete(ctx context.Context, principalID uuid.UUID) error {
	query := `
		UPDATE principals
		SET deleted_at = $2, updated_at = $2
		WHERE principal_id = $1 AND deleted_at IS NULL
	`

	now := time.Now()
	result, err := s.pool.Exec(ctx, query, principalID, now)
	if err != nil {
		return fmt.Errorf("failed to delete principal: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrPrincipalNotFound
	}

	log.Info().
		Str("principal_id", principalID.String()).
		Msg("Soft-deleted principal (revoked)")

	return nil
}

// ListByOrg returns all non-revoked principals for a given organization.
func (s *PrincipalStore) ListByOrg(ctx context.Context, orgID uuid.UUID, principalType *string) ([]*models.Principal, error) {
	query := `
		SELECT
			principal_id, org_id, type, name,
			github_id, github_login, email, avatar_url,
			public_key, public_key_der, fingerprint,
			roles, created_at, updated_at, last_used_at, deleted_at
		FROM principals
		WHERE org_id = $1 AND deleted_at IS NULL
	`

	args := []any{orgID}

	if principalType != nil {
		query += " AND type = $2"
		args = append(args, *principalType)
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list principals: %w", err)
	}
	defer rows.Close()

	var principals []*models.Principal
	for rows.Next() {
		var p models.Principal
		var publicKey, publicKeyDER, fingerprint any
		err := rows.Scan(
			&p.PrincipalID,
			&p.OrgID,
			&p.Type,
			&p.Name,
			&p.GitHubID,
			&p.GitHubLogin,
			&p.Email,
			&p.AvatarURL,
			&publicKey,
			&publicKeyDER,
			&fingerprint,
			&p.Roles,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.LastUsedAt,
			&p.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan principal: %w", err)
		}

		// Convert NULL values from database to Go zero values
		if publicKey != nil {
			p.PublicKey = publicKey.(string)
		}
		if publicKeyDER != nil {
			p.PublicKeyDER = publicKeyDER.([]byte)
		}
		if fingerprint != nil {
			p.Fingerprint = fingerprint.(string)
		}

		principals = append(principals, &p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating principals: %w", err)
	}

	return principals, nil
}

// ListRevoked returns all revoked principals (deleted_at IS NOT NULL).
func (s *PrincipalStore) ListRevoked(ctx context.Context) ([]*models.Principal, error) {
	query := `
		SELECT
			principal_id, org_id, type, name,
			github_id, github_login, email, avatar_url,
			public_key, public_key_der, fingerprint,
			roles, created_at, updated_at, last_used_at, deleted_at
		FROM principals
		WHERE deleted_at IS NOT NULL
		ORDER BY deleted_at DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list revoked principals: %w", err)
	}
	defer rows.Close()

	var principals []*models.Principal
	for rows.Next() {
		var p models.Principal
		var publicKey, publicKeyDER, fingerprint any
		err := rows.Scan(
			&p.PrincipalID,
			&p.OrgID,
			&p.Type,
			&p.Name,
			&p.GitHubID,
			&p.GitHubLogin,
			&p.Email,
			&p.AvatarURL,
			&publicKey,
			&publicKeyDER,
			&fingerprint,
			&p.Roles,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.LastUsedAt,
			&p.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan revoked principal: %w", err)
		}

		// Convert NULL values from database to Go zero values
		if publicKey != nil {
			p.PublicKey = publicKey.(string)
		}
		if publicKeyDER != nil {
			p.PublicKeyDER = publicKeyDER.([]byte)
		}
		if fingerprint != nil {
			p.Fingerprint = fingerprint.(string)
		}

		principals = append(principals, &p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating revoked principals: %w", err)
	}

	return principals, nil
}

// UpdateLastUsed updates the last_used_at timestamp for a principal.
func (s *PrincipalStore) UpdateLastUsed(ctx context.Context, principalID uuid.UUID) error {
	query := `
		UPDATE principals
		SET last_used_at = $2
		WHERE principal_id = $1 AND deleted_at IS NULL
	`

	now := time.Now()
	result, err := s.pool.Exec(ctx, query, principalID, now)
	if err != nil {
		return fmt.Errorf("failed to update last_used_at: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrPrincipalNotFound
	}

	return nil
}
