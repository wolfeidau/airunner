package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfeidau/airunner/internal/store"
)

// Reserved identifiers for the --no-auth development identity.
var (
	DevOrgID       = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	DevPrincipalID = uuid.MustParse("00000000-0000-7000-8000-000000000002")
)

const (
	devGitHubID = "dev"
	devName     = "dev"
)

// DevRoles are the roles granted to the development principal.
var DevRoles = []string{"admin", "user", "worker"}

// SeedDevIdentity idempotently creates the reserved development organization and
// user principal in one transaction and returns the matching caller. It fails when
// a reserved row exists with conflicting content.
func SeedDevIdentity(ctx context.Context, pool *pgxpool.Pool) (store.Caller, error) {
	caller := store.Caller{OrgID: DevOrgID, PrincipalID: DevPrincipalID}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return store.Caller{}, fmt.Errorf("begin dev identity seed: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (org_id, name, owner_principal_id)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, DevOrgID, devName, DevPrincipalID); err != nil {
		return store.Caller{}, fmt.Errorf("seed dev organization: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO principals (principal_id, org_id, type, name, github_id, roles)
		VALUES ($1, $2, 'user', $3, $4, $5)
		ON CONFLICT DO NOTHING`, DevPrincipalID, DevOrgID, devName, devGitHubID, DevRoles); err != nil {
		return store.Caller{}, fmt.Errorf("seed dev principal: %w", err)
	}

	var owner uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT owner_principal_id FROM organizations WHERE org_id = $1`, DevOrgID).Scan(&owner); err != nil {
		return store.Caller{}, fmt.Errorf("verify dev organization: %w", err)
	}
	if owner != DevPrincipalID {
		return store.Caller{}, fmt.Errorf("reserved dev organization %s has conflicting owner %s", DevOrgID, owner)
	}

	var (
		orgID    uuid.UUID
		typ      string
		githubID *string
	)
	err = tx.QueryRow(ctx, `SELECT org_id, type, github_id FROM principals WHERE principal_id = $1`, DevPrincipalID).Scan(&orgID, &typ, &githubID)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Caller{}, fmt.Errorf("reserved dev principal %s could not be created (github_id %q already in use?)", DevPrincipalID, devGitHubID)
	}
	if err != nil {
		return store.Caller{}, fmt.Errorf("verify dev principal: %w", err)
	}
	if orgID != DevOrgID || typ != "user" || githubID == nil || *githubID != devGitHubID {
		return store.Caller{}, fmt.Errorf("reserved dev principal %s has conflicting content", DevPrincipalID)
	}

	if err := tx.Commit(ctx); err != nil {
		return store.Caller{}, fmt.Errorf("commit dev identity seed: %w", err)
	}
	return caller, nil
}
