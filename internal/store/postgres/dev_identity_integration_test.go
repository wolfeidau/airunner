//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
)

func TestSeedDevIdentity_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := postgrestest.NewStores(t)

	c1, err := postgres.SeedDevIdentity(ctx, s.Pool)
	require.NoError(t, err)
	c2, err := postgres.SeedDevIdentity(ctx, s.Pool)
	require.NoError(t, err)
	require.Equal(t, c1, c2)
	require.Equal(t, postgres.DevOrgID, c1.OrgID)
	require.Equal(t, postgres.DevPrincipalID, c1.PrincipalID)

	var n int
	require.NoError(t, s.Pool.QueryRow(ctx, `SELECT count(*) FROM principals WHERE org_id = $1`, postgres.DevOrgID).Scan(&n))
	require.Equal(t, 1, n)
}

func TestSeedDevIdentity_ConflictingOrgOwner(t *testing.T) {
	ctx := context.Background()
	s := postgrestest.NewStores(t)

	_, err := s.Pool.Exec(ctx, `INSERT INTO organizations (org_id, name, owner_principal_id) VALUES ($1, 'other', gen_random_uuid())`, postgres.DevOrgID)
	require.NoError(t, err)

	_, err = postgres.SeedDevIdentity(ctx, s.Pool)
	require.Error(t, err)
}

func TestSeedDevIdentity_ConflictingPrincipal(t *testing.T) {
	ctx := context.Background()
	s := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, s)

	_, err := s.Pool.Exec(ctx, `INSERT INTO principals (principal_id, org_id, type, name, github_id, roles) VALUES ($1, $2, 'user', 'x', 'dev', '{user}')`,
		postgres.DevPrincipalID, fx.Org)
	require.NoError(t, err)

	_, err = postgres.SeedDevIdentity(ctx, s.Pool)
	require.Error(t, err)
}
