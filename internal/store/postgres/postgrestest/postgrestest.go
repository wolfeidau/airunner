//go:build integration

// Package postgrestest provides PostgreSQL-backed store fixtures for integration tests.
package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/testutil/pgtest"
)

// Stores bundles the PostgreSQL stores built on one isolated test database.
type Stores struct {
	Pool       *pgxpool.Pool
	Jobs       *postgres.JobStore
	Principals *postgres.PrincipalStore
	Orgs       *postgres.OrganizationStore
}

// Fixture describes an organization seeded with a user and a worker principal.
type Fixture struct {
	Org    uuid.UUID
	User   store.Caller
	Worker store.Caller
}

// NewStores creates an isolated database, runs migrations and starts a job store.
// Cleanup stops the store and closes the pool.
func NewStores(t testing.TB) *Stores {
	t.Helper()
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, &postgres.PoolConfig{ConnString: pgtest.NewDatabase(t)})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, postgres.RunMigrations(ctx, pool))

	jobs, err := postgres.NewJobStore(pool, &postgres.JobStoreConfig{
		TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
	})
	require.NoError(t, err)
	require.NoError(t, jobs.Start())
	t.Cleanup(func() { _ = jobs.Stop() })

	return &Stores{
		Pool:       pool,
		Jobs:       jobs,
		Principals: postgres.NewPrincipalStore(pool),
		Orgs:       postgres.NewOrganizationStore(pool),
	}
}

// SeedOrg creates an organization with a user principal (owner) and a worker principal.
func SeedOrg(t testing.TB, s *Stores) Fixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	orgID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	workerID := uuid.Must(uuid.NewV7())

	require.NoError(t, s.Orgs.Create(ctx, &models.Organization{
		OrgID:            orgID,
		Name:             "test-org-" + orgID.String(),
		OwnerPrincipalID: userID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}))

	githubID := "gh-" + userID.String()
	require.NoError(t, s.Principals.Create(ctx, &models.Principal{
		PrincipalID: userID,
		OrgID:       orgID,
		Type:        "user",
		Name:        "test-user",
		GitHubID:    &githubID,
		Roles:       []string{"user"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	require.NoError(t, s.Principals.Create(ctx, &models.Principal{
		PrincipalID: workerID,
		OrgID:       orgID,
		Type:        "worker",
		Name:        "test-worker",
		Fingerprint: "fp-" + workerID.String(),
		Roles:       []string{"worker"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	return Fixture{
		Org:    orgID,
		User:   store.Caller{OrgID: orgID, PrincipalID: userID},
		Worker: store.Caller{OrgID: orgID, PrincipalID: workerID},
	}
}
