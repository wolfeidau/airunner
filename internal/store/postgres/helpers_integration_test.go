//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/models"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/testutil/pgtest"
)

// orgFixture is an organization with a user and a worker principal.
type orgFixture struct {
	Org    uuid.UUID
	User   jobstore.Caller
	Worker jobstore.Caller
}

// setupStore creates an isolated database with a started JobStore and one seeded org.
// It cannot use postgrestest because that package imports this one.
func setupStore(t testing.TB) (*JobStore, orgFixture) {
	t.Helper()
	ctx := context.Background()

	pool, err := NewPool(ctx, &PoolConfig{ConnString: pgtest.NewDatabase(t)})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, RunMigrations(ctx, pool))

	js, err := NewJobStore(pool, &JobStoreConfig{
		TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
	})
	require.NoError(t, err)
	require.NoError(t, js.Start())
	t.Cleanup(func() { _ = js.Stop() })

	return js, seedOrg(t, js)
}

// seedOrg creates another org with a user and worker principal in the store's database.
func seedOrg(t testing.TB, js *JobStore) orgFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	orgID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	workerID := uuid.Must(uuid.NewV7())

	require.NoError(t, NewOrganizationStore(js.pool).Create(ctx, &models.Organization{
		OrgID: orgID, Name: "org-" + orgID.String(), OwnerPrincipalID: userID, CreatedAt: now, UpdatedAt: now,
	}))

	principals := NewPrincipalStore(js.pool)
	githubID := "gh-" + userID.String()
	require.NoError(t, principals.Create(ctx, &models.Principal{
		PrincipalID: userID, OrgID: orgID, Type: "user", Name: "user", GitHubID: &githubID,
		Roles: []string{"user"}, CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, principals.Create(ctx, &models.Principal{
		PrincipalID: workerID, OrgID: orgID, Type: "worker", Name: "worker", Fingerprint: "fp-" + workerID.String(),
		Roles: []string{"worker"}, CreatedAt: now, UpdatedAt: now,
	}))

	return orgFixture{
		Org:    orgID,
		User:   jobstore.Caller{OrgID: orgID, PrincipalID: userID},
		Worker: jobstore.Caller{OrgID: orgID, PrincipalID: workerID},
	}
}
