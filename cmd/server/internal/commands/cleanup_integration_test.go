//go:build integration

package commands

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
	"github.com/wolfeidau/airunner/internal/testutil/pgtest"
)

const testSecret = "test-secret-key-min-32-bytes-long"

func cleanupCmd(connString string) *CleanupCmd {
	return &CleanupCmd{
		Retention:  RetentionFlags{JobRetentionDays: 90, EventsRetentionDays: 30},
		MaxBatches: 100,
		PostgresStore: PostgresStoreFlags{
			ConnString:         connString,
			TokenSigningSecret: testSecret,
			DefaultMaxAttempts: 3,
			MaxConns:           4,
			MinConns:           1,
			MaxConnLifetime:    3600,
			MaxConnIdleTime:    1800,
		},
	}
}

func TestCleanupCmd_DeletesAgedJob(t *testing.T) {
	ctx := context.Background()
	connString := pgtest.NewDatabase(t)

	pool, err := postgres.NewPool(ctx, &postgres.PoolConfig{ConnString: connString})
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.RunMigrations(ctx, pool))

	jobs, err := postgres.NewJobStore(pool, &postgres.JobStoreConfig{TokenSigningSecret: []byte(testSecret), DisableRetentionLoop: true})
	require.NoError(t, err)
	stores := &postgrestest.Stores{Pool: pool, Jobs: jobs, Principals: postgres.NewPrincipalStore(pool), Orgs: postgres.NewOrganizationStore(pool)}
	fx := postgrestest.SeedOrg(t, stores)

	old, err := jobs.EnqueueJob(ctx, fx.User, &jobv1.EnqueueJobRequest{Queue: "q", RequestId: "old"})
	require.NoError(t, err)
	recent, err := jobs.EnqueueJob(ctx, fx.User, &jobv1.EnqueueJobRequest{Queue: "q", RequestId: "recent"})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE jobs SET state = 3, updated_at = now() - interval '100 days' WHERE job_id = $1`, old.JobId)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE jobs SET state = 3 WHERE job_id = $1`, recent.JobId)
	require.NoError(t, err)

	require.NoError(t, cleanupCmd(connString).Run(&Globals{}))

	var remaining []string
	rows, err := pool.Query(ctx, `SELECT job_id FROM jobs`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		remaining = append(remaining, id)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{recent.JobId}, remaining)
}

func TestCleanupCmd_InvalidFlags(t *testing.T) {
	tests := map[string]func(*CleanupCmd){
		"job retention":   func(c *CleanupCmd) { c.Retention.JobRetentionDays = 0 },
		"events negative": func(c *CleanupCmd) { c.Retention.EventsRetentionDays = -1 },
		"max batches":     func(c *CleanupCmd) { c.MaxBatches = 0 },
		"no secret":       func(c *CleanupCmd) { c.PostgresStore.TokenSigningSecret = "" },
	}
	for name, mutate := range tests {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			c := cleanupCmd("postgres://unused")
			mutate(c)
			require.Error(t, c.Run(&Globals{}))
		})
	}
}
