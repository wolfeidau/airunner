//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestMigration2_PrincipalOrgFKs(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	other := seedOrg(t, js)

	enq, err := js.EnqueueJob(ctx, fx.User, &jobv1.EnqueueJobRequest{
		RequestId: "fk-1", Queue: "q", JobParams: &jobv1.JobParams{Repository: "r"},
	})
	require.NoError(t, err)
	jobs, err := js.DequeueJobs(ctx, fx.Worker, "q", 1, 300)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	requireFKViolation := func(constraint string, err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, pgerrcode.ForeignKeyViolation, pgErr.Code)
		require.Equal(t, constraint, pgErr.ConstraintName)
	}

	// Creator from another org
	_, err = js.pool.Exec(ctx, `UPDATE jobs SET created_by = $1 WHERE job_id = $2`, other.User.PrincipalID, enq.JobId)
	requireFKViolation("jobs_created_by_org_fkey", err)

	// Leaser from another org
	_, err = js.pool.Exec(ctx, `UPDATE jobs SET leased_by = $1 WHERE job_id = $2`, other.Worker.PrincipalID, enq.JobId)
	requireFKViolation("jobs_leased_by_org_fkey", err)

	// Same-org principals and NULL leased_by (non-RUNNING) are accepted
	_, err = js.pool.Exec(ctx, `UPDATE jobs SET created_by = $1 WHERE job_id = $2`, fx.Worker.PrincipalID, enq.JobId)
	require.NoError(t, err)

	// The single-column FKs are gone
	var n int
	require.NoError(t, js.pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_constraint WHERE conname IN ('jobs_created_by_fkey', 'jobs_leased_by_fkey')`).Scan(&n))
	require.Zero(t, n)
}
