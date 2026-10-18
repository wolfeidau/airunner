//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func contractReq(requestID, queue, command string) *jobv1.EnqueueJobRequest {
	return &jobv1.EnqueueJobRequest{
		RequestId: requestID,
		Queue:     queue,
		JobParams: &jobv1.JobParams{Repository: "https://github.com/test/contract", Command: command},
	}
}

func TestContract_EnqueueFingerprint(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	first, err := js.EnqueueJob(ctx, fx.User, contractReq("r1", "q", "echo"))
	require.NoError(t, err)

	t.Run("same intent returns same job", func(t *testing.T) {
		again, err := js.EnqueueJob(ctx, fx.User, contractReq("r1", "q", "echo"))
		require.NoError(t, err)
		require.Equal(t, first.JobId, again.JobId)
	})

	t.Run("changed params conflict", func(t *testing.T) {
		_, err := js.EnqueueJob(ctx, fx.User, contractReq("r1", "q", "ls"))
		require.ErrorIs(t, err, jobstore.ErrConflict)
	})

	t.Run("changed queue conflict", func(t *testing.T) {
		_, err := js.EnqueueJob(ctx, fx.User, contractReq("r1", "other", "echo"))
		require.ErrorIs(t, err, jobstore.ErrConflict)
	})

	t.Run("changed max attempts conflict", func(t *testing.T) {
		req := contractReq("r1", "q", "echo")
		n := int32(5)
		req.MaxAttempts = &n
		_, err := js.EnqueueJob(ctx, fx.User, req)
		require.ErrorIs(t, err, jobstore.ErrConflict)
	})

	t.Run("invalid max attempts", func(t *testing.T) {
		for _, n := range []int32{0, -1, 101} {
			req := contractReq("bad", "q", "echo")
			req.MaxAttempts = &n
			_, err := js.EnqueueJob(ctx, fx.User, req)
			require.Error(t, err)
			require.NotErrorIs(t, err, jobstore.ErrConflict)
		}
	})
}

func TestContract_SameRequestIDAcrossOrgs(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	other := seedOrg(t, js)

	a, err := js.EnqueueJob(ctx, fx.User, contractReq("shared", "q", "echo"))
	require.NoError(t, err)
	b, err := js.EnqueueJob(ctx, other.User, contractReq("shared", "q", "ls"))
	require.NoError(t, err)
	require.NotEqual(t, a.JobId, b.JobId)
}

func TestContract_OrgIsolation(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)
	other := seedOrg(t, js)

	enq, err := js.EnqueueJob(ctx, fx.User, contractReq("iso", "q", "echo"))
	require.NoError(t, err)

	list, err := js.ListJobs(ctx, other.User, &jobv1.ListJobsRequest{Queue: "q"})
	require.NoError(t, err)
	require.Empty(t, list.Jobs)

	jobs, err := js.DequeueJobs(ctx, other.Worker, "q", 10, 300)
	require.NoError(t, err)
	require.Empty(t, jobs)

	_, err = js.StreamEvents(ctx, other.User, enq.JobId, 0, 0, 0, nil)
	require.ErrorIs(t, err, jobstore.ErrJobNotFound)

	// The owning org still sees and can dequeue its job.
	list, err = js.ListJobs(ctx, fx.User, &jobv1.ListJobsRequest{Queue: "q"})
	require.NoError(t, err)
	require.Len(t, list.Jobs, 1)

	jobs, err = js.DequeueJobs(ctx, fx.Worker, "q", 10, 300)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	// A token from one org cannot be used by another.
	_, err = js.UpdateJobVisibility(ctx, other.Worker, jobs[0].TaskToken, 60)
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	err = js.CompleteJob(ctx, other.Worker, jobs[0].TaskToken, &jobv1.JobResult{JobId: jobs[0].Job.JobId, Success: true}, 0)
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
}

func TestContract_DequeueAttempts(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	_, err := js.EnqueueJob(ctx, fx.User, contractReq("att", "q", "echo"))
	require.NoError(t, err)

	jobs, err := js.DequeueJobs(ctx, fx.Worker, "q", 1, 120)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.Equal(t, int32(1), jobs[0].Job.Attempt)
	require.Equal(t, int32(3), jobs[0].Job.MaxAttempts, "default max_attempts")
	require.Equal(t, int32(120), jobs[0].VisibilityTimeoutSeconds)

	var leasedBy string
	require.NoError(t, js.pool.QueryRow(ctx, `SELECT leased_by::text FROM jobs WHERE job_id = $1`, jobs[0].Job.JobId).Scan(&leasedBy))
	require.Equal(t, fx.Worker.PrincipalID.String(), leasedBy)

	require.NoError(t, js.ReleaseJob(ctx, fx.Worker, jobs[0].TaskToken))

	jobs, err = js.DequeueJobs(ctx, fx.Worker, "q", 1, 120)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.Equal(t, int32(2), jobs[0].Job.Attempt)
}

func TestContract_ExplicitMaxAttempts(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	req := contractReq("max", "q", "echo")
	n := int32(1)
	req.MaxAttempts = &n
	_, err := js.EnqueueJob(ctx, fx.User, req)
	require.NoError(t, err)

	jobs, err := js.DequeueJobs(ctx, fx.Worker, "q", 1, 60)
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	require.Equal(t, int32(1), jobs[0].Job.MaxAttempts)

	// Releasing with no attempts left fails the job rather than stranding it as SCHEDULED.
	require.NoError(t, js.ReleaseJob(ctx, fx.Worker, jobs[0].TaskToken))
	var state int32
	require.NoError(t, js.pool.QueryRow(ctx, `SELECT state FROM jobs WHERE job_id = $1`, jobs[0].Job.JobId).Scan(&state))
	require.Equal(t, int32(jobv1.JobState_JOB_STATE_FAILED), state)
}

func TestContract_DequeueSkipsExhaustedJob(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	enq, err := js.EnqueueJob(ctx, fx.User, contractReq("exh", "q", "echo"))
	require.NoError(t, err)

	_, err = js.pool.Exec(ctx, `UPDATE jobs SET attempt = max_attempts WHERE job_id = $1 AND state = 1`, enq.JobId)
	require.NoError(t, err)

	jobs, err := js.DequeueJobs(ctx, fx.Worker, "q", 1, 60)
	require.NoError(t, err)
	require.Empty(t, jobs)
}

func TestContract_LeaseCheckConstraint(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	enq, err := js.EnqueueJob(ctx, fx.User, contractReq("chk", "q", "echo"))
	require.NoError(t, err)

	requireCheckViolation := func(err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code)
	}

	t.Run("update to RUNNING without leased_by", func(t *testing.T) {
		_, err := js.pool.Exec(ctx, `
			UPDATE jobs SET state = 2, attempt = 1, visibility_until = NOW(), receipt_handle = gen_random_uuid()
			WHERE job_id = $1`, enq.JobId)
		requireCheckViolation(err)
	})

	t.Run("insert RUNNING without leased_by", func(t *testing.T) {
		_, err := js.pool.Exec(ctx, `
			INSERT INTO jobs (job_id, org_id, created_by, queue, state, request_id, request_fingerprint,
				attempt, max_attempts, created_at, updated_at, job_params, visibility_until, receipt_handle)
			VALUES (gen_random_uuid(), $1, $2, 'q', 2, 'raw', '\x00', 1, 3, NOW(), NOW(), '{}', NOW(), gen_random_uuid())`,
			fx.Org, fx.User.PrincipalID)
		requireCheckViolation(err)
	})

	t.Run("SCHEDULED with leased_by", func(t *testing.T) {
		_, err := js.pool.Exec(ctx, `UPDATE jobs SET leased_by = $2 WHERE job_id = $1`, enq.JobId, fx.Worker.PrincipalID)
		requireCheckViolation(err)
	})
}

func TestContract_MigrationsIdempotent(t *testing.T) {
	ctx := context.Background()
	js, _ := setupStore(t)

	require.NoError(t, RunMigrations(ctx, js.pool))

	var count int
	require.NoError(t, js.pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count))
	require.Equal(t, 2, count)
}

func TestContract_PublishStampsAttempt(t *testing.T) {
	ctx := context.Background()
	js, fx := setupStore(t)

	_, err := js.EnqueueJob(ctx, fx.User, contractReq("pub", "q", "echo"))
	require.NoError(t, err)
	jobs, err := js.DequeueJobs(ctx, fx.Worker, "q", 1, 60)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	res, err := js.PublishEvents(ctx, fx.Worker, jobs[0].TaskToken, []*jobv1.JobEvent{
		{Attempt: 1, Sequence: 1, Timestamp: timestamppb.Now(), EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START},
		{Attempt: 1, Sequence: 2, Timestamp: timestamppb.Now(), EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH, EventData: &jobv1.JobEvent_OutputBatch{
			OutputBatch: &jobv1.OutputBatchEvent{StartSequence: 2, EndSequence: 5, Outputs: outputItems(4)},
		}},
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), res.Attempt)
	require.Equal(t, int64(5), res.AcknowledgedThroughSequence)

	rows, err := js.pool.Query(ctx, `SELECT attempt, sequence, end_sequence FROM job_events WHERE job_id = $1 ORDER BY sequence`, jobs[0].Job.JobId)
	require.NoError(t, err)
	defer rows.Close()
	var got [][3]int64
	for rows.Next() {
		var a int32
		var seq, end int64
		require.NoError(t, rows.Scan(&a, &seq, &end))
		got = append(got, [3]int64{int64(a), seq, end})
	}
	require.Equal(t, [][3]int64{{1, 1, 1}, {1, 2, 5}}, got)
}
