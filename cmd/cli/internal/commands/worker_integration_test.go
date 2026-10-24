//go:build integration

package commands

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"github.com/wolfeidau/airunner/internal/worker/wal"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type workerEnv struct {
	stores  *postgrestest.Stores
	user    jobv1connect.JobServiceClient
	clients *client.Clients
	walCfg  *wal.WALConfig
}

func principalURL(t *testing.T, handler http.Handler, caller store.Caller, role string) string {
	t.Helper()
	p := &auth.Principal{PrincipalID: caller.PrincipalID, OrgID: caller.OrgID, Roles: []string{role}, Type: role}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	stores := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, stores)
	handler := server.NewServer(stores.Jobs).Handler()
	workerURL := principalURL(t, handler, fx.Worker, "worker")
	return &workerEnv{
		stores: stores,
		user:   jobv1connect.NewJobServiceClient(http.DefaultClient, principalURL(t, handler, fx.User, "user")),
		clients: &client.Clients{
			Job:    jobv1connect.NewJobServiceClient(http.DefaultClient, workerURL),
			Events: jobv1connect.NewJobEventsServiceClient(http.DefaultClient, workerURL),
		},
		walCfg: &wal.WALConfig{
			WALDir:            filepath.Join(t.TempDir(), "wal"),
			ArchiveDir:        filepath.Join(t.TempDir(), "archive"),
			FlushInterval:     20 * time.Millisecond,
			FlushPollInterval: 20 * time.Millisecond,
			ArchiveOnComplete: true,
			RetryBackoff:      wal.BackoffConfig{InitialInterval: 50 * time.Millisecond, MaxInterval: 200 * time.Millisecond, Multiplier: 2},
		},
	}
}

func (e *workerEnv) enqueueAndDequeue(t *testing.T, command string, args ...string) *jobv1.DequeueJobResponse {
	t.Helper()
	return e.enqueueAndDequeueVT(t, 30, command, args...)
}

func (e *workerEnv) enqueueAndDequeueVT(t *testing.T, visibilitySeconds int32, command string, args ...string) *jobv1.DequeueJobResponse {
	t.Helper()
	ctx := context.Background()
	_, err := e.user.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{
		RequestId: uuid.NewString(),
		Queue:     "q",
		JobParams: &jobv1.JobParams{Repository: "https://example.com/repo", Command: command, Args: args, ProcessType: jobv1.ProcessType_PROCESS_TYPE_PIPE},
	}))
	require.NoError(t, err)

	stream, err := e.clients.Job.DequeueJob(ctx, connect.NewRequest(&jobv1.DequeueJobRequest{Queue: "q", MaxJobs: 1, VisibilityTimeoutSeconds: visibilitySeconds}))
	require.NoError(t, err)
	defer stream.Close()
	require.True(t, stream.Receive(), "%v", stream.Err())
	return stream.Msg()
}

func (e *workerEnv) jobState(t *testing.T, jobID string) (state jobv1.JobState, lastSeq int64, result string) {
	t.Helper()
	var s int32
	var res *string
	err := e.stores.Pool.QueryRow(context.Background(),
		`SELECT state, last_event_sequence, result::text FROM jobs WHERE job_id = $1`, jobID).Scan(&s, &lastSeq, &res)
	require.NoError(t, err)
	if res != nil {
		result = *res
	}
	return jobv1.JobState(s), lastSeq, result
}

func (e *workerEnv) eventStats(t *testing.T, jobID string) (attempts, maxSeq int64) {
	t.Helper()
	err := e.stores.Pool.QueryRow(context.Background(),
		`SELECT COUNT(DISTINCT attempt), COALESCE(MAX(end_sequence), 0) FROM job_events WHERE job_id = $1`, jobID).Scan(&attempts, &maxSeq)
	require.NoError(t, err)
	return attempts, maxSeq
}

func requireNoWAL(t *testing.T, cfg *wal.WALConfig, jobID string) {
	t.Helper()
	_, err := os.Stat(filepath.Join(cfg.WALDir, jobID))
	require.ErrorIs(t, err, os.ErrNotExist, "WAL directory should be gone")
}

func TestRunJob_Success(t *testing.T) {
	e := newWorkerEnv(t)
	d := e.enqueueAndDequeue(t, "sh", "-c", "echo hello; echo world")
	jobID := d.Job.JobId

	w := &WorkerCmd{VisibilityTimeout: 30}
	require.NoError(t, w.runJob(context.Background(), e.clients, e.walCfg, d))

	state, lastSeq, _ := e.jobState(t, jobID)
	require.Equal(t, jobv1.JobState_JOB_STATE_COMPLETED, state)
	attempts, maxSeq := e.eventStats(t, jobID)
	require.Equal(t, int64(1), attempts, "events are recorded under attempt 1 only")
	require.Positive(t, maxSeq)
	require.Equal(t, maxSeq, lastSeq, "final sequence matches the recorded events")

	requireNoWAL(t, e.walCfg, jobID)
	archived, err := filepath.Glob(filepath.Join(e.walCfg.ArchiveDir, "*"+jobID+"*"))
	require.NoError(t, err)
	require.NotEmpty(t, archived, "completed WAL is archived")
}

func TestRunJob_LeaseLostAbortsExecution(t *testing.T) {
	e := newWorkerEnv(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	d := e.enqueueAndDequeue(t, "sh", "-c", "echo $$ > "+pidFile+"; exec sleep 60")
	jobID := d.Job.JobId

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- (&WorkerCmd{VisibilityTimeout: 30}).runJob(context.Background(), e.clients, e.walCfg, d)
	}()

	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil || len(strings.TrimSpace(string(b))) == 0 {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)

	// Expire the lease and reclaim it, as the server reaper would after a partition.
	_, err := e.stores.Pool.Exec(context.Background(),
		`UPDATE jobs SET visibility_until = clock_timestamp() - INTERVAL '1 second' WHERE job_id = $1`, jobID)
	require.NoError(t, err)
	n, err := e.stores.Jobs.ReapExpired(context.Background(), 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(40 * time.Second):
		t.Fatal("worker did not abort after lease loss")
	}
	t.Logf("worker aborted %s after start", time.Since(start))

	state, _, result := e.jobState(t, jobID)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, state, "job is redelivered, not completed (result=%s)", result)
	requireNoWAL(t, e.walCfg, jobID)

	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 10*time.Second, 100*time.Millisecond, "job process should be killed")
}

func TestRunJob_CancelStopsExecution(t *testing.T) {
	e := newWorkerEnv(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	d := e.enqueueAndDequeue(t, "sh", "-c", "echo $$ > "+pidFile+"; exec sleep 300")
	jobID := d.Job.JobId

	done := make(chan error, 1)
	go func() {
		done <- (&WorkerCmd{VisibilityTimeout: 30}).runJob(context.Background(), e.clients, e.walCfg, d)
	}()

	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil || len(strings.TrimSpace(string(b))) == 0 {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)

	cancelledAt := time.Now()
	resp, err := e.user.CancelJob(context.Background(), connect.NewRequest(&jobv1.CancelJobRequest{JobId: jobID}))
	require.NoError(t, err)
	require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, resp.Msg.State)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(40 * time.Second):
		t.Fatal("worker did not stop after cancel")
	}
	t.Logf("worker exited %s after cancel", time.Since(cancelledAt))

	state, _, result := e.jobState(t, jobID)
	require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, state, "job is never completed after cancel")
	require.Empty(t, result)
	requireNoWAL(t, e.walCfg, jobID)

	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 10*time.Second, 100*time.Millisecond, "job process should be killed")
}

type rejectingEvents struct {
	jobv1connect.JobEventsServiceClient
}

func (rejectingEvents) PublishJobEvents(context.Context, *connect.Request[jobv1.PublishJobEventsRequest]) (*connect.Response[jobv1.PublishJobEventsResponse], error) {
	return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("rejected"))
}

func TestRunJob_PermanentPublishErrorFailsJob(t *testing.T) {
	e := newWorkerEnv(t)
	d := e.enqueueAndDequeue(t, "sh", "-c", "echo hello")
	jobID := d.Job.JobId
	e.clients.Events = rejectingEvents{e.clients.Events}

	require.NoError(t, (&WorkerCmd{VisibilityTimeout: 30}).runJob(context.Background(), e.clients, e.walCfg, d))

	state, lastSeq, result := e.jobState(t, jobID)
	require.Equal(t, jobv1.JobState_JOB_STATE_FAILED, state)
	require.Zero(t, lastSeq, "final sequence is the acknowledged prefix")
	require.Contains(t, result, "event log incomplete")
	requireNoWAL(t, e.walCfg, jobID)
}

// chattyCommand prints a line every 200ms for about 300s and records its pid.
func chattyArgs(pidFile string) []string {
	return []string{"-c", "echo $$ > " + pidFile + "; i=0; while [ $i -lt 1500 ]; do echo line $i; i=$((i+1)); sleep 0.2; done"}
}

func waitPID(t *testing.T, pidFile string) int {
	t.Helper()
	var pid int
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil || len(strings.TrimSpace(string(b))) == 0 {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)
	return pid
}

func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}, 10*time.Second, 100*time.Millisecond, "job process should be killed")
}

func abandonedByReason(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, mm := range sm.Metrics {
			if mm.Name != "worker.jobs.abandoned" {
				continue
			}
			for _, dp := range mm.Data.(metricdata.Sum[int64]).DataPoints {
				v, _ := dp.Attributes.Value("reason")
				got[v.AsString()] += dp.Value
			}
		}
	}
	return got
}

// With a 300s lease the renewal is far away, so only the WAL sender can stop execution early.
func TestRunJob_CancelWhileOutputFlowsStopsViaWALSender(t *testing.T) {
	e := newWorkerEnv(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	d := e.enqueueAndDequeueVT(t, 300, "sh", chattyArgs(pidFile)...)
	jobID := d.Job.JobId

	done := make(chan error, 1)
	go func() {
		done <- (&WorkerCmd{VisibilityTimeout: 300}).runJob(context.Background(), e.clients, e.walCfg, d)
	}()
	pid := waitPID(t, pidFile)
	time.Sleep(time.Second) // let output flow

	cancelledAt := time.Now()
	_, err := e.user.CancelJob(context.Background(), connect.NewRequest(&jobv1.CancelJobRequest{JobId: jobID}))
	require.NoError(t, err)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("worker did not stop within 15s of cancel")
	}
	t.Logf("worker exited %s after cancel", time.Since(cancelledAt))

	state, _, result := e.jobState(t, jobID)
	require.Equal(t, jobv1.JobState_JOB_STATE_CANCELLED, state)
	require.Empty(t, result)
	requireNoWAL(t, e.walCfg, jobID)
	requireProcessGone(t, pid)
}

func TestRunJob_LeaseLostOnPublishStopsExecution(t *testing.T) {
	e := newWorkerEnv(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	d := e.enqueueAndDequeueVT(t, 300, "sh", chattyArgs(pidFile)...)
	jobID := d.Job.JobId

	reader := sdkmetric.NewManualReader()
	m, err := telemetry.NewWorkerMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- (&WorkerCmd{VisibilityTimeout: 300, metrics: m}).runJob(context.Background(), e.clients, e.walCfg, d)
	}()
	pid := waitPID(t, pidFile)
	time.Sleep(time.Second)

	_, err = e.stores.Pool.Exec(context.Background(),
		`UPDATE jobs SET visibility_until = clock_timestamp() - INTERVAL '1 second' WHERE job_id = $1`, jobID)
	require.NoError(t, err)
	n, err := e.stores.Jobs.ReapExpired(context.Background(), 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("worker did not stop within 15s of lease loss")
	}

	state, _, result := e.jobState(t, jobID)
	require.Equal(t, jobv1.JobState_JOB_STATE_SCHEDULED, state, "result=%s", result)
	requireNoWAL(t, e.walCfg, jobID)
	require.Equal(t, map[string]int64{"lease_lost": 1}, abandonedByReason(t, reader))
	requireProcessGone(t, pid)
}

type lossyCompleteJobs struct {
	jobv1connect.JobServiceClient
}

func (lossyCompleteJobs) CompleteJob(context.Context, *connect.Request[jobv1.CompleteJobRequest]) (*connect.Response[jobv1.CompleteJobResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("response lost"))
}

func TestRunJob_LostCompleteResponseKeepsWAL(t *testing.T) {
	e := newWorkerEnv(t)
	d := e.enqueueAndDequeue(t, "sh", "-c", "echo hello")
	jobID := d.Job.JobId
	e.clients.Job = lossyCompleteJobs{e.clients.Job}

	err := (&WorkerCmd{VisibilityTimeout: 30}).runJob(context.Background(), e.clients, e.walCfg, d)
	require.Error(t, err)
	require.Equal(t, connect.CodeUnavailable, connect.CodeOf(errors.Unwrap(err)))

	requireNoWAL(t, e.walCfg, jobID)
	kept, err := filepath.Glob(filepath.Join(e.walCfg.WALDir, "failed", "*"+jobID+"*"))
	require.NoError(t, err)
	require.NotEmpty(t, kept, "WAL is kept in failed/ when the complete response is lost")
}
