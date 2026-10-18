//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/attribute"
)

// setupMetricsStore returns a started store on the same database as setupStore's, wired to a
// metrics harness.
func setupMetricsStore(t *testing.T, mutate func(*JobStoreConfig)) (*JobStore, orgFixture, *telemetrytest.Harness) {
	t.Helper()
	base, fx := setupStore(t)
	h := telemetrytest.New(t)

	cfg := &JobStoreConfig{
		TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
		StreamPollInterval: 20 * time.Millisecond,
		Metrics:            h.Metrics,
	}
	if mutate != nil {
		mutate(cfg)
	}
	js, err := NewJobStore(base.pool, cfg)
	require.NoError(t, err)
	require.NoError(t, js.Start())
	t.Cleanup(func() { _ = js.Stop() })
	return js, fx, h
}

func attr(k, v string) attribute.KeyValue { return attribute.String(k, v) }

func TestMetricsJobLifecycle(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	req := contractReq("lifecycle", "lifecycle", "echo")
	_, err := js.EnqueueJob(ctx, fx.User, req)
	require.NoError(t, err)
	_, err = js.EnqueueJob(ctx, fx.User, req) // idempotent replay
	require.NoError(t, err)
	require.EqualValues(t, 1, h.Sum(t, "jobs.enqueued"))

	jobID, token := dequeueOne(t, js, fx, "lifecycle", 300)
	require.EqualValues(t, 1, h.Sum(t, "jobs.dequeued"))

	events := []*jobv1.JobEvent{startEvent(1), batchEvent(2, 4)}
	_, err = js.PublishEvents(ctx, fx.Worker, token, events)
	require.NoError(t, err)
	require.EqualValues(t, 2, h.Sum(t, "events.published"))

	// Identical retry is a replay.
	_, err = js.PublishEvents(ctx, fx.Worker, token, events)
	require.NoError(t, err)
	require.EqualValues(t, 1, h.Sum(t, "events.publish_replays"))
	require.EqualValues(t, 2, h.Sum(t, "events.published"))

	// Conflicting retry is rejected.
	conflicting := startEvent(1)
	conflicting.Timestamp.Seconds += 100
	_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{conflicting})
	require.ErrorIs(t, err, jobstore.ErrConflict)
	require.EqualValues(t, 1, h.Sum(t, "events.publish_rejected", attr("reason", "conflict")))
	require.EqualValues(t, 3, h.HistogramCount(t, "events.publish_duration"))

	_, err = js.UpdateJobVisibility(ctx, fx.Worker, token, 300)
	require.NoError(t, err)
	require.EqualValues(t, 1, h.Sum(t, "lease.renewals"))

	require.NoError(t, js.CompleteJob(ctx, fx.Worker, token, successResult(jobID), 4))
	require.EqualValues(t, 1, h.Sum(t, "jobs.completed", attr("result", "success")))
	require.EqualValues(t, 0, h.Sum(t, "jobs.completed", attr("result", "failure")))
}

func TestMetricsRelease(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	_, token := leasedJob(t, js, fx, "release", 3, 300)
	require.NoError(t, js.ReleaseJob(ctx, fx.Worker, token))
	require.EqualValues(t, 1, h.Sum(t, "jobs.released"))
}

func TestMetricsReaper(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	retryID, _ := leasedJob(t, js, fx, "retry", 3, 300)
	deadID, _ := leasedJob(t, js, fx, "dead", 1, 300)
	expireLease(t, js, retryID)
	expireLease(t, js, deadID)

	js.reapTick(ctx)

	require.EqualValues(t, 1, h.Sum(t, "jobs.redelivered"))
	require.EqualValues(t, 1, h.Sum(t, "jobs.dead_lettered"))
	// The background reaper also ticks, so at least our explicit tick is recorded.
	require.GreaterOrEqual(t, h.HistogramCount(t, "reaper.sweep_duration"), uint64(1))
	backlog, ok := h.IntGauge(t, "reaper.backlog")
	require.True(t, ok)
	require.EqualValues(t, 0, backlog)
	age, ok := h.FloatGauge(t, "reaper.oldest_expired_age")
	require.True(t, ok)
	require.Zero(t, age)
}

func TestMetricsReaperBacklog(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	id, _ := leasedJob(t, js, fx, "backlog", 3, 300)
	expireLease(t, js, id)

	// Record the backlog without reaping.
	js.recordReaperBacklog(ctx, time.Millisecond)

	backlog, _ := h.IntGauge(t, "reaper.backlog")
	require.EqualValues(t, 1, backlog)
	age, _ := h.FloatGauge(t, "reaper.oldest_expired_age")
	require.Greater(t, age, 0.0)
}

func TestMetricsLeaseLost(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	id, token := leasedJob(t, js, fx, "lost", 3, 300)
	expireLease(t, js, id)
	_, err := js.ReapExpired(ctx, 10)
	require.NoError(t, err)

	require.ErrorIs(t, js.CompleteJob(ctx, fx.Worker, token, successResult(id), 0), jobstore.ErrLeaseLost)
	require.ErrorIs(t, js.ReleaseJob(ctx, fx.Worker, token), jobstore.ErrLeaseLost)
	_, err = js.UpdateJobVisibility(ctx, fx.Worker, token, 30)
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)
	_, err = js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
	require.ErrorIs(t, err, jobstore.ErrLeaseLost)

	for _, op := range []string{"complete", "release", "renew", "publish"} {
		require.EqualValues(t, 1, h.Sum(t, "jobs.lease_lost", attr("operation", op)), op)
	}
	require.EqualValues(t, 1, h.Sum(t, "events.publish_rejected", attr("reason", "lease_lost")))
}

func TestMetricsStreams(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, nil)

	id, token := leasedJob(t, js, fx, "stream", 3, 300)
	_, err := js.PublishEvents(ctx, fx.Worker, token, []*jobv1.JobEvent{startEvent(1)})
	require.NoError(t, err)

	// Open stream on a running job: active is 1 and lag is recorded for the event.
	streamCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	got := make(chan struct{}, 8)
	go func() {
		done <- js.StreamEvents(streamCtx, fx.User, jobstore.StreamRequest{JobID: id}, func(r *jobstore.StreamResponse) error {
			if r.Event != nil {
				got <- struct{}{}
			}
			return nil
		})
	}()
	select {
	case <-got:
	case <-time.After(streamWait):
		t.Fatal("timed out waiting for stream event")
	}
	require.EqualValues(t, 1, h.Sum(t, "streams.active"))
	require.EqualValues(t, 1, h.HistogramCount(t, "streams.delivery_lag"))

	cancel()
	select {
	case <-done:
	case <-time.After(streamWait):
		t.Fatal("timed out waiting for stream to end")
	}
	require.EqualValues(t, 0, h.Sum(t, "streams.active"))

	// A stream on a finished job ends by itself and also returns to zero.
	require.NoError(t, js.CompleteJob(ctx, fx.Worker, token, successResult(id), 1))
	require.NoError(t, js.StreamEvents(ctx, fx.User, jobstore.StreamRequest{JobID: id}, discardStream))
	require.EqualValues(t, 0, h.Sum(t, "streams.active"))
}

func TestMetricsRetention(t *testing.T) {
	ctx := context.Background()
	js, fx, h := setupMetricsStore(t, func(c *JobStoreConfig) {
		c.JobRetention = 24 * time.Hour
		c.EventRetention = 12 * time.Hour
		c.DisableRetentionLoop = true
	})

	seedJob(t, js, fx, "old", stateCompletedInt, 48*time.Hour, 3)

	_, err := js.SweepRetention(ctx, 5)
	require.NoError(t, err)

	require.EqualValues(t, 1, h.HistogramCount(t, "retention.sweep_duration"))
	require.EqualValues(t, 3, h.Sum(t, "retention.events_deleted"))
	require.EqualValues(t, 1, h.Sum(t, "retention.jobs_deleted"))
	age, ok := h.FloatGauge(t, "retention.oldest_eligible_age")
	require.True(t, ok)
	require.Zero(t, age)

	// Unpurged eligible work is reported as age beyond the cutoff: record without purging.
	seedJob(t, js, fx, "old2", stateFailedInt, 30*time.Hour, 0)
	js.recordRetentionLag(ctx, time.Now(), time.Now().Add(-js.cfg.JobRetention))
	age, _ = h.FloatGauge(t, "retention.oldest_eligible_age")
	require.InDelta(t, 6*time.Hour.Seconds(), age, 120)
}
