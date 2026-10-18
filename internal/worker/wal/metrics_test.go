package wal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type metricsEnv struct {
	reader  *sdkmetric.ManualReader
	metrics *telemetry.WorkerMetrics
}

func newMetricsEnv(t *testing.T) *metricsEnv {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := telemetry.NewWorkerMetrics(mp.Meter("test"))
	require.NoError(t, err)
	return &metricsEnv{reader: reader, metrics: m}
}

func (e *metricsEnv) find(t *testing.T, name string) (metricdata.Aggregation, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, e.reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, mm := range sm.Metrics {
			if mm.Name == name {
				return mm.Data, true
			}
		}
	}
	return nil, false
}

// sum totals all int64 sum points of a counter; 0 when absent.
func (e *metricsEnv) sum(t *testing.T, name string) int64 {
	t.Helper()
	data, ok := e.find(t, name)
	if !ok {
		return 0
	}
	var total int64
	for _, dp := range data.(metricdata.Sum[int64]).DataPoints {
		total += dp.Value
	}
	return total
}

func (e *metricsEnv) gauge(t *testing.T, name string) (int64, bool) {
	t.Helper()
	data, ok := e.find(t, name)
	if !ok {
		return 0, false
	}
	dps := data.(metricdata.Gauge[int64]).DataPoints
	require.Len(t, dps, 1)
	return dps[0].Value, true
}

func (e *metricsEnv) histCount(t *testing.T, name string) uint64 {
	t.Helper()
	data, ok := e.find(t, name)
	if !ok {
		return 0
	}
	var n uint64
	for _, dp := range data.(metricdata.Histogram[float64]).DataPoints {
		n += dp.Count
	}
	return n
}

func TestSender_Metrics(t *testing.T) {
	e := newMetricsEnv(t)
	cfg := testCfg(t)
	cfg.Metrics = e.metrics

	r := newReceiver()
	r.script = []func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error){
		func(*fakeReceiver, []*jobv1.JobEvent) (Ack, error) { return Ack{}, errors.New("boom") },
	}
	w := startWAL(t, cfg, r)
	appendSeqs(t, w, 3)
	require.NoError(t, flush(t, w))

	require.EqualValues(t, 1, e.sum(t, "worker.publish.retries"))
	acked := uint64(len(r.callSizes()) - 1) // every call but the failed one is acknowledged
	require.Equal(t, acked, e.histCount(t, "worker.publish.ack_latency"))
	require.NotZero(t, acked)
	v, ok := e.gauge(t, "worker.wal.pending_records")
	require.True(t, ok)
	require.EqualValues(t, 0, v)
}

func TestCleanupStale_Metrics(t *testing.T) {
	e := newMetricsEnv(t)
	cfg := testCfg(t)
	cfg.Metrics = e.metrics

	// Two stale per-attempt files, one legacy flat file.
	for _, attempt := range []string{"1.wal", "2.wal"} {
		dir := filepath.Join(cfg.WALDir, testJob)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, attempt), nil, 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(cfg.WALDir, "legacy.wal"), nil, 0o644))

	report, err := CleanupStale(cfg, 0)
	require.NoError(t, err)
	require.Equal(t, 2, report.Deleted)
	require.Equal(t, 1, report.LegacyDeleted)
	require.EqualValues(t, 3, e.sum(t, "worker.wal.failed_deleted"))
}

func TestCleanupStale_MovedNotCounted(t *testing.T) {
	e := newMetricsEnv(t)
	cfg := testCfg(t)
	cfg.Metrics = e.metrics
	dir := filepath.Join(cfg.WALDir, testJob)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "1.wal"), nil, 0o644))

	report, err := CleanupStale(cfg, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, report.Moved)
	require.EqualValues(t, 0, e.sum(t, "worker.wal.failed_deleted"))
}

func TestDiscard_Metrics(t *testing.T) {
	e := newMetricsEnv(t)
	cfg := testCfg(t)
	cfg.Metrics = e.metrics

	w, err := NewWAL(cfg, testJob, 1)
	require.NoError(t, err)
	require.NoError(t, w.Discard(false))
	require.EqualValues(t, 1, e.sum(t, "worker.wal.failed_deleted"))

	w, err = NewWAL(cfg, testJob, 2)
	require.NoError(t, err)
	require.NoError(t, w.Discard(true))
	require.EqualValues(t, 1, e.sum(t, "worker.wal.failed_deleted"), "move to failed/ is not a deletion")
}
