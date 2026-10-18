package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestWorkerMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := NewWorkerMetrics(mp.Meter("test"))
	require.NoError(t, err)
	m.PublishRetries.Add(context.Background(), 1)

	rm := collect(t, reader)
	require.Len(t, rm, 1)
	require.Equal(t, "worker.publish.retries", rm[0])
}

func TestNoopWorkerMetrics(t *testing.T) {
	m := NoopWorkerMetrics()
	require.NotNil(t, m.WALPendingRecords)
	m.JobsAbandoned.Add(context.Background(), 1)
}

func collect(t *testing.T, r sdkmetric.Reader) []string {
	t.Helper()
	rm := new(metricdata.ResourceMetrics)
	require.NoError(t, r.Collect(context.Background(), rm))
	var names []string
	for _, sm := range rm.ScopeMetrics {
		for _, mm := range sm.Metrics {
			names = append(names, mm.Name)
		}
	}
	return names
}
