// Package telemetrytest provides an in-memory metrics harness for tests.
package telemetrytest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Harness collects measurements recorded through Metrics.
type Harness struct {
	Reader  *sdkmetric.ManualReader
	Metrics *telemetry.Metrics
}

// New returns a Harness backed by a ManualReader.
func New(t testing.TB) *Harness {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	m, err := telemetry.NewMetrics(mp.Meter("test"))
	require.NoError(t, err)
	return &Harness{Reader: reader, Metrics: m}
}

func (h *Harness) find(t testing.TB, name string) (metricdata.Aggregation, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, h.Reader.Collect(context.Background(), &rm))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m.Data, true
			}
		}
	}
	return nil, false
}

func matches(set attribute.Set, want []attribute.KeyValue) bool {
	for _, kv := range want {
		v, ok := set.Value(kv.Key)
		if !ok || v != kv.Value {
			return false
		}
	}
	return true
}

// Sum totals the int64 data points of a counter or up/down counter whose attributes
// include every given attribute. It returns 0 when the metric has no data.
func (h *Harness) Sum(t testing.TB, name string, attrs ...attribute.KeyValue) int64 {
	t.Helper()
	data, ok := h.find(t, name)
	if !ok {
		return 0
	}
	sum, ok := data.(metricdata.Sum[int64])
	require.True(t, ok, "metric %s is not an int64 sum", name)
	var total int64
	for _, dp := range sum.DataPoints {
		if matches(dp.Attributes, attrs) {
			total += dp.Value
		}
	}
	return total
}

// HistogramCount totals the recorded values of a float64 histogram.
func (h *Harness) HistogramCount(t testing.TB, name string) uint64 {
	t.Helper()
	data, ok := h.find(t, name)
	if !ok {
		return 0
	}
	hist, ok := data.(metricdata.Histogram[float64])
	require.True(t, ok, "metric %s is not a float64 histogram", name)
	var total uint64
	for _, dp := range hist.DataPoints {
		total += dp.Count
	}
	return total
}

// IntGauge returns the last value of an int64 gauge and whether one was recorded.
func (h *Harness) IntGauge(t testing.TB, name string) (int64, bool) {
	t.Helper()
	data, ok := h.find(t, name)
	if !ok {
		return 0, false
	}
	g, ok := data.(metricdata.Gauge[int64])
	require.True(t, ok, "metric %s is not an int64 gauge", name)
	if len(g.DataPoints) == 0 {
		return 0, false
	}
	return g.DataPoints[len(g.DataPoints)-1].Value, true
}

// FloatGauge returns the last value of a float64 gauge and whether one was recorded.
func (h *Harness) FloatGauge(t testing.TB, name string) (float64, bool) {
	t.Helper()
	data, ok := h.find(t, name)
	if !ok {
		return 0, false
	}
	g, ok := data.(metricdata.Gauge[float64])
	require.True(t, ok, "metric %s is not a float64 gauge", name)
	if len(g.DataPoints) == 0 {
		return 0, false
	}
	return g.DataPoints[len(g.DataPoints)-1].Value, true
}
