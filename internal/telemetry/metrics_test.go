package telemetry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"github.com/wolfeidau/airunner/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func TestMetricsNew(t *testing.T) {
	h := telemetrytest.New(t)
	ctx := context.Background()

	h.Metrics.JobsCompleted.Add(ctx, 2, metric.WithAttributes(telemetry.AttrResult.String(telemetry.ResultSuccess)))
	h.Metrics.JobsCompleted.Add(ctx, 1, metric.WithAttributes(telemetry.AttrResult.String(telemetry.ResultFailure)))

	require.EqualValues(t, 3, h.Sum(t, "jobs.completed"))
	require.EqualValues(t, 2, h.Sum(t, "jobs.completed", attribute.String("result", "success")))
}

func TestMetricsNoop(t *testing.T) {
	m := telemetry.NoopMetrics()
	require.NotNil(t, m)

	ctx := context.Background()
	m.JobsEnqueued.Add(ctx, 1)
	m.EventsPublishDuration.Record(ctx, 0.1)
	m.ReaperBacklog.Record(ctx, 1)
	m.StreamsActive.Add(ctx, -1)
}
