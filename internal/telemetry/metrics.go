package telemetry

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	meterName = "github.com/wolfeidau/airunner"
)

// Metrics holds all the OpenTelemetry metric instruments
type Metrics struct {
	// Event metrics
	EventPublishTotal       metric.Int64Counter
	EventPublishErrorsTotal metric.Int64Counter
	EventPublishDuration    metric.Float64Histogram
	EventsPersistedTotal    metric.Int64Counter
	EventsDroppedTotal      metric.Int64Counter

	// Stream metrics
	ActiveStreams            metric.Int64UpDownCounter
	HistoricalReplayDuration metric.Float64Histogram
	HistoricalEventsReplayed metric.Int64Counter

	// Store operation metrics
	JobsEnqueuedTotal    metric.Int64Counter
	JobsDequeuedTotal    metric.Int64Counter
	JobsCompletedTotal   metric.Int64Counter
	JobsRedeliveredTotal metric.Int64Counter
	JobsReleasedTotal    metric.Int64Counter
	VisibilityUpdates    metric.Int64Counter

	// DynamoDB metrics (SQS store only)
	DynamoDBOperationsTotal metric.Int64Counter
	DynamoDBThrottlesTotal  metric.Int64Counter
	DynamoDBBatchRetries    metric.Int64Counter

	// Channel metrics
	ChannelOverflowTotal metric.Int64Counter
}

var (
	once    sync.Once
	metrics *Metrics
)

// GetMetrics returns the singleton Metrics instance, initializing it if necessary
func GetMetrics() *Metrics {
	once.Do(func() {
		metrics = initMetrics()
	})
	return metrics
}

// initMetrics creates and registers all metric instruments
func initMetrics() *Metrics {
	meter := otel.GetMeterProvider().Meter(meterName)

	m := &Metrics{}

	// Event metrics
	m.EventPublishTotal, _ = meter.Int64Counter(
		"airunner.events.publish.total",
		metric.WithDescription("Total number of event publish attempts"),
		metric.WithUnit("{event}"),
	)

	m.EventPublishErrorsTotal, _ = meter.Int64Counter(
		"airunner.events.publish.errors.total",
		metric.WithDescription("Total number of event publish errors"),
		metric.WithUnit("{error}"),
	)

	m.EventPublishDuration, _ = meter.Float64Histogram(
		"airunner.events.publish.duration",
		metric.WithDescription("Duration of event publish operations"),
		metric.WithUnit("ms"),
	)

	m.EventsPersistedTotal, _ = meter.Int64Counter(
		"airunner.events.persisted.total",
		metric.WithDescription("Total number of events successfully persisted"),
		metric.WithUnit("{event}"),
	)

	m.EventsDroppedTotal, _ = meter.Int64Counter(
		"airunner.events.dropped.total",
		metric.WithDescription("Total number of events dropped due to errors or overflow"),
		metric.WithUnit("{event}"),
	)

	// Stream metrics
	m.ActiveStreams, _ = meter.Int64UpDownCounter(
		"airunner.streams.active",
		metric.WithDescription("Number of active event streams"),
		metric.WithUnit("{stream}"),
	)

	m.HistoricalReplayDuration, _ = meter.Float64Histogram(
		"airunner.streams.historical_replay.duration",
		metric.WithDescription("Duration of historical event replay"),
		metric.WithUnit("ms"),
	)

	m.HistoricalEventsReplayed, _ = meter.Int64Counter(
		"airunner.streams.historical_replay.events.total",
		metric.WithDescription("Total number of historical events replayed"),
		metric.WithUnit("{event}"),
	)

	// Store operation metrics
	m.JobsEnqueuedTotal, _ = meter.Int64Counter(
		"airunner.jobs.enqueued.total",
		metric.WithDescription("Total number of jobs enqueued"),
		metric.WithUnit("{job}"),
	)

	m.JobsDequeuedTotal, _ = meter.Int64Counter(
		"airunner.jobs.dequeued.total",
		metric.WithDescription("Total number of jobs dequeued"),
		metric.WithUnit("{job}"),
	)

	m.JobsCompletedTotal, _ = meter.Int64Counter(
		"airunner.jobs.completed.total",
		metric.WithDescription("Total number of jobs completed"),
		metric.WithUnit("{job}"),
	)

	m.JobsRedeliveredTotal, _ = meter.Int64Counter(
		"airunner.jobs.redelivered.total",
		metric.WithDescription("Total number of jobs redelivered due to failed delivery"),
		metric.WithUnit("{job}"),
	)

	m.JobsReleasedTotal, _ = meter.Int64Counter(
		"airunner.jobs.released.total",
		metric.WithDescription("Total number of jobs released back to queue"),
		metric.WithUnit("{job}"),
	)

	m.VisibilityUpdates, _ = meter.Int64Counter(
		"airunner.jobs.visibility_updates.total",
		metric.WithDescription("Total number of visibility timeout updates"),
		metric.WithUnit("{update}"),
	)

	// DynamoDB metrics
	m.DynamoDBOperationsTotal, _ = meter.Int64Counter(
		"airunner.dynamodb.operations.total",
		metric.WithDescription("Total number of DynamoDB operations"),
		metric.WithUnit("{operation}"),
	)

	m.DynamoDBThrottlesTotal, _ = meter.Int64Counter(
		"airunner.dynamodb.throttles.total",
		metric.WithDescription("Total number of DynamoDB throttling events"),
		metric.WithUnit("{throttle}"),
	)

	m.DynamoDBBatchRetries, _ = meter.Int64Counter(
		"airunner.dynamodb.batch_retries.total",
		metric.WithDescription("Total number of DynamoDB batch write retries"),
		metric.WithUnit("{retry}"),
	)

	// Channel metrics
	m.ChannelOverflowTotal, _ = meter.Int64Counter(
		"airunner.channels.overflow.total",
		metric.WithDescription("Total number of channel overflow events (dropped events)"),
		metric.WithUnit("{event}"),
	)

	return m
}
