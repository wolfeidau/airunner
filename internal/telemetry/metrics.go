package telemetry

import (
	"errors"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// MeterName is the instrumentation scope used for airunner metrics.
const MeterName = "github.com/wolfeidau/airunner"

// Attribute keys. Values are drawn from small bounded sets; never label by job ID,
// token, org or queue.
const (
	AttrResult    = attribute.Key("result")
	AttrOperation = attribute.Key("operation")
	AttrReason    = attribute.Key("reason")
	AttrProcedure = attribute.Key("procedure")
	AttrCategory  = attribute.Key("category")
	AttrFrom      = attribute.Key("from")
)

// Result attribute values for jobs.completed.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// From attribute values for jobs.cancelled.
const (
	FromScheduled = "scheduled"
	FromRunning   = "running"
)

// Operation attribute values for jobs.lease_lost.
const (
	OpRenew    = "renew"
	OpPublish  = "publish"
	OpComplete = "complete"
	OpRelease  = "release"
)

// Reason attribute values for events.publish_rejected and authz.denied.
const (
	ReasonLeaseLost       = "lease_lost"
	ReasonConflict        = "conflict"
	ReasonInvalid         = "invalid"
	ReasonTooLarge        = "too_large"
	ReasonUnavailable     = "unavailable"
	ReasonOther           = "other"
	ReasonUnauthenticated = "unauthenticated"
	ReasonForbidden       = "forbidden"
)

// Metrics holds the OpenTelemetry instruments used by the server and store.
type Metrics struct {
	JobsEnqueued     metric.Int64Counter
	JobsDequeued     metric.Int64Counter
	JobsReleased     metric.Int64Counter
	JobsCompleted    metric.Int64Counter
	JobsRedelivered  metric.Int64Counter
	JobsDeadLettered metric.Int64Counter
	JobsLeaseLost    metric.Int64Counter
	JobsCancelled    metric.Int64Counter
	LeaseRenewals    metric.Int64Counter

	EventsPublished       metric.Int64Counter
	EventsPublishReplays  metric.Int64Counter
	EventsPublishRejected metric.Int64Counter
	EventsPublishDuration metric.Float64Histogram

	StreamsActive        metric.Int64UpDownCounter
	StreamsStalled       metric.Int64Counter
	StreamsDeliveryLag   metric.Float64Histogram
	AuthzDenied          metric.Int64Counter
	ReaperSweepDuration  metric.Float64Histogram
	ReaperBacklog        metric.Int64Gauge
	ReaperOldestExpired  metric.Float64Gauge
	RetentionSweepTime   metric.Float64Histogram
	RetentionOldestAge   metric.Float64Gauge
	RetentionEventsDel   metric.Int64Counter
	RetentionJobsDel     metric.Int64Counter
	RetentionSessionsDel metric.Int64Counter
	RetentionSweepErrors metric.Int64Counter
}

// NoopMetrics returns a Metrics whose instruments discard all measurements.
func NoopMetrics() *Metrics {
	m, err := NewMetrics(noop.NewMeterProvider().Meter(MeterName))
	if err != nil {
		// noop instrument creation cannot fail
		panic(err)
	}
	return m
}

// NewMetrics creates all instruments on the given meter, returning the first error.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	b := &builder{meter: meter}
	m := &Metrics{}

	m.JobsEnqueued = b.counter("jobs.enqueued", "Jobs newly enqueued (idempotent replays excluded)", "{job}")
	m.JobsDequeued = b.counter("jobs.dequeued", "Jobs leased to workers", "{job}")
	m.JobsReleased = b.counter("jobs.released", "Jobs released back to the queue by workers", "{job}")
	m.JobsCompleted = b.counter("jobs.completed", "Jobs completed, by result", "{job}")
	m.JobsRedelivered = b.counter("jobs.redelivered", "Expired leases returned to the queue for redelivery", "{job}")
	m.JobsDeadLettered = b.counter("jobs.dead_lettered", "Expired leases failed because attempts were exhausted", "{job}")
	m.JobsLeaseLost = b.counter("jobs.lease_lost", "Operations rejected because the lease was lost, by operation", "{operation}")
	m.JobsCancelled = b.counter("jobs.cancelled", "Jobs cancelled, by prior state", "{job}")
	m.LeaseRenewals = b.counter("lease.renewals", "Successful lease renewals", "{renewal}")

	m.EventsPublished = b.counter("events.published", "Events persisted", "{event}")
	m.EventsPublishReplays = b.counter("events.publish_replays", "Identical publish retries accepted without inserting", "{request}")
	m.EventsPublishRejected = b.counter("events.publish_rejected", "Publish requests rejected, by reason", "{request}")
	m.EventsPublishDuration = b.histogram("events.publish_duration", "Duration of store event publish operations", "s")

	m.StreamsActive = b.updown("streams.active", "Active event streams", "{stream}")
	m.StreamsStalled = b.counter("streams.stalled", "Event streams that stalled", "{stream}")
	m.StreamsDeliveryLag = b.histogram("streams.delivery_lag", "Lag between event timestamp and delivery to a stream", "s")

	m.AuthzDenied = b.counter("authz.denied", "Requests denied by authorization, by procedure and reason", "{request}")

	m.ReaperSweepDuration = b.histogram("reaper.sweep_duration", "Duration of a lease reaper sweep", "s")
	m.ReaperBacklog = b.intGauge("reaper.backlog", "Expired leases awaiting reaping after a sweep", "{job}")
	m.ReaperOldestExpired = b.floatGauge("reaper.oldest_expired_age", "Age of the oldest expired lease after a sweep", "s")

	m.RetentionSweepTime = b.histogram("retention.sweep_duration", "Duration of a retention sweep", "s")
	m.RetentionOldestAge = b.floatGauge("retention.oldest_eligible_age", "How long the oldest eligible terminal job has been past its retention cutoff", "s")
	m.RetentionEventsDel = b.counter("retention.events_deleted", "Job events deleted by the retention sweep", "{event}")
	m.RetentionJobsDel = b.counter("retention.jobs_deleted", "Terminal jobs deleted by the retention sweep", "{job}")
	m.RetentionSessionsDel = b.counter("retention.sessions_deleted", "Expired sessions deleted by the retention sweep", "{session}")
	m.RetentionSweepErrors = b.counter("retention.sweep_errors", "Retention sweep errors, by category", "{error}")

	if b.err != nil {
		return nil, b.err
	}
	return m, nil
}

// builder creates instruments, retaining the first error.
type builder struct {
	meter metric.Meter
	err   error
}

func (b *builder) keep(err error) { b.err = errors.Join(b.err, err) }

func (b *builder) counter(name, desc, unit string) metric.Int64Counter {
	c, err := b.meter.Int64Counter(name, metric.WithDescription(desc), metric.WithUnit(unit))
	b.keep(err)
	return c
}

func (b *builder) updown(name, desc, unit string) metric.Int64UpDownCounter {
	c, err := b.meter.Int64UpDownCounter(name, metric.WithDescription(desc), metric.WithUnit(unit))
	b.keep(err)
	return c
}

func (b *builder) histogram(name, desc, unit string) metric.Float64Histogram {
	h, err := b.meter.Float64Histogram(name, metric.WithDescription(desc), metric.WithUnit(unit))
	b.keep(err)
	return h
}

func (b *builder) intGauge(name, desc, unit string) metric.Int64Gauge {
	g, err := b.meter.Int64Gauge(name, metric.WithDescription(desc), metric.WithUnit(unit))
	b.keep(err)
	return g
}

func (b *builder) floatGauge(name, desc, unit string) metric.Float64Gauge {
	g, err := b.meter.Float64Gauge(name, metric.WithDescription(desc), metric.WithUnit(unit))
	b.keep(err)
	return g
}
