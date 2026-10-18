package telemetry

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// WorkerMetrics holds the worker's metric instruments. Attributes are limited to
// low-cardinality reasons; job IDs and queue names are never used as labels.
type WorkerMetrics struct {
	// WALPendingRecords is the number of unacknowledged records in the active WAL.
	WALPendingRecords metric.Int64Gauge
	// WALFailedDeleted counts WAL files deleted by Discard or removed by stale cleanup.
	WALFailedDeleted metric.Int64Counter
	// PublishAckLatency is the time from sending a batch to its valid acknowledgement.
	PublishAckLatency metric.Float64Histogram
	// PublishRetries counts transient publish failures that were retried.
	PublishRetries metric.Int64Counter
	// LeaseAborts counts lease aborts, attribute reason=lost|budget.
	LeaseAborts metric.Int64Counter
	// JobsAbandoned counts abandoned jobs, attribute reason=lease_lost|flush_timeout|other.
	JobsAbandoned metric.Int64Counter
}

// NewWorkerMetrics creates the worker instruments on meter.
func NewWorkerMetrics(meter metric.Meter) (*WorkerMetrics, error) {
	var (
		m   WorkerMetrics
		err error
	)
	if m.WALPendingRecords, err = meter.Int64Gauge("worker.wal.pending_records",
		metric.WithDescription("Unacknowledged records in the active WAL"),
		metric.WithUnit("{record}")); err != nil {
		return nil, fmt.Errorf("worker.wal.pending_records: %w", err)
	}
	if m.WALFailedDeleted, err = meter.Int64Counter("worker.wal.failed_deleted",
		metric.WithDescription("WAL files deleted by discard or stale cleanup"),
		metric.WithUnit("{wal}")); err != nil {
		return nil, fmt.Errorf("worker.wal.failed_deleted: %w", err)
	}
	if m.PublishAckLatency, err = meter.Float64Histogram("worker.publish.ack_latency",
		metric.WithDescription("Time from sending an event batch to its acknowledgement"),
		metric.WithUnit("s")); err != nil {
		return nil, fmt.Errorf("worker.publish.ack_latency: %w", err)
	}
	if m.PublishRetries, err = meter.Int64Counter("worker.publish.retries",
		metric.WithDescription("Event publish attempts retried after a transient failure"),
		metric.WithUnit("{retry}")); err != nil {
		return nil, fmt.Errorf("worker.publish.retries: %w", err)
	}
	if m.LeaseAborts, err = meter.Int64Counter("worker.lease.aborts",
		metric.WithDescription("Lease controller aborts by reason"),
		metric.WithUnit("{abort}")); err != nil {
		return nil, fmt.Errorf("worker.lease.aborts: %w", err)
	}
	if m.JobsAbandoned, err = meter.Int64Counter("worker.jobs.abandoned",
		metric.WithDescription("Jobs abandoned without completion by reason"),
		metric.WithUnit("{job}")); err != nil {
		return nil, fmt.Errorf("worker.jobs.abandoned: %w", err)
	}
	return &m, nil
}

// NoopWorkerMetrics returns instruments that record nothing.
func NoopWorkerMetrics() *WorkerMetrics {
	m, _ := NewWorkerMetrics(noop.NewMeterProvider().Meter("noop"))
	return m
}
