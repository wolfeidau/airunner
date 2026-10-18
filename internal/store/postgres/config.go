package postgres

import (
	"fmt"
	"time"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

// JobStoreConfig holds job-specific configuration for the PostgreSQL job store.
// Pool configuration is handled separately via PoolConfig.
type JobStoreConfig struct {
	// TokenSigningSecret is the secret used for HMAC signing of task tokens.
	// Must be kept secure and consistent across all instances.
	TokenSigningSecret []byte

	// DefaultExecutionConfig provides default execution configuration for jobs
	// when not specified in the EnqueueJob request.
	DefaultExecutionConfig *jobv1.ExecutionConfig

	// DefaultMaxAttempts is the maximum delivery attempts applied to jobs that
	// do not request one. Default: 3, valid range 1-100.
	DefaultMaxAttempts int32

	// QueryTimeoutSeconds is the maximum time a query can run before timing out.
	// Default: 10 seconds
	// Set to 0 to use context timeouts only (no additional timeout)
	QueryTimeoutSeconds int32

	// LeaseReaperInterval is how often expired leases are reclaimed. Default: 5s.
	LeaseReaperInterval time.Duration

	// StreamPollInterval is how often an event stream polls for new events. Default: 500ms.
	StreamPollInterval time.Duration

	// JobRetention is how long terminal jobs (completed, failed, cancelled) are kept,
	// measured from their last update. Default: 90 days. Must be positive.
	JobRetention time.Duration

	// EventRetention is how long the events of terminal jobs are kept, measured from
	// the job's last update. 0 keeps events until the job itself is deleted. Must be
	// >= 0 and <= JobRetention.
	//
	// ApplyDefaults sets this to 30 days only when both EventRetention and JobRetention
	// are unset (zero). Callers that set JobRetention explicitly and leave EventRetention
	// zero therefore get "keep events for the job's lifetime".
	EventRetention time.Duration

	// RetentionInterval is how often the retention sweep runs. Default: 1h.
	// Must be positive when the retention loop is enabled and never negative.
	RetentionInterval time.Duration

	// DisableRetentionLoop stops Start from running the in-process retention loop.
	// Retention can then be run on a schedule with SweepRetention.
	DisableRetentionLoop bool

	// Metrics holds the telemetry instruments. Nil uses no-op instruments.
	Metrics *telemetry.Metrics
}

// Validate checks that the configuration is valid.
func (c *JobStoreConfig) Validate() error {
	if len(c.TokenSigningSecret) == 0 {
		return fmt.Errorf("token signing secret is required")
	}

	if len(c.TokenSigningSecret) < 32 {
		return fmt.Errorf("token signing secret must be at least 32 bytes")
	}

	if c.DefaultMaxAttempts < 1 || c.DefaultMaxAttempts > maxAttemptsLimit {
		return fmt.Errorf("default max attempts must be between 1 and %d", maxAttemptsLimit)
	}

	if c.LeaseReaperInterval <= 0 {
		return fmt.Errorf("lease reaper interval must be positive")
	}

	if c.StreamPollInterval <= 0 {
		return fmt.Errorf("stream poll interval must be positive")
	}

	if c.JobRetention <= 0 {
		return fmt.Errorf("job retention must be positive")
	}

	if c.EventRetention < 0 {
		return fmt.Errorf("event retention must not be negative")
	}

	if c.EventRetention > c.JobRetention {
		return fmt.Errorf("event retention must not exceed job retention")
	}

	if c.RetentionInterval < 0 || (c.RetentionInterval == 0 && !c.DisableRetentionLoop) {
		return fmt.Errorf("retention interval must be positive")
	}

	return nil
}

// ApplyDefaults applies default values to unset configuration fields.
func (c *JobStoreConfig) ApplyDefaults() {
	if c.Metrics == nil {
		c.Metrics = telemetry.NoopMetrics()
	}

	if c.QueryTimeoutSeconds == 0 {
		c.QueryTimeoutSeconds = 10 // 10 seconds
	}

	if c.LeaseReaperInterval == 0 {
		c.LeaseReaperInterval = 5 * time.Second
	}

	if c.StreamPollInterval == 0 {
		c.StreamPollInterval = 500 * time.Millisecond
	}

	// EventRetention 0 is meaningful (keep events with the job), so its default only
	// applies when retention is entirely unconfigured.
	if c.JobRetention == 0 && c.EventRetention == 0 {
		c.EventRetention = 30 * 24 * time.Hour
	}

	if c.JobRetention == 0 {
		c.JobRetention = 90 * 24 * time.Hour
	}

	if c.RetentionInterval == 0 && !c.DisableRetentionLoop {
		c.RetentionInterval = time.Hour
	}

	if c.DefaultMaxAttempts == 0 {
		c.DefaultMaxAttempts = 3
	}

	// Apply default execution config if not provided
	if c.DefaultExecutionConfig == nil {
		c.DefaultExecutionConfig = &jobv1.ExecutionConfig{
			Batching: &jobv1.BatchingConfig{
				FlushIntervalSeconds:   2,
				MaxBatchSize:           50,
				MaxBatchBytes:          256 * 1024, // 256KB
				PlaybackIntervalMillis: 50,
			},
			HeartbeatIntervalSeconds:  30,
			OutputFlushIntervalMillis: 100,
		}
	}
}
