package postgres

import (
	"fmt"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
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

	// EventsTTLDays configures how many days events should be retained.
	// 0 means no expiration (events kept indefinitely).
	EventsTTLDays int32

	// QueryTimeoutSeconds is the maximum time a query can run before timing out.
	// Default: 10 seconds
	// Set to 0 to use context timeouts only (no additional timeout)
	QueryTimeoutSeconds int32
}

// Validate checks that the configuration is valid.
func (c *JobStoreConfig) Validate() error {
	if len(c.TokenSigningSecret) == 0 {
		return fmt.Errorf("token signing secret is required")
	}

	if len(c.TokenSigningSecret) < 32 {
		return fmt.Errorf("token signing secret must be at least 32 bytes")
	}

	return nil
}

// ApplyDefaults applies default values to unset configuration fields.
func (c *JobStoreConfig) ApplyDefaults() {
	if c.QueryTimeoutSeconds == 0 {
		c.QueryTimeoutSeconds = 10 // 10 seconds
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
