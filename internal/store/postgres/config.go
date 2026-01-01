package postgres

import (
	"fmt"
	"os"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// JobStoreConfig holds configuration for the PostgreSQL job store.
type JobStoreConfig struct {
	// ConnString is the PostgreSQL connection string.
	// Format: postgres://user:password@host:port/database?options
	// Can be set via POSTGRES_CONNECTION_STRING or DATABASE_URL environment variables.
	ConnString string

	// TokenSigningSecret is the secret used for HMAC signing of task tokens.
	// Must be kept secure and consistent across all instances.
	TokenSigningSecret []byte

	// DefaultExecutionConfig provides default execution configuration for jobs
	// when not specified in the EnqueueJob request.
	DefaultExecutionConfig *jobv1.ExecutionConfig

	// EventsTTLDays configures how many days events should be retained.
	// 0 means no expiration (events kept indefinitely).
	EventsTTLDays int32

	// MaxConns is the maximum number of connections in the pool.
	// Default: 20
	MaxConns int32

	// MinConns is the minimum number of connections to keep open in the pool.
	// Default: 5
	MinConns int32

	// MaxConnLifetime is the maximum time a connection can be reused (in seconds).
	// Default: 3600 (1 hour)
	MaxConnLifetime int32

	// MaxConnIdleTime is the maximum time a connection can be idle (in seconds).
	// Default: 1800 (30 minutes)
	MaxConnIdleTime int32

	// AutoMigrate controls whether migrations run automatically on startup.
	// Default: false (migrations must be explicitly enabled)
	AutoMigrate bool
}

// Validate checks that the configuration is valid.
func (c *JobStoreConfig) Validate() error {
	if c.ConnString == "" {
		return fmt.Errorf("connection string is required")
	}

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
	// Try to get connection string from environment if not set
	if c.ConnString == "" {
		if connStr := os.Getenv("POSTGRES_CONNECTION_STRING"); connStr != "" {
			c.ConnString = connStr
		} else if connStr := os.Getenv("DATABASE_URL"); connStr != "" {
			c.ConnString = connStr
		}
	}

	// Apply pool defaults
	if c.MaxConns == 0 {
		c.MaxConns = 20
	}

	if c.MinConns == 0 {
		c.MinConns = 5
	}

	if c.MaxConnLifetime == 0 {
		c.MaxConnLifetime = 3600 // 1 hour
	}

	if c.MaxConnIdleTime == 0 {
		c.MaxConnIdleTime = 1800 // 30 minutes
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
