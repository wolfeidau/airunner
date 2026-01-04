package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig holds configuration for PostgreSQL connection pooling.
// This is extracted from JobStoreConfig to allow reuse across different stores.
type PoolConfig struct {
	// ConnString is the PostgreSQL connection string.
	// Format: postgres://user:password@host:port/database?options
	ConnString string

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

	// HealthCheckPeriod is the duration between health checks (in seconds).
	// Default: 60 (1 minute)
	HealthCheckPeriod int32

	// ConnectTimeout is the maximum time to wait for a connection (in seconds).
	// Default: 10
	ConnectTimeout int32
}

// Validate checks that the pool configuration is valid.
func (c *PoolConfig) Validate() error {
	if c.ConnString == "" {
		return fmt.Errorf("connection string is required")
	}
	return nil
}

// ApplyDefaults applies default values to unset configuration fields.
func (c *PoolConfig) ApplyDefaults() {
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
	if c.HealthCheckPeriod == 0 {
		c.HealthCheckPeriod = 60 // 1 minute
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 10 // 10 seconds
	}
}

// NewPool creates a new PostgreSQL connection pool with the given configuration.
// It validates the config, applies defaults, creates the pool, and pings to verify connectivity.
func NewPool(ctx context.Context, cfg *PoolConfig) (*pgxpool.Pool, error) {
	if cfg == nil {
		return nil, fmt.Errorf("pool config is required")
	}

	// Apply defaults first
	cfg.ApplyDefaults()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid pool config: %w", err)
	}

	// Parse connection string
	poolConfig, err := pgxpool.ParseConfig(cfg.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Configure pool settings
	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = time.Duration(cfg.MaxConnLifetime) * time.Second
	poolConfig.MaxConnIdleTime = time.Duration(cfg.MaxConnIdleTime) * time.Second
	poolConfig.HealthCheckPeriod = time.Duration(cfg.HealthCheckPeriod) * time.Second
	poolConfig.ConnConfig.ConnectTimeout = time.Duration(cfg.ConnectTimeout) * time.Second

	// Create pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connectivity
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}
