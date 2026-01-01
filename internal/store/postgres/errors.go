package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wolfeidau/airunner/internal/store"
)

// mapPostgresError maps PostgreSQL-specific errors to sentinel errors.
// Returns the original error if it's not a PostgreSQL error or doesn't match known patterns.
func mapPostgresError(err error) error {
	if err == nil {
		return nil
	}

	// Check if it's a PostgreSQL error
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}

	// Map error codes to sentinel errors
	switch pgErr.Code {
	case pgerrcode.UniqueViolation:
		// Check which constraint was violated
		if pgErr.ConstraintName == "jobs_request_id_key" || pgErr.ConstraintName == "idx_jobs_request_id" {
			// Request ID duplicate - this is expected for idempotency
			return store.ErrJobNotFound // Will be handled by checking if job exists
		}
		return fmt.Errorf("unique constraint violation: %s: %w", pgErr.ConstraintName, err)

	case pgerrcode.ForeignKeyViolation:
		// Job not found (e.g., when inserting events for non-existent job)
		return fmt.Errorf("%w: %s", store.ErrJobNotFound, pgErr.Detail)

	case pgerrcode.CheckViolation:
		// Invalid state or constraint violation
		return fmt.Errorf("check constraint violation: %s: %w", pgErr.ConstraintName, err)

	case pgerrcode.SerializationFailure, pgerrcode.DeadlockDetected:
		// Retryable transaction errors
		return fmt.Errorf("transaction conflict (retryable): %w", err)

	case pgerrcode.ConnectionException,
		pgerrcode.ConnectionDoesNotExist,
		pgerrcode.ConnectionFailure,
		pgerrcode.CannotConnectNow,
		pgerrcode.SQLClientUnableToEstablishSQLConnection:
		// Connection errors
		return fmt.Errorf("database connection error: %w", err)

	case pgerrcode.AdminShutdown,
		pgerrcode.CrashShutdown:
		// Server unavailable
		return fmt.Errorf("database server unavailable: %w", err)

	case pgerrcode.QueryCanceled:
		// Context cancellation or timeout
		return fmt.Errorf("query canceled: %w", err)

	case pgerrcode.InsufficientResources,
		pgerrcode.DiskFull,
		pgerrcode.OutOfMemory,
		pgerrcode.TooManyConnections:
		// Resource errors (throttling-like)
		return fmt.Errorf("database resource limit: %w", err)

	default:
		// Unknown error - wrap with PostgreSQL error details
		return fmt.Errorf("postgres error [%s]: %s (detail: %s, hint: %s): %w",
			pgErr.Code, pgErr.Message, pgErr.Detail, pgErr.Hint, err)
	}
}
