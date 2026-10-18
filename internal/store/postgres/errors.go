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
		if pgErr.ConstraintName == "jobs_org_request_id_key" {
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
		return fmt.Errorf("%w: transaction conflict: %w", store.ErrUnavailable, err)

	case pgerrcode.LockNotAvailable:
		// lock_timeout expired while waiting for a job row lock
		return fmt.Errorf("%w: lock timeout: %w", store.ErrUnavailable, err)

	case pgerrcode.ConnectionException,
		pgerrcode.ConnectionDoesNotExist,
		pgerrcode.ConnectionFailure,
		pgerrcode.CannotConnectNow,
		pgerrcode.SQLClientUnableToEstablishSQLConnection:
		// Connection errors
		return fmt.Errorf("%w: database connection error: %w", store.ErrUnavailable, err)

	case pgerrcode.AdminShutdown,
		pgerrcode.CrashShutdown:
		// Server unavailable
		return fmt.Errorf("%w: database server unavailable: %w", store.ErrUnavailable, err)

	case pgerrcode.QueryCanceled:
		// statement_timeout expired or the query was cancelled
		return fmt.Errorf("%w: query canceled: %w", store.ErrUnavailable, err)

	case pgerrcode.InsufficientResources,
		pgerrcode.DiskFull,
		pgerrcode.OutOfMemory,
		pgerrcode.TooManyConnections:
		// Resource errors (throttling-like)
		return fmt.Errorf("%w: database resource limit: %w", store.ErrUnavailable, err)

	default:
		// Unknown error - wrap with PostgreSQL error details
		return fmt.Errorf("postgres error [%s]: %s (detail: %s, hint: %s): %w",
			pgErr.Code, pgErr.Message, pgErr.Detail, pgErr.Hint, err)
	}
}

// isUniqueViolation checks if an error is a unique constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}
