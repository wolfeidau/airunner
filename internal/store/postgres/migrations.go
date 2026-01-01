package postgres

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// runMigrations executes all pending database migrations in order.
// Migrations are tracked in the schema_migrations table.
// Returns an error if any migration fails.
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	log.Info().Msg("Running database migrations")

	// Read all migration files
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Parse and sort migration files by version number
	type migration struct {
		version int
		name    string
		content string
	}

	var migrations []migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		// Extract version number from filename (e.g., "1_initial_schema.sql" -> 1)
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) < 2 {
			log.Warn().Str("file", entry.Name()).Msg("Skipping migration file with invalid name format")
			continue
		}

		version, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Warn().Str("file", entry.Name()).Err(err).Msg("Skipping migration file with invalid version number")
			continue
		}

		// Read migration content
		content, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, migration{
			version: version,
			name:    entry.Name(),
			content: string(content),
		})
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	log.Info().Int("count", len(migrations)).Msg("Found migration files")

	// Execute migrations in order
	for _, m := range migrations {
		if err := executeMigration(ctx, pool, m.version, m.name, m.content); err != nil {
			return fmt.Errorf("migration %s failed: %w", m.name, err)
		}
	}

	log.Info().Msg("All migrations completed successfully")
	return nil
}

// executeMigration runs a single migration if it hasn't been applied yet.
func executeMigration(ctx context.Context, pool *pgxpool.Pool, version int, name string, content string) error {
	// Check if migration already applied (outside transaction to avoid abort on table not existing)
	var applied bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM schema_migrations WHERE version = $1
		)
	`, version).Scan(&applied)

	// If schema_migrations table doesn't exist yet, assume migration not applied
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			applied = false
		} else {
			return fmt.Errorf("failed to check migration status: %w", err)
		}
	}

	if applied {
		log.Debug().Int("version", version).Str("name", name).Msg("Migration already applied, skipping")
		return nil
	}

	// Start transaction for migration
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is safe to call after commit

	// Execute migration
	log.Info().Int("version", version).Str("name", name).Msg("Applying migration")
	_, err = tx.Exec(ctx, content)
	if err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	log.Info().Int("version", version).Str("name", name).Msg("Migration applied successfully")
	return nil
}
