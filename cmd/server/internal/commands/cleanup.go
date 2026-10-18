package commands

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/wolfeidau/airunner/internal/logger"
	postgresstore "github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

// CleanupCmd runs one retention pass and exits, for use from cron, an ECS scheduled task or
// a Kubernetes CronJob. It requires an existing schema and never runs migrations.
//
// It reuses PostgresStoreFlags, so the token signing secret must be set (normally already
// present in the deployment environment) even though cleanup does not sign tokens.
type CleanupCmd struct {
	Retention  RetentionFlags `embed:""`
	MaxBatches int            `help:"maximum batches per category per pass (events, jobs, sessions)" default:"100" env:"AIRUNNER_CLEANUP_MAX_BATCHES"`
	Tracing    bool           `help:"enable tracing and metrics export" default:"false" env:"AIRUNNER_TRACING"`

	PostgresStore PostgresStoreFlags `embed:"" prefix:"postgres-"`
}

// Run executes one cleanup pass. It returns an error if any category failed; a pass that
// stops with backlog remaining only logs a warning.
func (c *CleanupCmd) Run(globals *Globals) error {
	log := logger.Setup(globals.Debug)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	jobRetention, eventRetention, err := c.Retention.Durations()
	if err != nil {
		return err
	}
	if c.MaxBatches <= 0 {
		return errors.New("--max-batches must be positive")
	}
	if err = c.PostgresStore.Validate(); err != nil {
		return err
	}

	if c.Tracing {
		shutdown, tErr := telemetry.InitTelemetry(ctx, "airunner-cleanup", globals.Version)
		if tErr != nil {
			log.Warn().Err(tErr).Msg("Failed to initialize telemetry, continuing without metrics")
		} else {
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if sErr := shutdown(shutdownCtx); sErr != nil {
					log.Error().Err(sErr).Msg("Failed to shutdown telemetry")
				}
			}()
		}
	}

	pool, err := postgresstore.NewPool(ctx, &postgresstore.PoolConfig{
		ConnString:      c.PostgresStore.ConnString,
		MaxConns:        c.PostgresStore.MaxConns,
		MinConns:        c.PostgresStore.MinConns,
		MaxConnLifetime: c.PostgresStore.MaxConnLifetime,
		MaxConnIdleTime: c.PostgresStore.MaxConnIdleTime,
	})
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}
	defer pool.Close()

	// The job store is intentionally not started: no reaper, monitor or retention loop.
	jobStore, err := postgresstore.NewJobStore(pool, &postgresstore.JobStoreConfig{
		TokenSigningSecret:   []byte(c.PostgresStore.TokenSigningSecret),
		DefaultMaxAttempts:   c.PostgresStore.DefaultMaxAttempts,
		JobRetention:         jobRetention,
		EventRetention:       eventRetention,
		DisableRetentionLoop: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create job store: %w", err)
	}

	report, retErr := jobStore.SweepRetention(ctx, c.MaxBatches)

	sessions, sessionsDrained, sessErr := postgresstore.SweepExpiredSessions(ctx, postgresstore.NewSessionStore(pool), sessionSweepBatch, c.MaxBatches)
	if sessions > 0 {
		telemetry.GetMetrics().RetentionSessionsDeleted.Add(ctx, int64(sessions))
	}
	if sessErr != nil {
		log.Error().Err(sessErr).Msg("Session sweep failed")
	}

	complete := report.Complete && sessionsDrained
	ev := log.Info()
	if retErr != nil || sessErr != nil {
		ev = log.Error()
	} else if !complete {
		ev = log.Warn()
	}
	ev.Int("events_deleted", report.EventsDeleted).
		Int("jobs_deleted", report.JobsDeleted).
		Int("sessions_deleted", sessions).
		Bool("retention_complete", report.Complete).
		Bool("sessions_complete", sessionsDrained).
		Msg("Cleanup finished")

	if err = errors.Join(retErr, sessErr); err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}
	if !complete {
		log.Warn().Msg("Backlog remains; the next scheduled run will continue, or raise --max-batches")
	}
	return nil
}
