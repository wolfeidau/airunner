//go:build integration

// Package pgtest provides isolated PostgreSQL databases for integration tests.
// It imports no repository packages so it can be used from internal tests of
// any package without creating an import cycle.
package pgtest

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	once      sync.Once
	adminConn string
	startErr  error
	dbCounter atomic.Int64
)

// startContainer starts one postgres container per test binary. It is never
// explicitly terminated; testcontainers' reaper removes it when the binary exits.
func startContainer() (string, error) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:18-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to start postgres container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get container host: %w", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return "", fmt.Errorf("failed to get container port: %w", err)
	}

	return fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port()), nil
}

// NewDatabase creates a uniquely named database on a shared postgres container
// and returns its connection string. The database is dropped on test cleanup.
func NewDatabase(t testing.TB) string {
	t.Helper()

	once.Do(func() {
		adminConn, startErr = startContainer()
	})
	require.NoError(t, startErr)

	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminConn)
	require.NoError(t, err)
	defer admin.Close(ctx) //nolint:errcheck // best-effort close

	name := fmt.Sprintf("test_%d_%d", time.Now().UnixNano(), dbCounter.Add(1))
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx := context.Background()
		c, err := pgx.Connect(ctx, adminConn)
		if err != nil {
			t.Logf("pgtest: failed to connect for drop of %s: %v", name, err)
			return
		}
		defer c.Close(ctx) //nolint:errcheck // best-effort close

		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("pgtest: failed to drop database %s: %v", name, err)
		}
	})

	u, err := url.Parse(adminConn)
	require.NoError(t, err)
	u.Path = "/" + strings.TrimPrefix(name, "/")

	return u.String()
}
