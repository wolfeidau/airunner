# PostgreSQL Auto-Migration Control with Testcontainers

## Overview

Add migration control flag and use testcontainers-go for integration tests.

**Scope**: ~40 lines across 4 files
**Complexity**: Low - configuration changes and testcontainers integration

## User Requirements

1. **Migration Control**: Add `--postgres-auto-migrate` flag (default: `false`)
   - Migrations are opt-in, not automatic
   - Production environments run migrations explicitly

2. **Test Isolation**: Use testcontainers-go for integration tests
   - Tests spin up ephemeral postgres containers
   - No shared database state between test runs
   - docker-compose is only for local development

## Current State

- Migrations run unconditionally in `NewJobStore()` at line 77 of `job_store.go`
- Integration tests use docker-compose postgres with manual TRUNCATE
- Tests depend on external database being available

## Implementation Plan

### 1. Add AutoMigrate Field to Config

**File**: `internal/store/postgres/config.go`

Add field after line 43 (after `MaxConnIdleTime`):
```go
// AutoMigrate controls whether migrations run automatically on startup.
// Default: false (migrations must be explicitly enabled)
AutoMigrate bool
```

### 2. Conditional Migration Execution

**File**: `internal/store/postgres/job_store.go`

Replace lines 76-80:
```go
// Run migrations only if explicitly enabled
if cfg.AutoMigrate {
    if err := runMigrations(ctx, pool); err != nil {
        pool.Close()
        return nil, fmt.Errorf("failed to run migrations: %w", err)
    }
    log.Info().Msg("Database migrations completed")
}
```

### 3. Add CLI Flag

**File**: `cmd/server/internal/commands/rpc.go`

Add to `PostgresStoreFlags` after line 77:
```go
// Migration Configuration
AutoMigrate bool `help:"run database migrations on startup" default:"false" env:"AIRUNNER_POSTGRES_AUTO_MIGRATE"`
```

Add to `createPostgresJobStore()` storeCfg after line 359:
```go
AutoMigrate:        cmd.PostgresStore.AutoMigrate,
```

### 4. Use Testcontainers for Integration Tests

**File**: `internal/store/postgres/job_store_integration_test.go`

Replace the connection string logic (lines 18-22) and add testcontainers setup:

```go
import (
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgresContainer(t *testing.T, ctx context.Context) (store *JobStore, cleanup func()) {
    // Start postgres container
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
    require.NoError(t, err)

    host, err := container.Host(ctx)
    require.NoError(t, err)

    port, err := container.MappedPort(ctx, "5432")
    require.NoError(t, err)

    connString := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())

    // Create store with auto-migrate enabled
    cfg := &JobStoreConfig{
        ConnString:         connString,
        TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
        AutoMigrate:        true,  // Enable migrations for tests
    }

    store, err := NewJobStore(ctx, cfg)
    require.NoError(t, err)

    err = store.Start()
    require.NoError(t, err)

    cleanup = func() {
        store.Stop()
        container.Terminate(ctx)
    }

    return store, cleanup
}
```

Update each test to use the helper:
```go
func TestIntegration_BasicJobLifecycle(t *testing.T) {
    ctx := context.Background()
    store, cleanup := setupPostgresContainer(t, ctx)
    defer cleanup()

    // ... rest of test
}
```

### 5. Update Documentation

**File**: `AGENT.md`

Add section (find appropriate location):

```markdown
## PostgreSQL Store

### Database Migrations

The PostgreSQL store uses embedded SQL migrations (in `internal/store/postgres/migrations/`). Migrations are opt-in and must be explicitly enabled.

**Running Migrations:**
```bash
# Enable auto-migration on server startup
./bin/airunner-server --store-type=postgres --postgres-auto-migrate

# Or via environment variable
AIRUNNER_POSTGRES_AUTO_MIGRATE=true ./bin/airunner-server --store-type=postgres
```

**Environment Variables:**
- `POSTGRES_CONNECTION_STRING` - Database connection string (required)
- `AIRUNNER_POSTGRES_AUTO_MIGRATE` - Set to `true` to run migrations on startup (default: `false`)

**Integration Testing:**
Integration tests use testcontainers-go to spin up ephemeral postgres containers. No external database required for running tests.
```

## Implementation Order

1. **Phase 1: Core Config Changes**
   - Update `config.go` - add AutoMigrate field
   - Update `job_store.go` - conditional migration logic
   - Update `rpc.go` - add CLI flag
   - ✅ Verify: Code compiles

2. **Phase 2: Testcontainers Integration**
   - Add testcontainers-go dependency
   - Update `job_store_integration_test.go` - use testcontainers
   - Update both test functions to use setupPostgresContainer
   - ✅ Verify: Integration tests pass

3. **Phase 3: Documentation**
   - Update `AGENT.md`
   - ✅ Verify: Documentation is clear

## Testing Checklist

- [ ] Code compiles successfully
- [ ] Server starts without migrations (default behavior)
- [ ] Server runs migrations with `--postgres-auto-migrate` flag
- [ ] Integration tests pass using testcontainers (no external postgres needed)
- [ ] Tests create isolated postgres containers
- [ ] Migrations run automatically in test containers (AutoMigrate: true)

## Setup for Development

```bash
# Start postgres for local development
docker-compose up -d postgres

# Run server with migrations enabled (first time)
./bin/airunner-server --store-type=postgres --postgres-auto-migrate

# Run integration tests (no external database needed)
go test -tags=integration ./internal/store/postgres/...
```


## Files to Modify

| File | Lines | Type |
|------|-------|------|
| `internal/store/postgres/config.go` | +3 | Add AutoMigrate field |
| `internal/store/postgres/job_store.go` | ~6 | Conditional migration |
| `cmd/server/internal/commands/rpc.go` | +3 | CLI flag |
| `internal/store/postgres/job_store_integration_test.go` | ~55 | Testcontainers integration |
| `go.mod` | +1 | Add testcontainers dependency |

**Total**: ~68 lines across 5 files (mostly testcontainers boilerplate)

## Summary

Clean separation of development and testing:
- ✅ Migrations are opt-in (default: disabled)
- ✅ Integration tests use testcontainers-go (no external database)
- ✅ docker-compose only for local development
- ✅ Tests are fully isolated and portable
- ✅ No manual database setup required for tests
