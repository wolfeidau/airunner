# AGENT.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

This is `airunner`, a Go-based job orchestration platform with production-ready AWS backend support.

### Binaries

- **airunner-server** (`cmd/server/main.go`) - Job queue server
  - Provides gRPC API via Connect RPC for job management
  - Supports in-memory store (development) or SQS/DynamoDB (production)
  - Handles job queuing, visibility timeouts, and event streaming
  - OpenTelemetry integration for metrics and tracing

- **airunner-cli** (`cmd/cli/main.go`) - Multi-purpose client
  - `worker` - Long-running job execution worker with event batching
  - `submit` - Submit jobs to the queue
  - `monitor` - Real-time job event monitoring with TUI
  - `list` - List and filter jobs with watch mode
  - `token` - Generate JWT authentication tokens

- **airunner-orchestrator** (`cmd/orchestrator/main.go`) - Cloud backend entry point
  - Uses SQS/DynamoDB backend for production deployments

The system uses Protocol Buffers with Connect RPC for service definitions, with the main job service defined in `api/job/v1/job.proto`.

## Development Commands

**Quick start:**
```bash
make help         # Show all available make targets
```

**Building the project:**
```bash
make build        # Build all binaries (airunner-cli, airunner-orchestrator, airunner-server)
make build-cli    # Build only the CLI binary
make build-agent  # Alias for build-cli (backwards compatibility)
make build-orchestrator # Build only the orchestrator binary
make build-server # Build only the server binary
```

**Usage Examples:**
```bash
# Start the server
./bin/airunner-server

# Run a worker
./bin/airunner-cli worker --server=https://localhost:8080

# Submit a job
./bin/airunner-cli submit --server=https://localhost:8080 github.com/example/repo

# Monitor job progress
./bin/airunner-cli monitor --server=https://localhost:8080 <job-id>

# List jobs
./bin/airunner-cli list --server=https://localhost:8080 --queue=default

# Watch jobs in real-time
./bin/airunner-cli list --server=https://localhost:8080 --watch
```

**CLI Command Reference:**
```bash
# Worker mode - runs continuously processing jobs
./bin/airunner-cli worker [--server=URL] [--queue=NAME] [--timeout=SECONDS]

# Submit mode - submit a single job
./bin/airunner-cli submit [--server=URL] [--queue=NAME] [OPTIONS] <repository-url>

# Monitor mode - stream events for a specific job
./bin/airunner-cli monitor [--server=URL] [--from-sequence=N] <job-id>

# List mode - list and filter jobs
./bin/airunner-cli list [--server=URL] [--queue=NAME] [--state=STATE] [--watch]
```

**Protocol Buffers:**
```bash
make proto-generate # Generate Go code from .proto files
make proto-lint     # Lint protocol buffer files
make proto-breaking # Check for breaking changes
```

**Testing:**
```bash
make test           # Run all tests with coverage
make test-coverage  # Run tests and show coverage report
```

**Local Infrastructure (for integration tests):**
```bash
docker-compose up -d  # Start local DynamoDB and LocalStack (SQS)
docker-compose down   # Stop local infrastructure
```

**Code Quality:**
```bash
make lint          # Run linter
make lint-fix      # Run linter with auto-fix
```

**Cleanup:**
```bash
make clean         # Clean build artifacts and coverage files
```

**TLS Certificates:**
```bash
make mkcert        # Generate local TLS certificates
```

## Architecture Notes

### Core Packages

- **internal/store/** - Job storage backends
  - `JobStore` interface defines the contract for all storage implementations
  - `MemoryJobStore` - In-memory FIFO queues with visibility timeouts for development
  - `SQSJobStore` - Production backend using AWS SQS for queuing and DynamoDB for persistence

- **internal/worker/** - Job execution engine
  - `JobExecutor` - Runs jobs via console-stream library with output capture
  - `EventBatcher` - Buffers output events before publishing (max 50 items, 256KB, 2s flush interval)

- **internal/server/** - HTTP/gRPC server implementation
  - `JobService` - Enqueue, dequeue, complete, list operations
  - `JobEventsService` - Publish and stream events with historical replay

- **internal/telemetry/** - Observability
  - OpenTelemetry initialization with OTLP exporters (Honeycomb-ready)
  - 20+ custom metrics for event publish/errors, job lifecycle, DynamoDB operations

- **internal/auth/** - Authentication
  - JWT verification middleware with ECDSA ES256
  - Token generation utilities

### Key Patterns

- **Interface-Based Design**: `JobStore` interface allows swapping MemoryJobStore or SQSJobStore
- **Stateless Task Tokens**: HMAC-signed tokens containing job_id, queue, receipt_handle
- **Event Streaming**: Bi-directional streaming with historical replay from DynamoDB
- **Visibility Timeout**: SQS-like job invisibility for at-least-once delivery
- **Idempotent Operations**: Request ID tracking via GSI2 for safe retries
- **Size-Aware Batching**: Conservative limits (350KB) accounting for DynamoDB 400KB limit

### AWS Backend (SQSJobStore)

The production backend uses:
- **SQS** - Job queue with visibility timeout management
- **DynamoDB Jobs Table** - Job metadata with GSI1 (queue) and GSI2 (request_id)
- **DynamoDB JobEvents Table** - Event persistence with TTL support
- Task tokens use HMAC-SHA256 signing with constant-time validation

## Code Style
- **Logging**: ALWAYS use `"github.com/rs/zerolog/log"` for all logging operations
- Use `testify/require` for tests
- Error handling: return errors up the stack, log at top level
- Package names: lowercase, descriptive (buildkite, commands, trace, tokens)
- Use contexts for cancellation and tracing throughout

### Error Handling Patterns

The codebase uses sentinel errors for common conditions:
```go
var (
    ErrInvalidTaskToken = errors.New("invalid task token")
    ErrQueueMismatch    = errors.New("queue mismatch")
    ErrJobNotFound      = errors.New("job not found")
    ErrThrottled        = errors.New("AWS request throttled")
    ErrEventTooLarge    = errors.New("event exceeds maximum size")
)
```

AWS errors are wrapped with `wrapAWSError()` which identifies throttling and size violations. Use `errors.Is()` to check for specific error types.

## Documentation Style
When creating any documentation (README files, code comments, design docs), write in the style of an Amazon engineer:
- Start with the customer problem and work backwards
- Use clear, concise, and data-driven language
- Include specific examples and concrete details
- Structure documents with clear headings and bullet points
- Focus on operational excellence, security, and scalability considerations
- Always include implementation details and edge cases
- Use the passive voice sparingly; prefer active, direct statements

## Authentication

JWT-based authentication using ECDSA ES256:

- **Server**: Pass public key via `JWT_PUBLIC_KEY` env var (PEM-encoded)
- **CLI**: Pass token via `--token` flag or `AIRUNNER_TOKEN` env var
- **Development**: Use `--no-auth` flag to disable authentication
- **Token generation**: `./bin/airunner-cli token --subject=<user> --ttl=1h`

Key files:
- `internal/auth/jwt.go` - JWT verification middleware
- `internal/auth/token.go` - Token generation
- `specs/api_auth.md` - Full authentication design spec

## Key Files

### API & Proto
- `api/job/v1/job.proto` - Core job service gRPC definitions
- `api/buf.yaml` - Protocol buffer configuration and linting rules

### Store Implementations
- `internal/store/store.go` - `JobStore` interface and `MemoryJobStore`
- `internal/store/sqs_store.go` - `SQSJobStore` with SQS/DynamoDB backend

### Worker & Event Processing
- `internal/worker/worker.go` - `JobExecutor` for running jobs
- `internal/worker/event_batcher.go` - Event batching with configurable flush thresholds

### Server
- `internal/server/server.go` - HTTP server setup with Connect RPC
- `internal/server/job.go` - JobService implementation
- `internal/server/job_event.go` - JobEventsService implementation

### Observability
- `internal/telemetry/telemetry.go` - OpenTelemetry initialization
- `internal/telemetry/metrics.go` - Custom metrics definitions

### Authentication
- `internal/auth/jwt.go` - JWT verification middleware
- `internal/auth/token.go` - Token generation

### CLI Commands
- `cmd/cli/internal/commands/` - Worker, submit, monitor, list, token commands

### Design Specs
- `specs/sqs_dynamodb_backend.md` - AWS backend architecture
- `specs/event_batching.md` - Event batching design
- `specs/api_auth.md` - Authentication specification

### Infrastructure
- `infra/` - Terraform configuration for AWS resources
- `docker-compose.yml` - Local DynamoDB and LocalStack for testing
