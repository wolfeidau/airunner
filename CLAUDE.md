# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `airunner`, a Go-based job orchestration platform with two main binaries:

### Binaries

- **airunner-server** (`cmd/server/main.go`) - Job queue server
  - Provides gRPC API for job management
  - Runs in-memory job store for development
  - Handles job queuing, visibility timeouts, and event streaming

- **airunner-cli** (`cmd/cli/main.go`) - Multi-purpose client
  - `worker` - Long-running job execution worker
  - `submit` - Submit jobs to the queue
  - `monitor` - Real-time job event monitoring
  - `list` - List and filter jobs

- **airunner-orchestrator** (`cmd/orchestrator/main.go`) - Future cloud backend
  - Reserved for SQS/DynamoDB/EventBridge implementation
  - Not currently implemented

The system uses Protocol Buffers for service definitions, with the main job service defined in `api/job/v1/job.proto`.

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

- **Protocol Buffers**: Uses buf for proto management with dependencies on googleapis and protovalidate
- **Job System**: The JobService provides EnqueueJob and ListJobs operations with pagination support
- **Microservices**: Three separate binaries that likely communicate via gRPC
- **Job States**: Jobs track status, timestamps, payloads, and error messages

The codebase appears to be in early stages with skeleton main.go files, suggesting active development of a distributed job processing system.

## Code Style
- **Logging**: ALWAYS use `"github.com/rs/zerolog/log"` for all logging operations
- Use `testify/require` for tests
- Error handling: return errors up the stack, log at top level
- Package names: lowercase, descriptive (buildkite, commands, trace, tokens)
- Use contexts for cancellation and tracing throughout

## Documentation Style
When creating any documentation (README files, code comments, design docs), write in the style of an Amazon engineer:
- Start with the customer problem and work backwards
- Use clear, concise, and data-driven language
- Include specific examples and concrete details
- Structure documents with clear headings and bullet points
- Focus on operational excellence, security, and scalability considerations
- Always include implementation details and edge cases
- Use the passive voice sparingly; prefer active, direct statements

## Key Files

- `api/job/v1/job.proto` - Core job service gRPC definitions
- `api/buf.yaml` - Protocol buffer configuration and linting rules  
- `go.mod` - Go module definition (requires Go 1.24.5)
- `cmd/*/main.go` - Entry points for the three main services
