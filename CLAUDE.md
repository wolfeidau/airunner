# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `airunner`, a Go-based microservices architecture with three main components:

- **Agent** (`cmd/agent/main.go`) - Job execution component
- **Orchestrator** (`cmd/orchestrator/main.go`) - Job coordination and management
- **Server** (`cmd/server/main.go`) - API server providing gRPC services

The system uses Protocol Buffers for service definitions, with the main job service defined in `api/job/v1/job.proto`.

## Development Commands

**Quick start:**
```bash
make help         # Show all available make targets
```

**Building the project:**
```bash
make build        # Build all binaries (agent, orchestrator, server)
make build-agent  # Build only the agent binary
make build-orchestrator # Build only the orchestrator binary
make build-server # Build only the server binary
```

**Running components:**
```bash
./bin/server      # Start the gRPC API server
./bin/orchestrator # Start the job orchestrator
./bin/agent       # Start a job agent
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
- Use `zerolog` for logging, `testify/require` for tests
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
