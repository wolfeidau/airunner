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

## Specification Documentation Standards

For complex features requiring significant implementation work (multi-package changes, infrastructure updates, new authentication systems), follow the **layered specification pattern** demonstrated in `specs/mtls/`.

### When to Use Layered Specs

Use this pattern when:
- Implementation spans 3+ packages or components
- Requires infrastructure changes (Terraform, AWS resources)
- Involves architectural decisions with multiple approaches
- Takes 7+ hours to implement
- Benefits from phase-by-phase execution

**Do NOT use for:**
- Simple bug fixes or single-file changes
- Documentation-only updates
- Trivial feature additions

### Layered Spec Structure

```
specs/<feature-name>/
├── README.md                    ← Entry point & navigation guide
├── 00-architecture.md           ← Design decisions, diagrams, data models
├── 01-phase1-<name>.md         ← First implementation phase
├── 02-phase2-<name>.md         ← Second implementation phase
├── 03-phase3-<name>.md         ← Third implementation phase
├── ...                          ← Additional phases as needed
├── operations-runbook.md        ← Day 2 operational procedures
├── ARCHIVE_*.md                 ← Original consolidated spec (if migrated)
└── examples/                    ← Complete code examples
    ├── <package1>/              ← Examples organized by package
    ├── <package2>/
    └── <package3>/
```

### File Guidelines

**Navigation and Hyperlinks:**
- All spec files MUST include markdown hyperlinks to related files
- Use breadcrumb navigation at top and bottom of each file (e.g., `[← README](README.md) | [Next Phase →](02-phase2.md)`)
- Link all file references in tables and text (e.g., `[00-architecture.md](00-architecture.md)` not `00-architecture.md`)
- Create a navigation section in README with direct links to all major files
- This dramatically improves navigation when viewing on GitHub or in markdown viewers

**README.md** (250-400 lines):
- Overview of what the feature provides
- Prerequisites (tools, access, knowledge)
- Quick start guide (5-step summary) with links to phase files
- File navigation table with hyperlinks and duration estimates
- Phase-by-phase execution guide with success criteria and links
- Troubleshooting section
- Next steps with links

**00-architecture.md** (400-800 lines):
- Breadcrumb navigation at top: `[← README](README.md) | [Phase 1 →](01-phase1.md)`
- Summary and goals (what/why)
- Design decisions and trade-offs
- Architecture diagrams (Mermaid)
- Data models (DynamoDB schemas, structs)
- Key concepts and terminology
- References to example code (with links to phase files where applicable)
- Breadcrumb navigation at bottom

**Phase Files** (250-500 lines each):
- Breadcrumb navigation at top: `[← README](README.md) | [← Previous](01-phase1.md) | [Next →](03-phase3.md)`
- Clear goal and duration estimate
- Prerequisites (previous phase completion)
- Success criteria (checkboxes)
- Package-by-package implementation guide
- Code snippets for interfaces and key patterns (inline)
- References to complete implementations in examples/ (with links)
- Verification steps with specific commands
- Next phase reference with hyperlink
- Breadcrumb navigation at bottom (same as top)

**operations-runbook.md** (300-500 lines):
- Breadcrumb navigation at top: `[← README](README.md) | [Architecture](00-architecture.md) | [Deployment](04-phase4.md)`
- Common operational procedures
- Emergency procedures
- Monitoring and alerting guidance
- Troubleshooting scenarios
- Metrics definitions
- AWS CLI commands for manual operations
- Additional Resources section with links to all spec files
- Breadcrumb navigation at bottom

**examples/** directory:
- **Complete files** for small, critical code (interfaces, small utilities)
- **Reference/skeleton files** for large implementations (500+ lines)
- Organized by package structure (mirrors actual codebase)
- Include comments about imports and dependencies
- Reference back to original spec line numbers for full implementations

### Code in Specs: Inline vs Examples

**Keep inline in spec files:**
- Interface definitions (<100 lines)
- Struct definitions (<50 lines)
- Key method signatures
- Small code snippets demonstrating patterns (<30 lines)
- Configuration examples (<50 lines)
- All Mermaid diagrams
- All tables and matrices

**Move to examples/ directory:**
- Complete implementations (>100 lines)
- Full file contents (even if <100 lines, if it's a complete file)
- Large Terraform modules (>80 lines)
- Complete CLI commands (>200 lines)
- Any code that would be copy-pasted wholesale

### Phase Organization

Organize phases by natural implementation flow:

1. **Phase 1: Core Code** - Interfaces, core logic, no infrastructure
2. **Phase 2: Integration** - Local testing, docker-compose, integration tests
3. **Phase 3: Infrastructure** - Terraform, AWS resources
4. **Phase 4: Deployment** - Production deployment, verification
5. **Phase 5: Cleanup** - Remove old code, update docs

**Checkpoint between each phase:**
- Each phase must have clear success criteria
- Must be verifiable independently
- Next phase should not start until previous succeeds

### Instructing Claude Code

When asking Claude Code to create layered specs, provide this template:

```
I need to create a layered specification for [FEATURE NAME] following the pattern in specs/mtls/.

The feature involves:
- [List key components/packages affected]
- [Infrastructure changes needed]
- [Estimated complexity: X hours]

Please create a layered spec structure with:
1. README.md as entry point
2. 00-architecture.md with design decisions and diagrams
3. Phase files (01-0X) for sequential implementation
4. operations-runbook.md for Day 2 operations
5. examples/ directory with code references

Follow the pattern established in specs/mtls/ including:
- Hyperlinks between all spec files (breadcrumbs at top/bottom of each file)
- All file references as markdown links in tables and text
- Inline code for interfaces and small snippets
- Examples directory for complete implementations
- Success criteria for each phase
- Verification commands
- Mermaid diagrams where appropriate

See AGENT.md "Specification Documentation Standards" section for complete guidelines.
```

### Example: mTLS Authentication Spec

**Reference implementation:** `specs/mtls/`

This spec demonstrates:
- ✅ Clear README with navigation and quick start
- ✅ Architecture file with design decisions and Mermaid diagrams
- ✅ 5 phase files for sequential implementation
- ✅ Operations runbook with procedures and metrics
- ✅ Examples directory with 12 code reference files
- ✅ Original 3,056-line spec archived for reference
- ✅ Each phase independently actionable
- ✅ Total: 3,062 lines across 8 focused spec files

**Key principles demonstrated:**
- Each file is independently readable
- Cross-references between files are clear and use hyperlinks
- Breadcrumb navigation at top and bottom of every file
- All file references in tables and text are clickable links
- Developers can start at README and execute sequentially
- Easy navigation when viewing on GitHub or in markdown viewers
- Examples are copy-paste ready when needed
- Original consolidated spec preserved for reference

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

**Layered Specifications** (follow this pattern for complex features):
- `specs/mtls/` - mTLS authentication (layered spec with 5 phases, examples, runbook)
  - See `specs/mtls/README.md` for entry point
  - Reference implementation of layered spec pattern

**Legacy Specifications** (deprecated, archived):
- `specs/sqs_dynamodb_backend.md` - AWS backend architecture (archived)
- `specs/event_batching.md` - Event batching design (archived)
- `specs/api_auth.md` - JWT authentication (deprecated, see specs/mtls/)

### Infrastructure
- `infra/` - Terraform configuration for AWS resources
- `docker-compose.yml` - Local DynamoDB and LocalStack for testing
