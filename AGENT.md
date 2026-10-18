# AGENT.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

`airunner` is a Go job orchestration platform. Clients enqueue jobs, workers dequeue and run them, and the server persists job state and an ordered event log in PostgreSQL. Delivery is at-least-once with bounded attempts, and every job is scoped to an organization.

PostgreSQL is the only job backend. There is no in-memory job store. In-memory identity stores (`internal/store/memory`) exist only as test fakes.

### Binaries

- **airunner-server** (`cmd/server/main.go`)
  - `server` - Serves the dashboard and the Connect RPC API (`JobService`, `JobEventsService`, credential service)
  - `cleanup` - Runs one retention pass (events, jobs, expired sessions) and exits; schedule it externally when in-process retention is disabled
- **airunner-cli** (`cmd/cli/main.go`)
  - `worker` - Dequeues jobs, renews leases, runs commands, publishes events through a local WAL
  - `submit` - Enqueue a job (optionally `--monitor`)
  - `monitor` - Stream job events (`--attempt` pins an attempt)
  - `list` - List and filter jobs, `--watch` for live refresh
  - `cancel` - Cancel a scheduled or running job
  - `init`, `credentials list|show|update|delete|set-default` - Manage local signing credentials
  - `test-output`, `test-status` - Demo and test generators (`test-status` emits OSC 7501 program status reports)

The API is defined in `api/job/v1/job.proto` (Protocol Buffers, Connect RPC).

## Development Commands

```bash
make help         # Show all make targets
make build        # Build airunner-cli and airunner-server into ./bin
make build-cli
make build-server
```

**Local run** (needs `mkcert`, Docker, `direnv`, `goreman`; see `README.md`):
```bash
make certs                                   # Local TLS certs into .certs/
docker compose up -d postgres
direnv exec . goreman -f Procfile.dev start  # server (--no-auth, --postgres-auto-migrate) + worker
```

**CLI reference** (verify with `--help`; flags change):
```bash
airunner-cli worker  [--server=URL] [--queue=NAME] [--credential=NAME] [--visibility-timeout=SECONDS] [--keep-failed-wal=DURATION] [--tracing]
airunner-cli submit  [--server=URL] [--queue=NAME] [--monitor] [--config=FILE] [--command=CMD] [--args=...] <repository>
airunner-cli monitor [--server=URL] [--from-sequence=N] [--attempt=N] <job-id>
airunner-cli list    [--server=URL] [--queue=NAME] [--state=STATE] [--page=N] [--page-size=N] [--watch]
airunner-cli cancel  [--server=URL] <job-id>
airunner-cli init <name> [--set-default]
airunner-cli credentials update --org-id=ID --principal-id=ID <name>
airunner-cli test-status [--scenario=happy|blocked|fail] [--steps=N] [--step-delay=DURATION]
```

**Server flags** (`airunner-server server --help`): `--listen`, `--cert`, `--key`, `--no-auth`, `--tracing`, `--postgres-conn-string` (`$POSTGRES_CONNECTION_STRING`), `--postgres-token-signing-secret` (`$AIRUNNER_POSTGRES_TOKEN_SECRET`), `--postgres-auto-migrate`, `--postgres-default-max-attempts` (3), `--lease-reaper-interval` (5s), `--job-retention-days` (90), `--events-retention-days` (30), `--retention-interval` (1h; 0 disables in-process sweeps), `--event-poll-interval` (500ms), `--stream-send-timeout` (30s). GitHub OAuth uses `--client-id`, `--client-secret`, `--callback-url`.

**Protocol Buffers:**
```bash
make proto-generate # Generate Go code from .proto files
make proto-lint     # Lint protocol buffer files
make proto-breaking # Check for breaking changes
```

**Testing:**
```bash
make test                       # Unit tests with coverage
make test-coverage              # Tests plus coverage report
make test-integration           # All tests including the `integration` build tag (testcontainers)
make test-integration-postgres  # PostgreSQL store integration tests only
```

Integration tests use [testcontainers-go](https://golang.testcontainers.org/) to start isolated PostgreSQL containers. Docker is the only prerequisite.

**Code quality and cleanup:**
```bash
make lint          # Run linter
make lint-fix      # Run linter with auto-fix
make clean         # Clean build artifacts and coverage files
```

## Architecture Notes

### Core Packages

- **internal/store/** - Storage contracts
  - `job_store.go` - `JobStore` interface and sentinel errors
  - `postgres/` - Production `JobStore` (SKIP LOCKED dequeue, fenced token operations, reaper, retention, sessions, principals, organizations)
  - `postgres/migrations/` - Squashed schema (`1_initial_schema.sql`, `2_principal_org_fks.sql`)
  - `postgres/postgrestest/`, `internal/testutil/pgtest/` - Testcontainers PostgreSQL helpers
  - `storetest/` - Reference model and command generators for differential replay against PostgreSQL
  - `memory/` - In-memory identity stores, test fakes only
- **internal/worker/** - Job execution
  - `worker.go` - `JobExecutor` runs commands via console-stream
  - `event_batcher.go` - `EventBatcher` buffers output (defaults: 50 items, 256KB, 2s flush)
  - `wal/` - Per-attempt write-ahead log, flock, ack-validated sender, archive and stale-WAL cleanup
  - `lease/` - Lease controller: renewal at about timeout/3 with a local deadline
- **internal/server/** - Connect handlers (`job.go`, `job_event.go`), store-error to RPC-code map (`errors.go`), stream send deadline (`stream_deadline.go`)
- **internal/auth/** - JWT and session authentication, role authorization (`authz.go`)
- **internal/telemetry/** - OpenTelemetry setup, `NewMetrics`, worker metrics; `telemetrytest/` for assertions
- **internal/leasereason/** - Shared lease-loss reason labels

### Key Patterns

- **Interface-based store**: `JobStore` is the contract; `storetest` holds the reference model the PostgreSQL store is replayed against
- **Leases and fencing**: Dequeue creates an attempt and a lease. Every token operation (update, publish, complete) runs under a row lock and is rejected with `ErrLeaseLost` once the lease is gone
- **Stateless task tokens**: HMAC-SHA256 signed over job ID, queue and the per-lease receipt handle; validated in constant time
- **Contiguous events**: Sequences are contiguous per attempt; identical retries are no-ops; acknowledgment follows commit
- **Polling streams**: `StreamJobEvents` polls the database, is pinned to an attempt, and ends when the attempt closes
- **Idempotent enqueue**: Request ID tracking with a request fingerprint
- **Org scoping**: Callers are derived from authentication only, never from request fields

### PostgreSQL Backend

- Tables: `jobs`, `job_events`, `organizations`, `principals`, `sessions`, `schema_migrations` (see `internal/store/postgres/migrations/`)
- `FOR UPDATE SKIP LOCKED` for concurrent dequeue
- Lease state in `receipt_handle`, `leased_by` and `visibility_until`; the reaper returns expired leases to `SCHEDULED`, or to `FAILED` when attempts are exhausted
- Migrations run on startup with `--postgres-auto-migrate`
- Developed and tested against PostgreSQL 18 (`docker-compose.yml`, testcontainers)

### Job Lifecycle Guarantees

- States: `SCHEDULED` -> `RUNNING` -> `COMPLETED` / `FAILED` / `CANCELLED`
- At-least-once delivery. Each dequeue consumes one of `max_attempts` (default 3)
- No writes through a stale lease. Committed events survive worker loss
- Unacknowledged WAL records are lost if the lease is lost or the worker disk is lost
- A job completes only after its whole log is committed (`final_event_sequence` equals the last committed sequence)
- Cancellation stops a connected worker within about 1.25 x timeout/3 + 5s RPC + 5s grace; a partitioned worker stops at its local lease deadline

Details: `specs/job-lifecycle/00-architecture.md`. Operations: `specs/job-lifecycle/operations-runbook.md`.

## Code Style
- **Logging**: ALWAYS use `"github.com/rs/zerolog/log"` for all logging operations
- Use `testify/require` for tests
- Error handling: return errors up the stack, log at top level
- Package names: lowercase, descriptive (buildkite, commands, trace, tokens)
- Use contexts for cancellation and tracing throughout


### Error Handling Patterns

The codebase uses sentinel errors from `internal/store/job_store.go`:
```go
var (
    ErrInvalidTaskToken   = errors.New("invalid task token")
    ErrQueueMismatch      = errors.New("queue mismatch")
    ErrJobNotFound        = errors.New("job not found")
    ErrJobIDMismatch      = errors.New("job ID mismatch")
    ErrEventTooLarge      = errors.New("event exceeds maximum size")
    ErrInvalidArgument    = errors.New("invalid argument")
    ErrUnavailable        = errors.New("storage temporarily unavailable")
    ErrLeaseLost          = errors.New("lease lost")
    ErrJobCancelled       = fmt.Errorf("job cancelled: %w", ErrLeaseLost)
    ErrFailedPrecondition = errors.New("failed precondition")
    ErrConflict           = errors.New("conflict")
)
```

Use `errors.Is()` to check for specific error types. `internal/server/errors.go` maps them to RPC codes.

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

For complex features requiring significant implementation work (multi-package changes, infrastructure updates, new authentication systems), follow the **layered specification pattern** demonstrated in `specs/job-lifecycle/` and `specs/cli-credentials/`.

### When to Use Layered Specs

Use this pattern when:
- Implementation spans 3+ packages or components
- Requires infrastructure changes (Terraform, database migrations)
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
- Data models (database schemas, structs)
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
3. **Phase 3: Infrastructure** - Terraform, database migrations
4. **Phase 4: Deployment** - Production deployment, verification
5. **Phase 5: Cleanup** - Remove old code, update docs

**Checkpoint between each phase:**
- Each phase must have clear success criteria
- Must be verifiable independently
- Next phase should not start until previous succeeds

### Instructing Claude Code

When asking Claude Code to create layered specs, provide this template:

```
I need to create a layered specification for [FEATURE NAME] following the pattern in specs/job-lifecycle/.

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

Follow the pattern established in specs/job-lifecycle/ including:
- Hyperlinks between all spec files (breadcrumbs at top/bottom of each file)
- All file references as markdown links in tables and text
- Inline code for interfaces and small snippets
- Examples directory for complete implementations
- Success criteria for each phase
- Verification commands
- Mermaid diagrams where appropriate

See AGENT.md "Specification Documentation Standards" section for complete guidelines.
```


### Example: Job Lifecycle Spec

**Reference implementations:** `specs/job-lifecycle/` and `specs/cli-credentials/`

Key principles demonstrated:
- README entry point with navigation
- Architecture file with design decisions
- One file per phase, each independently actionable
- Operations runbook (`specs/job-lifecycle/operations-runbook.md`)
- Hyperlinked cross-references and breadcrumbs

## Authentication

- **CLI and workers**: JWTs signed by a local credential. Run `airunner-cli init <name>`, import the public key in the dashboard Credentials view, then `airunner-cli credentials update --org-id=... --principal-id=... <name>`
- **Dashboard**: GitHub OAuth sessions
- **Authorization**: `NewJobAuthzInterceptor` and `jobProcedureRoles` in `internal/auth/authz.go`. user/admin: EnqueueJob, ListJobs, StreamJobEvents, CancelJob. worker/admin: DequeueJob, UpdateJob, CompleteJob, PublishJobEvents. Unknown procedures fail closed
- **Development**: `--no-auth` seeds a dev org and principal with admin, user and worker roles (`internal/store/postgres/dev_identity.go`)

## Key Files

### API & Proto
- `api/job/v1/job.proto` - Job and event service definitions
- `api/buf.yaml` - Buf configuration and lint rules

### Store
- `internal/store/job_store.go` - `JobStore` interface and sentinel errors
- `internal/store/postgres/job_store.go` - PostgreSQL job store
- `internal/store/postgres/job_store_retention.go` - Retention deletes
- `internal/store/postgres/task_token.go` - Task token signing
- `internal/store/postgres/migrations/` - Schema
- `internal/store/storetest/model.go` - Reference model

### Worker
- `cmd/cli/internal/commands/worker.go` - Worker loop, lease wiring, WAL cleanup
- `internal/worker/worker.go` - `JobExecutor`
- `internal/worker/event_batcher.go` - Event batching
- `internal/worker/wal/` - WAL, sender, archive
- `internal/worker/lease/controller.go` - Lease controller

### Server
- `internal/server/server.go` - HTTP server and Connect wiring
- `internal/server/job.go`, `job_event.go` - Service implementations
- `internal/server/errors.go` - Store error to RPC code mapping
- `internal/server/stream_deadline.go` - Stream send deadline

### Auth
- `internal/auth/authz.go` - Role authorization
- `internal/auth/jwt_middleware.go`, `dual_auth_middleware.go`, `session_interceptor.go` - Authentication

### Observability
- `internal/telemetry/telemetry.go` - OpenTelemetry initialization
- `internal/telemetry/metrics.go`, `worker.go` - Metric definitions

### CLI Commands
- `cmd/cli/internal/commands/` - worker, submit, monitor, list, cancel, init, credentials, test-output, test-status

### Design Specs

**Layered specifications** (reference implementations of the pattern):
- `specs/job-lifecycle/` - Job lifecycle, tenancy, fencing, worker durability, event streams, retention, metrics, cancellation
  - Start at `specs/job-lifecycle/README.md`; Day 2 procedures in `specs/job-lifecycle/operations-runbook.md`
- `specs/cli-credentials/` - CLI credential storage and JWT signing

**Other specs:**
- `specs/wal/` - Original WAL design, superseded by `specs/job-lifecycle/04b-phase4b-worker-durability.md`
- `specs/ui-credentials/` - Dashboard credentials view
- `specs/ui_job_events_drilldown.md` - Dashboard job events drilldown

### Infrastructure
- `docker-compose.yml` - Local PostgreSQL 18
- `Procfile.dev` - Local server (`--no-auth`) and worker
- `infra/` - Terraform. **Stale**: it still sets `AIRUNNER_STORE_TYPE` and `AIRUNNER_EVENTS_TTL_DAYS`, which the server no longer reads. Do not treat it as a deployment reference
