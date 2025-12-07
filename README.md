# airunner

This is demonstrating the use of [console-stream](https://github.com/wolfeidau/console-stream) and a [connectrpc](https://connectrpc.com/) server which recieves job events, and an agent which dequeues jobs and executes them.

# Prequisites

- Go 1.25.0 or later
- make
- [mkcert](https://github.com/FiloSottile/mkcert)
- [goreman](https://github.com/mattn/goreman) or [Foreman](https://github.com/ddollar/foreman)

# Usage

Before we start you need some certs, run `make certs` to generate them. Note you will want to setup mkcert on your system to generate the certificates.

```sh
brew install mkcert
make certs
```

In a shell window run.

```sh
goreman start
```

Then open another tab and run.

```sh
go run ./cmd/cli submit --config configs/example-job.yaml "https://github.com/wolfeidau/airunner"
```

This will enqueue a job to the airunner server, then monitor the job status and output the logs and the exit status.

You can see a history of jobs by running.

```sh
go run ./cmd/cli list
```

## Architecture

Airunner is a distributed job orchestration platform that implements a job queue system with real-time event streaming. The system follows a client-server architecture similar to AWS SQS + Lambda, but designed for running arbitrary commands in Git repositories.

### Components

The system has three main binaries:

1. `airunner-server` ([`cmd/server/main.go`](cmd/server/main.go)) - Central job queue service
   - Exposes gRPC API via Connect protocol over HTTPS
   - Runs on `localhost:8080` by default with TLS
   - Uses in-memory job store for development
   - Provides `JobService` and `JobEventsService`

2. `airunner-cli` worker - Long-running job execution worker
   - Continuously polls and executes jobs
   - Maintains visibility timeouts
   - Streams execution events in real-time

3. `airunner-cli` submit/monitor/list - Client tools
   - `submit` - Add jobs to the queue (supports YAML/JSON config)
   - `monitor` - Stream real-time events for specific jobs
   - `list` - Query and filter jobs with pagination

4. `airunner-orchestrator` ([`cmd/orchestrator/main.go`](cmd/orchestrator/main.go)) - Future cloud backend
   - Reserved for SQS/DynamoDB/EventBridge implementation
   - Not currently implemented

### Job Flow

1. Job Submission
```bash
./airunner-cli submit --queue=default github.com/example/repo
```
- Creates job with repository URL, command, and environment variables
- Server stores job in `SCHEDULED` state
- Returns job ID for tracking

2. Job Dequeue (Worker pulls job)
- Worker uses long polling (100ms intervals) to wait for jobs
- Server marks job as `RUNNING` and makes it invisible for 300s
- Returns job with task token (UUID) for authentication

3. Job Execution ([`internal/worker/worker.go`](internal/worker/worker.go))
- Worker spawns process using `console-stream` library (PTY or pipe mode)
- Streams events in real-time:
  - `ProcessStart` - PID and start timestamp
  - `Output` - stdout/stderr data chunks
  - `ProcessEnd` - exit code and duration
  - `ProcessError` - error messages
- Each event gets monotonic sequence number for ordering

4. Heartbeat & Visibility
- Worker sends `UpdateJob` every 60 seconds to extend visibility timeout
- Prevents job reassignment to another worker
- If worker crashes, timeout expires and job returns to queue (at-least-once delivery)

5. Job Completion
- Worker closes event stream and reports final status
- Server updates job state to `COMPLETED` or `FAILED`
- Job remains in store for querying and monitoring

### Key Technical Details

Job Store ([`internal/store/store.go`](internal/store/store.go))
- In-memory implementation with multiple indexes:
  - `jobs` - job ID → Job
  - `queues` - queue name → FIFO job list
  - `invisibleJobs` - visibility timeout tracking
  - `taskTokens` - capability-based authentication
  - `requestIds` - idempotency (prevents duplicate submissions)
- Background cleanup task (30s interval) requeues expired jobs

Event Streaming ([`internal/server/job_event.go`](internal/server/job_event.go))
- Events stored per-job in append-only buffer
- Real-time fanout to active monitors using Go channels
- Supports replay from sequence number or timestamp
- Powers `./airunner-cli monitor <job-id>` command

This follows similar patterns from projects like loki and promtail.

Protocol Buffers ([`api/job/v1/job.proto`](api/job/v1/job.proto))
- `JobService` - EnqueueJob, DequeueJob, UpdateJob, CompleteJob, ListJobs
- `JobEventsService` - StreamJobEvents (server→client), PublishJobEvents (worker→server)
- Uses Connect protocol (gRPC over HTTP/2)

**Process Types**
- `PIPE` - Non-interactive commands (default)
- `PTY` - Interactive commands with pseudo-terminal and ANSI support

### Authentication

The server supports JWT-based authentication using ECDSA (ES256) signing:

- **Server**: Requires `JWT_PUBLIC_KEY` environment variable containing PEM-encoded public key
- **CLI**: Pass token via `--token` flag or `AIRUNNER_TOKEN` environment variable
- **Development**: Use `--no-auth` flag to disable authentication

Generate tokens using the CLI:

```bash
# Set signing key (private key PEM)
export JWT_SIGNING_KEY="$(cat private-key.pem)"

# Generate a 1-hour token
./bin/airunner-cli token --subject="user@example.com" --ttl=1h
```

Tokens require an expiration claim (`exp`) and are validated on every request except `/health`.

### Design Patterns

1. Visibility Timeout, AWS SQS pattern for at-least-once delivery
2. Task Tokens, capability-based security (only token holder can complete job)
3. Long Polling, reduces request overhead vs. short polling
4. Event Sourcing, all job state changes tracked as events
5. Server-Side Streaming, real-time monitoring without constant polling

### Current State

**Implemented:**
- Complete job queue with visibility timeouts
- Worker execution with PTY/pipe mode
- Real-time event streaming
- TLS with local certificates
- Pagination and filtering
- Idempotent job submission
- JWT authentication (ECDSA ES256)

**Not Implemented:**
- `airunner-orchestrator` (cloud backend with SQS/DynamoDB/EventBridge)
- Job persistence (currently in-memory only)
- Multi-tenancy

This provides a production-ready development environment for testing job workflows, with clear extension points for cloud deployment. The architecture is similar to Buildkite Agent or GitHub Actions runners, but self-hosted.

## License

Apache License, Version 2.0 - Copyright [Mark Wolfe](https://www.wolfe.id.au)
