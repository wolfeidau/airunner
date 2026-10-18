# Phase 3: Tenancy, authorization, and lifecycle wiring

[← README](README.md) | [← Phase 2](02-phase2-schema-contract.md) | [Phase 4a →](04a-phase4a-fencing.md)

**Goal:** every job RPC enforces the caller's role. Store errors reach clients with consistent Connect codes. The schema guarantees that creators and leasers belong to the job's org. The job store can be started and stopped safely.

**Depends on:** [phase 2](02-phase2-schema-contract.md) (org-scoped schema, `store.Caller`, dev identity seed).

## Customer problem

After phase 2, every query was scoped to the caller's org, but any authenticated principal could still call any job RPC. A browser session could dequeue and complete jobs, and a worker credential could enqueue and list them. Clients also saw the same failure under different codes: a stale task token returned InvalidArgument, while an unknown store error leaked its cause as Internal. `JobStore.Stop` panicked when called twice, blocked on connected stream clients, and closed a connection pool that it did not own.

## Success criteria

- [ ] Job and events RPCs are rejected by role before handler or store access.
- [ ] Unknown job-service procedures fail closed.
- [ ] A coverage test fails when an RPC is added without a role mapping.
- [ ] `TestRepro_JobHandlersEnforceRoles` passes un-skipped.
- [ ] An admin cannot read, list, or dequeue another org's jobs.
- [ ] All job and events handlers use one shared error mapper.
- [ ] A failed token operation returns FailedPrecondition and does not reveal which check failed.
- [ ] Composite foreign keys reject a creator or leaser from another org.
- [ ] `Start` and `Stop` are idempotent, and restarting after `Stop` returns an error.
- [ ] `Stop` releases blocked streams within 10s and never closes the shared pool.

## Authorization

[internal/auth/authz.go](../../internal/auth/authz.go) provides `NewJobAuthzInterceptor`. It wraps unary and streaming handlers. [internal/server/server.go](../../internal/server/server.go) applies it to JobService and JobEventsService, after the logging and otel interceptors, so denials are still logged and traced. CredentialService keeps its own inline admin checks.

| RPC | user | worker | admin |
|---|---|---|---|
| EnqueueJob, ListJobs, StreamJobEvents, CancelJob | yes | | yes |
| DequeueJob, UpdateJob, CompleteJob, PublishJobEvents | | yes | yes |

**Precedence:**
1. No principal: Unauthenticated.
2. A principal with no allowed role: PermissionDenied.
3. An unknown procedure under `/job.v1.JobService/` or `/job.v1.JobEventsService/`: PermissionDenied (fails closed).

**Edge cases:**
- Connect returns 404 for an unknown procedure before any interceptor runs, so unit tests exercise the fail-closed branch on the interceptor directly.
- Admin is scoped to its org. Store queries filter by `caller.OrgID`, so an admin in org A receives NotFound for org B's job, as any other caller does.
- Admin does not bypass lease ownership. Phase 4 adds the leasing-principal fence.
- Login users receive `admin,user`, and imported worker credentials receive `worker`. Under `--no-auth` the development principal holds all three roles.

## Error mapping

[internal/server/errors.go](../../internal/server/errors.go) provides `toConnectError`, which every job and events handler uses.

| Store error | Connect code |
|---|---|
| existing `*connect.Error` | passthrough |
| `ErrInvalidTaskToken`, `ErrInvalidArgument`, `ErrJobIDMismatch`, `ErrQueueMismatch` | InvalidArgument |
| `ErrEventTooLarge` | ResourceExhausted |
| `ErrJobNotFound` | NotFound |
| `ErrLeaseLost` | FailedPrecondition |
| `ErrConflict` | AlreadyExists |
| `context.DeadlineExceeded` / `context.Canceled` | DeadlineExceeded / Canceled |
| anything else | Internal, with a generic message; the cause is logged server-side |

Token operations (UpdateJob, CompleteJob, release, PublishJobEvents) return `ErrLeaseLost` for an absent job, a job in another org, a wrong receipt, or a job that is not RUNNING. The error does not say which check failed. Receipt fencing on publish, the leasing-principal check, and post-lock `clock_timestamp()` expiry arrive in phase 4.

## Org-membership constraints

[Migration 2](../../internal/store/postgres/migrations/2_principal_org_fks.sql) adds `UNIQUE (principal_id, org_id)` on principals. It replaces the single-column foreign keys with composite ones:

- `jobs(created_by, org_id) → principals(principal_id, org_id)`
- `jobs(leased_by, org_id) → principals(principal_id, org_id)`. This key uses MATCH SIMPLE, so a NULL `leased_by` on a non-RUNNING row passes.

This is a separate migration so that local databases created in phase 2 need no reset. Phase 7 may squash it.

## Store lifecycle

| Call | Behaviour |
|---|---|
| `Start` (new) | creates the lifecycle context and starts pool monitoring |
| `Start` (started) | no-op |
| `Start` (stopped) | error; restart is not supported |
| `Stop` (started) | cancels the lifecycle context and waits up to 10s for tasks and streams |
| `Stop` (new or stopped) | no-op |
| `StreamEvents` (not started) | error |

- Each stream ends when either its request context or the lifecycle context ends.
- The producer goroutine is the only closer of its channel. It deregisters under the write lock and then closes the channel, while fanout sends under the read lock. This makes a send on a closed channel impossible.
- The server owns the shared pool. Deferred calls run in LIFO order: HTTP serving stops, then the revocation checker, then the job store, and finally the pool closes.

## Deferred behaviour

| Item | Phase |
|---|---|
| Leasing-principal fence, `clock_timestamp()` expiry, publish receipt fencing, reaper, polling streams | 4 |
| `authz.denied` and the other metrics; retention and session sweeps | 5 |
| CancelJob transition and CLI | 6 |

## Verification

```bash
go test -race ./internal/auth/ ./internal/server/                     # authz matrix, coverage, error mapper
go test -tags integration -race ./internal/server/ ./internal/store/... # RPC codes, org boundary, FKs, lifecycle, replay
go test -tags integration -race -count=5 -run 'Lifecycle|Stop' ./internal/store/postgres/
make lint test proto-lint
```

[← README](README.md) | [← Phase 2](02-phase2-schema-contract.md) | [Phase 4a →](04a-phase4a-fencing.md)
