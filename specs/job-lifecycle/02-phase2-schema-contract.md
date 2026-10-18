# Phase 2: Schema and contract

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [Phase 3 →](03-phase3-tenancy-authz.md)

**Goal:** establish the data contract that later phases build on: an org-scoped squashed schema, the new protocol fields, a `Caller`-aware store interface, PostgreSQL as the only job backend, and an independent reference model that checks the store.

**Depends on:** phase 1 (worker events, PR #152).

**Status:** this phase introduces contract fields and data structures. Behavioural guarantees, including fencing, the reaper, polling streams, retention and cancellation, remain in phases 3–6. Fields declared here but not yet honoured are listed under [Deferred behaviour](#deferred-behaviour).

## Customer problem

Jobs had no organization boundary. `request_id` was globally unique, the dequeue index predicate never matched SCHEDULED rows, and events had no attempt identity. Every later fix (fenced leases, per-attempt logs, retention) needs these columns and protocol fields first, and needs a test oracle that does not reuse the code under test.

## Success criteria

- [ ] Migrations 1–3 squashed into [1_initial_schema.sql](../../internal/store/postgres/migrations/1_initial_schema.sql); fresh and repeated application succeed.
- [ ] Jobs carry `org_id`, `created_by`, `leased_by`, `attempt`, `max_attempts`, `last_event_sequence`, `request_fingerprint`; CHECKs enforce lease columns ⇔ RUNNING.
- [ ] Events keyed `(job_id, attempt, sequence)` with `end_sequence`; no `ttl` column.
- [ ] `idx_jobs_dequeue` predicate is `state = 1`, and the dequeue SQL uses literal states (`TestRepro_DequeueIndexPredicateMatchesScheduledState` un-skipped and passing).
- [ ] Every caller-facing [JobStore](../../internal/store/job_store.go) method takes `store.Caller`; all queries are org-scoped.
- [ ] Request IDs are unique per org; a changed intent under an existing ID returns `store.ErrConflict`.
- [ ] Memory JobStore and the memory server backend are deleted; `--no-auth` seeds a fixed development identity in PostgreSQL.
- [ ] `PublishJobEvents` is unary; `CancelJob` exists and returns Unimplemented.
- [ ] Lifecycle reference model in [internal/store/storetest](../../internal/store/storetest/) passes boundary, property, and fuzz tests without Docker.
- [ ] Differential replay of 200 seeded histories agrees with PostgreSQL for the enabled operation set.

## Schema

See [1_initial_schema.sql](../../internal/store/postgres/migrations/1_initial_schema.sql). Key invariants:

| Constraint | Rule |
|---|---|
| `jobs_lease_consistency` | `state = 2` ⇔ `visibility_until`, `receipt_handle`, `leased_by` all set, and `attempt > 0` |
| `jobs_attempt_bounds` | `0 <= attempt <= max_attempts` |
| `jobs_max_attempts_bounds` | `1 <= max_attempts <= 100` |
| `jobs_org_request_id_key` | `UNIQUE (org_id, request_id)` |
| `state` | `BETWEEN 1 AND 5`, no default; matches `JobState` |
| `job_events` PK | `(job_id, attempt, sequence)`, `sequence > 0`, `end_sequence >= sequence` |

| Index | Definition | Used by |
|---|---|---|
| `idx_jobs_dequeue` | `(org_id, queue, created_at, job_id) WHERE state = 1` | DequeueJobs |
| `idx_jobs_lease` | `(visibility_until, job_id) WHERE state = 2` | reaper (phase 4) |
| `idx_jobs_list` | `(org_id, queue, state, created_at, job_id)` | ListJobs |
| `idx_jobs_retention` | `(updated_at, job_id) WHERE state IN (3,4,5)` | retention (phase 5) |

**Edge case:** a generic prepared plan cannot use a partial index when the state is a bound parameter. Every lifecycle query writes state as a literal; see [Validated assumptions](../job-lifecycle-tenancy-redesign-plan.md#validated-assumptions-and-repro-tests).

**Reset:** an existing database with version 1 recorded must be recreated (`docker compose down -v`). This deletes local identities; re-bootstrap afterwards.

## Store contract

```go
type Caller struct {
	OrgID       uuid.UUID
	PrincipalID uuid.UUID
}

type PublishResult struct {
	Attempt                     int32
	AcknowledgedThroughSequence int64
}
```

- **Enqueue:** inserts state 1, attempt 0, and `max_attempts` from the request or `--default-max-attempts` (default 3). It rejects values outside 1–100.
- **Fingerprint:** SHA-256 over the length-prefixed queue, the deterministic `job_params` encoding, and the max-attempts presence and value. `execution_config` is excluded because the server supplies it.
- **Dequeue:** `state = 1 AND attempt < max_attempts`, oldest first, `FOR UPDATE SKIP LOCKED`. Each acquisition increments `attempt`, resets `last_event_sequence` and `result`, and sets `leased_by`.
- **Release:** returns the job to SCHEDULED while attempts remain; otherwise FAILED. Every non-RUNNING transition clears all lease columns.
- **Publish:** stamps the job row's attempt into the column and payload and sets `end_sequence` (the output-batch end, or the sequence otherwise). It returns the attempt and the highest covered sequence.
- **New errors:** `ErrLeaseLost`, `ErrConflict`. `ErrThrottled` (an AWS leftover) is removed.

## Protocol changes

| Message / RPC | Change |
|---|---|
| `JobEvent` | `attempt = 20` |
| `Job` | `attempt = 7`, `max_attempts = 8` |
| `EnqueueJobRequest` | `optional int32 max_attempts = 4` |
| `DequeueJobResponse`, `UpdateJobResponse` | effective `visibility_timeout_seconds` |
| `UpdateJobRequest` | `queue` removed; field 1 and name reserved |
| `CompleteJobRequest` | `final_event_sequence = 3` |
| `PublishJobEvents` | client stream → unary; response `{attempt, acknowledged_through_sequence}` |
| `StreamJobEventsRequest` | `attempt = 5` |
| `StreamJobEventsResponse` | `resolved_attempt`, `job_state`, `attempt_closed` |
| `CancelJob` | new RPC on JobService |

**Expected `make proto-breaking` failures:** PublishJobEvents cardinality, and removal of `UpdateJobRequest.queue`. Any other incompatibility needs review.

## Caller propagation and development identity

Handlers derive `store.Caller` from `auth.PrincipalFromContext`; a missing principal returns Unauthenticated. Role checks remain phase 3.

This work moved from phase 3 into phase 2: the new foreign keys make an org and principal mandatory for every enqueue, so `--no-auth` would otherwise stop working. In `--no-auth` mode the server seeds a reserved development org and user principal (all roles) in one idempotent transaction, fails startup if a conflicting reserved row exists, and injects that principal on every API request. Authenticated startup never seeds.

## Reference model

[internal/store/storetest](../../internal/store/storetest/) is a pure-Go oracle. It has no PostgreSQL, Connect, clock, or goroutine dependencies, and it does not use production transition helpers.

- **Commands:** Enqueue, Acquire, Renew, Release, Expire, Cancel, Publish, Complete, List. Callers supply identities; time is an explicit integer.
- **Invariants checked after every command:**
  - terminal states never reopen
  - attempts are monotonic and bounded, and equal the acquisition count
  - lease fields are set ⇔ RUNNING
  - records within an attempt are contiguous from 1
  - rejected commands leave the snapshot unchanged
- **Tests:** hand-written boundary histories, a property test (500 seeds × 200 commands), and `FuzzJobContract`.

## Differential replay

`TestDifferentialReplay` replays seeded `storetest.Generate` histories against a PostgreSQL testcontainer, 200 by default and set with `-replay.histories`. After every step it compares the outcome kind and the normalized job view. The adapter maps handles to real IDs and tokens and never computes expected results.

| Operation | Enabled in |
|---|---|
| Enqueue (retry, conflict, cross-org), Acquire (FIFO, attempt bound), Complete with a valid lease, List | phase 2 |
| Renew, Release, Expire, Publish, stale-token operations | phase 4 |
| Cancel | phase 6 |

## Deferred behaviour

| Item | Phase |
|---|---|
| Role interceptor, shared error mapper, idempotent Start/Stop | 3 |
| Fencing (leasing principal, `clock_timestamp()` expiry), `ErrLeaseLost` on token failures, reaper, publish contiguity, `final_event_sequence` enforcement, stream `attempt` and status fields, per-attempt WAL | 4 |
| `--events-retention-days`, `--job-retention-days`, sweeps | 5 |
| CancelJob transition and CLI | 6 |

## Verification

```bash
go test -race ./internal/store/storetest/...          # model, no Docker
make test-integration-postgres                         # store contract + differential replay
make lint test test-integration proto-lint
make proto-breaking                                    # only the expected failures above
```

[← Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | [Phase 3 →](03-phase3-tenancy-authz.md)
