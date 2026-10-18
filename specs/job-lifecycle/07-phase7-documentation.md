# Phase 7: Documentation

[← README](README.md) | [← Phase 6](06-phase6-cancellation.md) | [Runbook →](operations-runbook.md)

**Goal:** the repository describes the system as built. A new engineer can start at `README.md` or `AGENT.md`, find the lifecycle guarantees, operate the system from the runbook, and not be misled by documents for designs that no longer exist.

**Status:** done, in this PR (number assigned at merge).

**Depends on:** [phase 6](06-phase6-cancellation.md). Documentation describes behaviour, so it lands last.

## Customer problem

After phases 1 to 6 the code had changed more than the documents:

- `AGENT.md` referred to `specs/mtls/` (absent), mTLS authentication, `internal/auth/authz.go` as a future file, `internal/store/store.go`, an in-memory development backend and an event-partitioning claim. None matched the repository.
- The root `README.md` did not explain tenancy, retention, lease and event guarantees, or the WAL loss boundary.
- `specs/wal-execution-isolation.md` and `specs/wal/` still described a job-ID-only WAL and a tokenless orphan upload, which phase 4b rejected. A reader could implement the wrong design from them.
- Operators had no procedure for dead letters, reaper backlog, retention scheduling or failed WALs.
- `infra/` still describes DynamoDB, SQS and `AIRUNNER_STORE_TYPE`. It is stale, and nothing said so.

## Success criteria

- [x] `AGENT.md` and `README.md` describe PostgreSQL-only storage, JWT and session authentication, tenancy, retention, the lease and event guarantees, and the WAL loss boundary.
- [x] Every stale reference named in the plan is removed or corrected.
- [x] The layered spec is complete: README, architecture, phases 1 to 7, runbook, examples.
- [x] The conflicting WAL documents carry a superseded banner that links to the replacement.
- [x] The redesign plan records that it is implemented and points to the as-built spec.
- [x] `infra/` is recorded as stale. Rewriting it is out of scope.
- [x] Every relative link resolves, every flag exists in `--help`, every runbook query runs, and every excerpt matches its source.

## What was updated

| File | Change |
|---|---|
| [AGENT.md](../../AGENT.md) | Rewrote the project overview, package map and key-files list for PostgreSQL-only storage. Added "PostgreSQL Backend" and "Job Lifecycle Guarantees" sections. Replaced mTLS references with JWT and session authentication. Pointed the layered-spec examples at `specs/job-lifecycle/` and `specs/cli-credentials/`. Marked `infra/` as stale. Listed `specs/wal/` as superseded |
| [README.md](../../README.md) | Rewrote prerequisites, quick start (Compose, `Procfile.dev`, `--no-auth`), authentication, architecture diagram and job flow, guarantees and operations. Linked this spec and the runbook |
| [specs/job-lifecycle/](README.md) | Added README, architecture, phase 1 and phase 7 files, the runbook and six examples. Changed the breadcrumbs of phases 2 to 6 to start at the README |
| [specs/wal-execution-isolation.md](../wal-execution-isolation.md) | Added a banner: superseded by [phase 4b](04b-phase4b-worker-durability.md); kept for history |
| [specs/wal/README.md](../wal/README.md) | Added a banner: superseded in part by phase 4b and the [architecture](00-architecture.md) |
| [Redesign plan](../job-lifecycle-tenancy-redesign-plan.md) | Added a status banner and a link to the as-built spec. Linked each phase row to its file and marked it Done |

AGENT.md and the root README are the places an agent or a new contributor starts. They carry the guarantees in summary and link here for detail, so there is one authoritative description of each rule.

### Stale items and where they went

| Stale item | Resolution |
|---|---|
| `specs/mtls/` | References removed; examples now cite `specs/job-lifecycle/` and `specs/cli-credentials/` |
| mTLS as the authentication model | JWT for CLI and workers, GitHub OAuth sessions for the dashboard |
| `internal/store/store.go` | Now [internal/store/job_store.go](../../internal/store/job_store.go) |
| Memory development backend | Gone. Local development uses Compose PostgreSQL and `--no-auth` |
| Event partitioning claim | Removed. `job_events` is not partitioned; retention is by job age |
| `infra/` | Recorded as stale DynamoDB and SQS Terraform that still sets `AIRUNNER_STORE_TYPE` and `AIRUNNER_EVENTS_TTL_DAYS` |

## Verification performed

All checks were run against the tree in this PR. The scripts live outside the repository (session scratchpad) because they are one-off checks, not project tooling.

### 1. Link check

A script extracted every relative markdown link (a markdown link target that does not start with `http` or `#`) from every file under `specs/job-lifecycle/`, stripped the `#anchor`, resolved the path from the linking file and confirmed the target exists. It also checked that each `#anchor` matches a heading in the target file, using GitHub's slug rules.

Result: the first run flagged only the 9 links to `07-phase7-documentation.md`, which did not exist yet. With this file in place, the run checks 367 links and reports **0 broken links and 0 bad anchors**.

### 2. Flags against `--help`

Every `--flag` mentioned under `specs/job-lifecycle/` was searched in the combined output of `airunner-server server --help`, `airunner-server cleanup --help` and `airunner-cli {worker,monitor,submit,list,cancel} --help`. All current flags are present. Flags that are deliberately absent from `--help` appear only where the text says they do not exist or names the plan's old spelling:

| Flag in the text | Why it is not in `--help` |
|---|---|
| `--default-max-attempts` | The plan's name. The flag is `--postgres-default-max-attempts` |
| `--postgres-token-secret` | Appears only in a startup error message. The flag is `--postgres-token-signing-secret` |
| `--store-type`, `--events-ttl-days` | Removed flags, named under compatibility constraints |
| `--org-id`, `--principal-id` | Flags of `credentials update`, not of the commands checked |

### 3. Runbook SQL

Every `sql` block in [operations-runbook.md](operations-runbook.md) was executed against the local Compose database (PostgreSQL 18) as

```bash
docker compose exec -T postgres psql -U airunner -d airunner_dev -v ON_ERROR_STOP=1
```

with each block wrapped in `BEGIN READ ONLY; ... ROLLBACK;` and placeholders replaced by literal UUIDs. All 10 blocks parsed and ran without error. The destructive reset procedure was **not** run.

### 4. Excerpts against source

A script compared every non-blank, non-`...` line of every `go` and `sql` code block in `examples/` (whitespace-normalised) with the files named in its "Source of truth" header. **0 mismatches.** [contract-test-skeleton.md](examples/contract-test-skeleton.md) is new code, not a copy; it was compiled with `go vet -tags integration` and run with `go test -tags integration -run TestContract_RedeliveryFencesOldToken ./internal/store/postgres/` through a Go build overlay (no file was added to the repository), and it passed.

### 5. Code facts re-verified

Each behaviour, default, metric name and SQL column in the new files was read from the code, not the plan. The differences found are listed in [Differences from the plan](00-architecture.md#differences-from-the-plan). One environment finding is worth recording: the local Compose database had `schema_migrations` versions 1, 2 and 3 and single-column principal foreign keys, so it predates the current migration files. [Audit queries 10 and 11](operations-runbook.md#sql-audit-queries) detect this. The fix is the opt-in [local reset](operations-runbook.md#local-compose-reset-destructive).

## Commands

```bash
# Link and anchor check, excerpt check
python3 <scratchpad>/check.py

# Flags
./bin/airunner-server server --help
./bin/airunner-server cleanup --help
./bin/airunner-cli worker --help

# Repository gates (documentation changes must not break them)
make lint test proto-lint
```

## Deferred work

| Item | Notes |
|---|---|
| `infra/` rewrite for PostgreSQL | Separate effort |
| Cancel execution on the first sender-side lease-loss signal | Planned fix; see [Known gaps](README.md#known-gaps) |
| Prune archived WALs | `wal.CleanupArchive` exists and is not called |
| Worker flag for the WAL directory | Currently `~/.airunner/wal` |

[← README](README.md) | [← Phase 6](06-phase6-cancellation.md) | [Runbook →](operations-runbook.md)
