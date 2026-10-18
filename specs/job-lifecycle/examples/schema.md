# Example: schema excerpt

[← README](../README.md) | [Architecture](../00-architecture.md) | [Fenced publish →](fenced-publish.md)

Source of truth: [1_initial_schema.sql](../../../internal/store/postgres/migrations/1_initial_schema.sql) and [2_principal_org_fks.sql](../../../internal/store/postgres/migrations/2_principal_org_fks.sql)

These are excerpts, trimmed with `-- ...`. If they differ from the migration files, the migration files win. Rationale for each rule is in [00-architecture.md](../00-architecture.md#data-model).

## jobs

Every lifecycle rule that PostgreSQL can enforce is a constraint: attempt bounds, lease columns set if and only if the job is RUNNING, and request IDs unique per org.

```sql
CREATE TABLE IF NOT EXISTS jobs (
    job_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES principals(principal_id),
    leased_by UUID REFERENCES principals(principal_id),  -- Set only while RUNNING
    queue VARCHAR(255) NOT NULL,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    request_id VARCHAR(255) NOT NULL,  -- For idempotency (user-provided, not a UUID)
    request_fingerprint BYTEA NOT NULL,  -- SHA-256 of the normalized enqueue intent
    attempt INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL,
    last_event_sequence BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    visibility_until TIMESTAMPTZ,  -- Lease expiry, set only while RUNNING
    receipt_handle UUID,  -- Task token versioning, changes on each dequeue
    -- ...
    CONSTRAINT jobs_org_request_id_key UNIQUE (org_id, request_id),
    CONSTRAINT jobs_attempt_bounds CHECK (attempt >= 0 AND attempt <= max_attempts),
    CONSTRAINT jobs_max_attempts_bounds CHECK (max_attempts >= 1 AND max_attempts <= 100),
    CONSTRAINT jobs_last_event_sequence_check CHECK (last_event_sequence >= 0),

    -- RUNNING requires every lease column and a consumed attempt; all other states require none
    CONSTRAINT jobs_lease_consistency CHECK (
        (state = 2 AND visibility_until IS NOT NULL AND receipt_handle IS NOT NULL
            AND leased_by IS NOT NULL AND attempt > 0) OR
        (state <> 2 AND visibility_until IS NULL AND receipt_handle IS NULL
            AND leased_by IS NULL)
    )
);
```

State values match `JobState`: 1 SCHEDULED, 2 RUNNING, 3 COMPLETED, 4 FAILED, 5 CANCELLED.

## job_events

The primary key carries the attempt, so a redelivered job has its own sequence space. An output batch covers `[sequence, end_sequence]`. There is no `ttl` column and no `org_id`; the parent job row carries both retention age and tenancy.

```sql
CREATE TABLE IF NOT EXISTS job_events (
    job_id UUID NOT NULL,
    attempt INT NOT NULL CHECK (attempt > 0),
    sequence BIGINT NOT NULL CHECK (sequence > 0),  -- Monotonic sequence number within the attempt
    end_sequence BIGINT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type INTEGER NOT NULL,  -- EventType enum
    event_payload BYTEA NOT NULL,  -- Protobuf binary, auto-compressed via TOAST for large events

    PRIMARY KEY (job_id, attempt, sequence),
    FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE,
    CONSTRAINT job_events_end_sequence_check CHECK (end_sequence >= sequence)
);
```

## Indexes

Every lifecycle query writes the state as a literal (`state = 1`) so a generic prepared plan can prove the partial-index predicate. A bound `state = $1` loses the index once PostgreSQL switches to a generic plan.

```sql
CREATE INDEX IF NOT EXISTS idx_jobs_dequeue ON jobs(org_id, queue, created_at, job_id)
    WHERE state = 1;

CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(visibility_until, job_id)
    WHERE state = 2;

CREATE INDEX IF NOT EXISTS idx_jobs_list ON jobs(org_id, queue, state, created_at, job_id);

CREATE INDEX IF NOT EXISTS idx_jobs_retention ON jobs(updated_at, job_id)
    WHERE state IN (3, 4, 5);

CREATE INDEX IF NOT EXISTS idx_job_events_timestamp ON job_events(job_id, attempt, timestamp);

CREATE INDEX IF NOT EXISTS idx_job_events_type ON job_events(job_id, attempt, event_type);
```

## Org-membership foreign keys (migration 2)

Migration 2 replaces the single-column principal foreign keys with composite ones, so a creator or leaser from another org is rejected by the database. `leased_by` uses MATCH SIMPLE, so a NULL on a non-RUNNING row passes.

```sql
ALTER TABLE principals
    ADD CONSTRAINT principals_principal_org_key UNIQUE (principal_id, org_id);
-- ...
ALTER TABLE jobs
    ADD CONSTRAINT jobs_created_by_org_fkey
    FOREIGN KEY (created_by, org_id) REFERENCES principals(principal_id, org_id);
-- ...
ALTER TABLE jobs
    ADD CONSTRAINT jobs_leased_by_org_fkey
    FOREIGN KEY (leased_by, org_id) REFERENCES principals(principal_id, org_id);
```

[← README](../README.md) | [Architecture](../00-architecture.md) | [Fenced publish →](fenced-publish.md)
