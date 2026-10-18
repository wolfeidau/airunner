-- PostgreSQL Schema
-- Migration 1: Squashed initial schema for organizations, principals, sessions, jobs and job_events

-- Schema migrations tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Organizations table: Tenants in the system
CREATE TABLE IF NOT EXISTS organizations (
    org_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner_principal_id UUID NOT NULL,  -- FK to principals, but can't enforce due to circular dependency
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Owner lookup (no FK constraint, see above)
CREATE INDEX IF NOT EXISTS idx_organizations_owner
    ON organizations(owner_principal_id);

-- Principals table: Identities in the system (users, workers, services)
CREATE TABLE IF NOT EXISTS principals (
    principal_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('user', 'worker', 'service')),
    name VARCHAR(255) NOT NULL,

    -- User principals (GitHub OAuth)
    github_id VARCHAR(255),
    github_login VARCHAR(255),
    email VARCHAR(255),
    avatar_url TEXT,

    -- Worker/service principals
    public_key TEXT,
    public_key_der BYTEA,
    fingerprint VARCHAR(255) UNIQUE,

    -- Authorization
    roles TEXT[] NOT NULL DEFAULT '{}',

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,  -- Soft delete for revocation tracking

    -- Constraints: Ensure fields are populated correctly based on type
    CONSTRAINT principal_type_fields CHECK (
        (type = 'user' AND github_id IS NOT NULL AND fingerprint IS NULL) OR
        (type IN ('worker', 'service') AND fingerprint IS NOT NULL AND github_id IS NULL)
    )
);

-- Fingerprint lookup for worker JWT authentication (most frequent query)
-- Partial index excludes deleted principals for efficiency
CREATE INDEX IF NOT EXISTS idx_principals_fingerprint
    ON principals(fingerprint) WHERE fingerprint IS NOT NULL AND deleted_at IS NULL;

-- GitHub ID lookup for user OAuth login
CREATE INDEX IF NOT EXISTS idx_principals_github_id
    ON principals(github_id) WHERE github_id IS NOT NULL AND deleted_at IS NULL;

-- Org + type listing (for credential management UI)
CREATE INDEX IF NOT EXISTS idx_principals_org_type
    ON principals(org_id, type) WHERE deleted_at IS NULL;

-- Revoked principals (for ListRevokedPrincipals RPC)
CREATE INDEX IF NOT EXISTS idx_principals_revoked
    ON principals(deleted_at) WHERE deleted_at IS NOT NULL;

-- Email lookup (optional, for future use)
CREATE INDEX IF NOT EXISTS idx_principals_email
    ON principals(email) WHERE email IS NOT NULL AND deleted_at IS NULL;

-- Sessions table: Server-side session storage with opaque session IDs
-- Cookie contains only session_id (UUIDv7), all session data lives here
CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address INET
);

-- Index for logout-all-sessions and session listing
CREATE INDEX IF NOT EXISTS idx_sessions_principal ON sessions(principal_id);

-- Index for expired session cleanup job
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Jobs table: Core job storage, org-scoped, with bounded delivery attempts
-- state values match JobState: 1=SCHEDULED, 2=RUNNING, 3=COMPLETED, 4=FAILED, 5=CANCELLED
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
    job_params JSONB NOT NULL,
    execution_config JSONB,
    result JSONB,  -- Populated on completion

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

-- Job events table: Per-attempt event persistence with sequence-based ordering
-- A normal event covers one sequence; an output batch covers [sequence, end_sequence]
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

-- Indexes for jobs table
-- Dequeue: oldest-first within (org, queue), partial on SCHEDULED
-- Literal state predicates in queries are required so generic plans can use these indexes
CREATE INDEX IF NOT EXISTS idx_jobs_dequeue ON jobs(org_id, queue, created_at, job_id)
    WHERE state = 1;

-- Lease expiry scan for the reaper, partial on RUNNING
CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(visibility_until, job_id)
    WHERE state = 2;

-- ListJobs by org, queue and state
CREATE INDEX IF NOT EXISTS idx_jobs_list ON jobs(org_id, queue, state, created_at, job_id);

-- Retention scan, partial on terminal states (COMPLETED, FAILED, CANCELLED)
CREATE INDEX IF NOT EXISTS idx_jobs_retention ON jobs(updated_at, job_id)
    WHERE state IN (3, 4, 5);

-- Indexes for job_events table
-- Timestamp-based queries (for historical replay with timestamp filters)
CREATE INDEX IF NOT EXISTS idx_job_events_timestamp ON job_events(job_id, attempt, timestamp);

-- Event type filtering
CREATE INDEX IF NOT EXISTS idx_job_events_type ON job_events(job_id, attempt, event_type);

-- Record this migration
INSERT INTO schema_migrations (version) VALUES (1) ON CONFLICT DO NOTHING;
