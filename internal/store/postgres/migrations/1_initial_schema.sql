-- PostgreSQL JobStore Schema
-- Migration 1: Initial schema for jobs and job_events tables

-- Schema migrations tracking table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Jobs table: Core job storage with FIFO queue semantics
CREATE TABLE IF NOT EXISTS jobs (
    job_id UUID PRIMARY KEY,
    queue VARCHAR(255) NOT NULL,
    state INTEGER NOT NULL DEFAULT 0,  -- 0=SCHEDULED, 1=RUNNING, 2=COMPLETED, 3=FAILED, 4=CANCELLED, 5=PAUSED
    request_id VARCHAR(255) NOT NULL UNIQUE,  -- For idempotency (user-provided, not a UUID)
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    visibility_until TIMESTAMPTZ,  -- NULL = visible, non-NULL = invisible until timestamp
    receipt_handle UUID,  -- Task token versioning, changes on each dequeue
    job_params JSONB NOT NULL,
    execution_config JSONB,
    result JSONB,  -- Populated on completion

    -- Ensure visibility_until and receipt_handle are consistent
    CONSTRAINT visibility_receipt_consistency CHECK (
        (visibility_until IS NULL AND receipt_handle IS NULL) OR
        (visibility_until IS NOT NULL AND receipt_handle IS NOT NULL)
    )
);

-- Job events table: Event persistence with sequence-based ordering
CREATE TABLE IF NOT EXISTS job_events (
    job_id UUID NOT NULL,
    sequence BIGINT NOT NULL,  -- Monotonic sequence number
    timestamp TIMESTAMPTZ NOT NULL,
    event_type INTEGER NOT NULL,  -- EventType enum
    event_payload BYTEA NOT NULL,  -- Protobuf binary, auto-compressed via TOAST for large events
    ttl TIMESTAMPTZ,  -- Optional expiration timestamp for auto-deletion

    PRIMARY KEY (job_id, sequence),
    FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
);

-- Indexes for jobs table
-- Critical index for DequeueJobs: FIFO ordering with visibility filter
-- Partial index only on SCHEDULED jobs for efficiency
-- Note: Cannot include NOW() in WHERE clause as it's not immutable
-- Query will filter visibility_until at runtime
CREATE INDEX IF NOT EXISTS idx_jobs_dequeue ON jobs(queue, created_at)
    WHERE state = 0;

-- Idempotency lookup (covered by UNIQUE constraint, but explicit for clarity)
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_request_id ON jobs(request_id);

-- ListJobs queries by queue and state
CREATE INDEX IF NOT EXISTS idx_jobs_queue_state ON jobs(queue, state);

-- Indexes for job_events table
-- Timestamp-based queries (for historical replay with timestamp filters)
CREATE INDEX IF NOT EXISTS idx_job_events_timestamp ON job_events(job_id, timestamp);

-- Event type filtering (optional, for future optimizations)
CREATE INDEX IF NOT EXISTS idx_job_events_type ON job_events(job_id, event_type);

-- Record this migration
INSERT INTO schema_migrations (version) VALUES (1) ON CONFLICT DO NOTHING;
