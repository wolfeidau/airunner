-- PostgreSQL Sessions Schema
-- Migration 3: Sessions table and additional GitHub fields for principals

-- Add GitHub profile fields to principals table
ALTER TABLE principals
    ADD COLUMN IF NOT EXISTS github_login VARCHAR(255),
    ADD COLUMN IF NOT EXISTS email VARCHAR(255),
    ADD COLUMN IF NOT EXISTS avatar_url TEXT;

-- Index for email lookup (optional, for future use)
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

-- Record this migration
INSERT INTO schema_migrations (version) VALUES (3) ON CONFLICT DO NOTHING;
