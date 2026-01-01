-- PostgreSQL Principal Authentication Schema
-- Migration 2: Organizations and Principals tables for JWT-based authentication

-- Organizations table: Tenants in the system
CREATE TABLE IF NOT EXISTS organizations (
    org_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner_principal_id UUID NOT NULL,  -- FK to principals, but can't enforce due to circular dependency
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index for owner lookup before adding FK constraint
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

-- Critical indexes for principals table
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

-- Record this migration
INSERT INTO schema_migrations (version) VALUES (2) ON CONFLICT DO NOTHING;
