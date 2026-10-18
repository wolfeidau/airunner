-- Migration 2: Enforce that job creators and leasers belong to the job's organization
-- Replaces the single-column principal FKs on jobs with composite (principal, org) FKs.

-- Composite FK target
ALTER TABLE principals DROP CONSTRAINT IF EXISTS principals_principal_org_key;
ALTER TABLE principals
    ADD CONSTRAINT principals_principal_org_key UNIQUE (principal_id, org_id);

-- Drop the single-column FKs created by migration 1
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_created_by_fkey;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_leased_by_fkey;

-- Composite FKs (MATCH SIMPLE: a NULL leased_by is not checked)
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_created_by_org_fkey;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_created_by_org_fkey
    FOREIGN KEY (created_by, org_id) REFERENCES principals(principal_id, org_id);

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_leased_by_org_fkey;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_leased_by_org_fkey
    FOREIGN KEY (leased_by, org_id) REFERENCES principals(principal_id, org_id);

-- Record this migration
INSERT INTO schema_migrations (version) VALUES (2) ON CONFLICT DO NOTHING;
