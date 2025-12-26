# Phase 5: Cleanup

[← Back to README](README.md) | [← Phase 4: Deployment](04-phase4-deployment.md) | [Operations Runbook](operations-runbook.md)

## Overview

**Goal:** Remove old JWT authentication code and finalize the migration to mTLS.

**Duration:** 1 hour

**Prerequisites:**
- Phase 4 complete and production deployment verified
- mTLS working correctly in production
- All clients migrated to certificate-based authentication

**Success Criteria:**
- [ ] JWT code removed from codebase
- [ ] JWT Terraform resources removed
- [ ] Documentation updated
- [ ] All tests pass
- [ ] No JWT references remain in codebase

## Step 1: Remove JWT Code

### Files to Delete

```bash
# Delete JWT token generation
rm cmd/cli/internal/commands/token.go

# Delete JWT middleware (if separate from mTLS)
# Check if internal/auth/jwt.go exists and remove if not needed
rm internal/auth/jwt.go

# Delete JWT token utilities
rm internal/auth/token.go
```

### Search for Remaining References

```bash
# Search for JWT references
grep -r "JWT_PUBLIC_KEY" .
grep -r "JWT_SIGNING_KEY" .
grep -r "airunner-cli token" .
grep -r "NewJWTAuthFunc" .

# Expected: No results (or only in this cleanup doc and ARCHIVE file)
```

### Update Command Registration

**File:** `cmd/cli/main.go`

Remove the token command:

```go
// DELETE this line:
// cli.Register("token", "Generate JWT authentication token", &commands.TokenCmd{})
```

### Update Server Command

**File:** `cmd/server/internal/commands/rpc.go`

Remove JWT-related flags and code:

```go
// DELETE these fields:
// NoAuth       bool   `help:"Disable authentication (development only)"`
// JWTPublicKey string `help:"JWT public key for authentication" env:"JWT_PUBLIC_KEY"`

// DELETE JWT authentication setup:
// if !s.NoAuth {
//     publicKey, _ := os.ReadFile(s.JWTPublicKey)
//     authFunc := auth.NewJWTAuthFunc(publicKey)
//     middleware := authn.NewMiddleware(authFunc)
//     handler = middleware.Wrap(mux)
// }
```

**Note:** Keep `--no-auth` flag for local development only if needed.

## Step 2: Remove JWT Terraform Resources

**Location:** `infra/` (various files)

### Delete JWT Key Resources

```hcl
# DELETE from infra/ssm.tf or similar:

resource "tls_private_key" "jwt" {
  algorithm = "ECDSA"
  ecdsa_curve = "P256"
}

resource "aws_ssm_parameter" "jwt_signing_key" {
  name        = "/${var.application}/${var.environment}/jwt-signing-key"
  description = "JWT signing private key"
  type        = "SecureString"
  value       = tls_private_key.jwt.private_key_pem

  tags = local.tags
}

resource "aws_ssm_parameter" "jwt_public_key" {
  name        = "/${var.application}/${var.environment}/jwt-public-key"
  description = "JWT verification public key"
  type        = "String"
  value       = tls_private_key.jwt.public_key_pem

  tags = local.tags
}
```

### Remove Old Secrets Manager CA Key Resources (if migrating from old spec)

**Note:** If you previously used Secrets Manager for CA key storage (before migrating to KMS), remove those resources:

```hcl
# DELETE from infra/secrets.tf or similar (if exists):

resource "aws_secretsmanager_secret" "ca_key" {
  name        = "/${var.application}/${var.environment}/ca-key"
  description = "CA private key (admin access only)"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_policy" "ca_key" {
  secret_arn = aws_secretsmanager_secret.ca_key.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAdminAccess"
        Effect = "Allow"
        Principal = { AWS = var.admin_role_arn }
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "*"
      }
    ]
  })
}
```

**Clean up AWS:**

```bash
# Delete any existing CA key in Secrets Manager (if migrating)
aws secretsmanager delete-secret \
  --secret-id /airunner/prod/ca-key \
  --force-delete-without-recovery

# Verify deleted
aws secretsmanager list-secrets | grep ca-key
# Should return no results
```

### Update ECS Task Definition

**File:** `infra/ecs.tf`

Remove JWT environment variables:

```hcl
# DELETE from container_definitions environment:
# {
#   name  = "JWT_PUBLIC_KEY"
#   value = ""
# }
```

### Apply Terraform Changes

```bash
cd infra/

# Review changes
terraform plan

# Expected deletions:
# - tls_private_key.jwt
# - aws_ssm_parameter.jwt_signing_key
# - aws_ssm_parameter.jwt_public_key

# Apply deletions
terraform apply
```

## Step 3: Update Documentation

### AGENT.md

**File:** `AGENT.md`

Update the authentication section:

```markdown
# DELETE JWT authentication section:
# ## Authentication
#
# JWT-based authentication using ECDSA ES256:
# - **Server**: Pass public key via `JWT_PUBLIC_KEY` env var (PEM-encoded)
# - **CLI**: Pass token via `--token` flag or `AIRUNNER_TOKEN` env var
# - **Token generation**: `./bin/airunner-cli token --subject=<user> --ttl=1h`

# REPLACE WITH:
## Authentication

mTLS (mutual TLS) authentication using per-principal X.509 certificates:

- **Server**: Requires client certificates signed by the Airunner CA
- **CLI**: Pass certificates via `--cacert`, `--client-cert`, `--client-key` flags
- **Bootstrap**: `./bin/airunner-cli bootstrap` to create CA and initial admin credentials
- **Certificate management**: Use `PrincipalService` RPCs to manage principals and certificates

Key files:
- `internal/pki/oid.go` - Custom OID extraction for principal metadata
- `internal/auth/mtls.go` - mTLS authentication middleware
- `internal/auth/authz.go` - Role-based authorization
- `specs/mtls/` - Complete implementation documentation
```

### README.md (Project Root)

**File:** `README.md`

Update authentication documentation:

```markdown
# DELETE JWT references
# REPLACE WITH mTLS instructions

## Authentication

The server uses mutual TLS (mTLS) for authentication. Each principal (user, worker, service) has their own X.509 certificate signed by the Airunner CA.

### Setup

```bash
# 1. Bootstrap (creates CA and admin credentials)
./bin/airunner-cli bootstrap --environment=prod --domain=airunner.example.com

# 2. Create principals
./bin/airunner-cli principal create worker-01 --type=worker --server=...

# 3. Generate certificates
./bin/airunner-cli certificate generate worker-01 --server=...

# 4. Use certificates with CLI
./bin/airunner-cli list --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/worker-01-cert.pem \
  --client-key=~/.airunner/worker-01-key.pem
```

See `specs/mtls/README.md` for complete documentation.
```

### Code Comments

Search for and update JWT-related code comments:

```bash
# Find JWT-related comments
grep -r "JWT" . --include="*.go" | grep -v "vendor"

# Update or remove as appropriate
```

## Step 4: Clean Up Tests

### Remove JWT Test Files

```bash
# Delete JWT-related test files
rm internal/auth/jwt_test.go
rm internal/auth/token_test.go
rm cmd/cli/internal/commands/token_test.go
```

### Update Integration Tests

**Files:** Any files in `*_test.go` that reference JWT

Replace JWT authentication setup with mTLS:

```go
// DELETE:
// token := generateJWTToken(t)
// req.Header.Set("Authorization", "Bearer " + token)

// REPLACE WITH:
// Use test certificates for mTLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{loadTestCert(t)},
    RootCAs:      loadTestCA(t),
}
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: tlsConfig,
    },
}
```

## Step 5: Final Verification

### Build and Test

```bash
# Clean build
make clean
make build

# All binaries should build successfully
ls -lh bin/
# Expected: airunner-cli, airunner-server, airunner-orchestrator

# Run all tests
make test

# Expected: PASS (all tests pass)

# Run linter
make lint

# Expected: No errors
```

### Search for JWT References

Final sweep for any remaining JWT references:

```bash
# Search entire codebase
grep -r "JWT" . \
  --exclude-dir=vendor \
  --exclude-dir=.git \
  --exclude-dir=node_modules \
  --exclude="*.md"

# Expected: No results (except in specs/mtls/ARCHIVE_original_consolidated_spec.md)

# Search for token command
grep -r "airunner-cli token" . \
  --exclude-dir=vendor \
  --exclude-dir=.git

# Expected: Only in this cleanup doc and ARCHIVE file
```

### Git Status

```bash
# Check git status
git status

# Expected:
# - Deleted files (JWT-related)
# - Modified files (documentation updates)
# - Clean working directory (no unexpected changes)
```

## Step 6: Commit Changes

```bash
# Stage deletions and modifications
git add -A

# Commit with descriptive message
git commit -m "chore: remove JWT authentication code

- Delete JWT token generation command
- Remove JWT middleware and utilities
- Remove JWT Terraform resources
- Update documentation (AGENT.md, README.md)
- Update tests to use mTLS

Complete migration to mTLS authentication per specs/mtls/."

# Push to remote
git push origin main
```

## Success Checklist

- [ ] JWT code files deleted
- [ ] JWT Terraform resources removed
- [ ] Documentation updated (AGENT.md, README.md)
- [ ] Tests updated and passing
- [ ] No JWT references remain in codebase
- [ ] Clean build successful
- [ ] Production system still working correctly
- [ ] Changes committed to git

## Post-Cleanup Monitoring

Monitor production for 24-48 hours after cleanup:

```bash
# Check ECS task logs
aws logs tail /ecs/airunner-prod --follow

# Expected: No errors related to JWT or authentication

# Monitor metrics
# Check CloudWatch/Honeycomb for:
# - mtls_auth_total (should be increasing)
# - No JWT-related errors
# - No authentication failures
```

## Rollback Plan

If issues are discovered after cleanup:

```bash
# Revert the commit
git revert HEAD

# Restore JWT Terraform resources
cd infra/
git checkout HEAD~1 -- ssm.tf
terraform apply

# Redeploy with JWT code
# (Should not be needed if mTLS is working)
```

## Conclusion

The JWT authentication system has been completely removed. The system now uses:
- **mTLS for authentication**: Per-principal X.509 certificates
- **Role-based authorization**: Principal types map to permissions
- **Certificate management**: Bootstrap command and PrincipalService RPCs
- **Industry-standard PKI**: Self-managed CA with ECDSA P-256

For operational procedures, see [operations-runbook.md](operations-runbook.md).

---

[← Back to README](README.md) | [← Phase 4: Deployment](04-phase4-deployment.md) | [Operations Runbook](operations-runbook.md)
