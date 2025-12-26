# mTLS Authentication Implementation Guide

## Overview

This directory contains a layered documentation structure for implementing per-principal PKI authentication with mutual TLS (mTLS) for the Airunner job orchestration platform. The implementation replaces the current shared JWT public key authentication model with a certificate-based system where each principal (user, worker, service) maintains their own ECDSA P-256 key pair and X.509 certificate.

**Key Benefits:**
- Eliminate shared credentials - each principal has unique credentials
- Enable certificate rotation - workers automatically rotate certificates every 60-90 days
- Support revocation - individual principals can be revoked without affecting others
- Maintain security - ECDSA ES256 certificates with per-principal verification
- Message integrity - TLS provides cryptographic integrity for all requests
- Replay protection - TLS sequence numbers and nonces prevent replay attacks
- Zero application code - Authentication handled at TLS layer, not application layer
- Role-based authorization - Principal types map to specific permissions

**What's in this directory:**
- Phased implementation guides (01-05) for sequential execution
- Architecture and design documentation
- Complete code examples in the `examples/` directory
- Operations runbook for Day 2 procedures

**Original consolidated spec:** For reference, the complete original specification that this directory replaces can be found at:
- `ARCHIVE_original_consolidated_spec.md` (created after migration)

## Prerequisites

Before starting the implementation, ensure you have the following:

**Development Tools:**
- Go 1.21 or later
- Protocol Buffers compiler (`protoc`) with Go plugin
- GNU Make
- Docker and Docker Compose (for local integration testing)

**AWS Tools:**
- AWS CLI v2 configured with appropriate credentials
- Terraform 1.5 or later
- Access to AWS account with permissions for:
  - DynamoDB table creation and management
  - SSM Parameter Store access
  - KMS key creation and signing permissions
  - ECS task definition updates
  - Network Load Balancer configuration

**AWS Account Requirements:**
- IAM role for ECS task execution with SSM Parameter Store access
- IAM role for ECS tasks with DynamoDB, SSM, and KMS signing permissions
- VPC with public and private subnets
- Existing ECS cluster (if deploying to production)

**Knowledge Prerequisites:**
- Familiarity with X.509 certificates and PKI concepts
- Understanding of TLS/mTLS handshake process
- Basic Terraform knowledge
- Experience with AWS services (ECS, DynamoDB, NLB)

## Quick Start

**For developers implementing from scratch:**

```bash
# 1. Read the architecture to understand the design
cat 00-architecture.md

# 2. Execute phases sequentially
# Phase 1: Core code (2-3 hours)
cat 01-phase1-core-code.md
# Implement store interfaces, auth, authz, proto

# Phase 2: Integration testing (2-3 hours)
cat 02-phase2-integration.md
# Local testing with docker-compose

# Phase 3: Infrastructure (1-2 hours)
cat 03-phase3-infrastructure.md
# Terraform for AWS resources

# Phase 4: Deployment (1-2 hours)
cat 04-phase4-deployment.md
# Bootstrap and production deployment

# Phase 5: Cleanup (1 hour)
cat 05-phase5-cleanup.md
# Remove old JWT code
```

Or navigate directly:
- [Architecture](00-architecture.md) - Design decisions and diagrams
- [Phase 1](01-phase1-core-code.md) → [Phase 2](02-phase2-integration.md) → [Phase 3](03-phase3-infrastructure.md) → [Phase 4](04-phase4-deployment.md) → [Phase 5](05-phase5-cleanup.md)
- [Operations Runbook](operations-runbook.md) - Day 2 procedures

**Success verification at each phase:**
```bash
# Phase 1 checkpoint
make proto-generate && make test

# Phase 2 checkpoint
docker-compose up -d
./bin/airunner-server --no-auth  # Test locally

# Phase 3 checkpoint
terraform plan  # Review infrastructure changes

# Phase 4 checkpoint
curl http://airunner-dev.example.com:8080/health
airunner-cli principal list  # Test mTLS

# Phase 5 checkpoint
grep -r "JWT_PUBLIC_KEY" .  # Should return no results
make test  # All tests pass
```

## File Navigation Guide

### Entry Points

| File | Purpose | When to Read |
|------|---------|--------------|
| `README.md` (this file) | Entry point, navigation guide | Start here |
| [00-architecture.md](00-architecture.md) | Design decisions, diagrams, context | Read before implementation |
| [operations-runbook.md](operations-runbook.md) | Day 2 operations | After deployment |

### Implementation Phases (Execute in Order)

| Phase | File | Duration | Description | Dependencies |
|-------|------|----------|-------------|--------------|
| 1 | [01-phase1-core-code.md](01-phase1-core-code.md) | 2-3 hours | Implement store interfaces, auth, authz, proto | None |
| 2 | [02-phase2-integration.md](02-phase2-integration.md) | 2-3 hours | Local integration testing with docker-compose | Phase 1 complete, tests passing |
| 3 | [03-phase3-infrastructure.md](03-phase3-infrastructure.md) | 1-2 hours | Terraform for DynamoDB, SSM, KMS, NLB, ECS | Phase 2 verified locally |
| 4 | [04-phase4-deployment.md](04-phase4-deployment.md) | 1-2 hours | Bootstrap (uses KMS for signing), production deployment | Phase 3 Terraform applied |
| 5 | [05-phase5-cleanup.md](05-phase5-cleanup.md) | 1 hour | Remove JWT code, update docs | Phase 4 deployed and verified |

**Total estimated time:** 7-10 hours of focused implementation

### Examples Directory Guide

The `examples/` directory contains complete code implementations organized by package:

```
examples/
├── pki/oid.go              # Custom OID extraction (complete, 80 lines)
├── store/
│   ├── principal_store.go  # PrincipalStore interface (complete, 85 lines)
│   └── certificate_store.go # CertificateStore interface (complete, 95 lines)
├── auth/
│   ├── mtls.go            # MTLSAuthenticator (complete, 270 lines)
│   └── authz.go           # Authorization logic (complete, 100 lines)
├── proto/principal.proto  # PrincipalService definition (complete, 165 lines)
├── cli/bootstrap.go       # Bootstrap command (reference, see spec lines 2279-2783)
├── server/rpc.go          # Server config (reference, see spec lines 1872-2032)
└── terraform/
    ├── dynamodb.tf        # DynamoDB tables (reference, see spec lines 602-708)
    ├── ssm.tf             # SSM/Secrets Manager (reference, see spec lines 710-783)
    ├── nlb.tf             # Network Load Balancer (reference, see spec lines 784-869)
    └── ecs.tf             # ECS task updates (reference, see spec lines 870-967)
```

**How to use examples:**
- **Complete files** (`pki/`, `store/`, `auth/`, `proto/`) - Ready to copy or use as reference
- **Reference files** (`cli/`, `server/`, `terraform/`) - Contain structure and guidance, full code in original spec

## Phase-by-Phase Execution

### Phase 1: Core Code

**File:** [01-phase1-core-code.md](01-phase1-core-code.md)

**Goal:** Implement core authentication components (stores, auth, authz, proto)

**What you'll create:**
- `internal/pki/oid.go` - Custom OID extraction
- `internal/store/principal_store.go` - PrincipalStore interface
- `internal/store/certificate_store.go` - CertificateStore interface
- `internal/store/memory_principal_store.go` - In-memory implementation
- `internal/store/memory_cert_store.go` - In-memory implementation
- `internal/auth/mtls.go` - MTLSAuthenticator
- `internal/auth/authz.go` - Authorization logic
- `api/job/v1/principal.proto` - PrincipalService definition

**Success Criteria:**
- [ ] All code compiles
- [ ] `make proto-generate` succeeds
- [ ] Unit tests pass
- [ ] No linting errors

**Quick commands:**
```bash
make proto-generate
make test
make lint
```

---

### Phase 2: Local Integration Testing

**File:** [02-phase2-integration.md](02-phase2-integration.md)

**Goal:** Validate mTLS flow with LocalStack and docker-compose

**What you'll create:**
- DynamoDB store implementations (production-ready)
- Server configuration with dual listeners
- CLI bootstrap command
- Docker-compose setup for local testing

**Success Criteria:**
- [ ] LocalStack DynamoDB accessible
- [ ] Bootstrap command creates CA and certs
- [ ] Server starts with mTLS enabled
- [ ] Health check endpoint responds
- [ ] mTLS authentication works locally

**Quick commands:**
```bash
docker-compose up -d
./bin/airunner-cli bootstrap --environment=local
./bin/airunner-server # Starts with mTLS
curl http://localhost:8080/health
```

---

### Phase 3: Infrastructure

**File:** [03-phase3-infrastructure.md](03-phase3-infrastructure.md)

**Goal:** Update Terraform for AWS resources

**What you'll create:**
- DynamoDB tables (principals, certificates)
- SSM parameters (ca-cert, server-cert, server-key)
- Secrets Manager (ca-key with restricted access)
- Network Load Balancer (TCP passthrough for mTLS)
- ECS task definition updates

**Success Criteria:**
- [ ] Terraform plan shows expected changes
- [ ] No breaking changes to existing resources
- [ ] DynamoDB tables have correct GSIs and TTL
- [ ] SSM parameters use lifecycle ignore_changes
- [ ] NLB configured for TCP passthrough on port 443

**Quick commands:**
```bash
cd infra/
terraform plan
terraform apply
```

---

### Phase 4: Deployment

**File:** [04-phase4-deployment.md](04-phase4-deployment.md)

**Goal:** Deploy to production and verify

**What you'll do:**
- Run bootstrap command for production environment
- Upload certificates to AWS (SSM/Secrets Manager)
- Apply Terraform changes
- Update ECS service
- Verify mTLS connections

**Success Criteria:**
- [ ] Bootstrap completes successfully
- [ ] All certs uploaded to AWS
- [ ] ECS service updated and healthy
- [ ] Health check endpoint accessible
- [ ] mTLS API accessible with client cert
- [ ] Authorization working correctly

**Quick commands:**
```bash
airunner-cli bootstrap --environment=prod --domain=airunner.example.com
terraform apply
aws ecs update-service --cluster airunner-prod --service airunner-prod --force-new-deployment
curl http://airunner.example.com:8080/health
```

---

### Phase 5: Cleanup

**File:** [05-phase5-cleanup.md](05-phase5-cleanup.md)

**Goal:** Remove old JWT code and finalize

**What you'll do:**
- Remove JWT-related code and files
- Remove JWT Terraform resources
- Update documentation (AGENT.md, README.md)
- Final verification

**Success Criteria:**
- [ ] No JWT references in codebase
- [ ] JWT Terraform resources removed
- [ ] Documentation updated
- [ ] All tests pass
- [ ] Git history clean

**Quick commands:**
```bash
grep -r "JWT_PUBLIC_KEY" .  # Should return nothing
grep -r "airunner-cli token" .  # Should return nothing
make test
git status
```

## Troubleshooting

### Common Issues

**Problem:** `proto-generate` fails with missing imports
- **Solution:** Ensure `buf` is installed and up to date: `go install github.com/bufbuild/buf/cmd/buf@latest`

**Problem:** Bootstrap command fails to create CA
- **Solution:** Check AWS credentials and permissions for KMS (kms:Sign, kms:GetPublicKey). Verify KMS key exists: `aws kms describe-key --key-id alias/airunner-{env}-ca`

**Problem:** mTLS connection refused
- **Solution:** Verify server has correct CA certificate loaded and client is presenting valid cert

**Problem:** Certificate verification fails
- **Solution:** Check that custom OID extensions are present in certificate: `openssl x509 -in cert.pem -text -noout`

**Problem:** Authorization denied unexpectedly
- **Solution:** Check principal type matches expected permissions in `RolePermissions` map

**Problem:** Health check failing after deployment
- **Solution:** Verify security groups allow port 8080 from NLB, check ECS task logs

### Getting Help

**Documentation:**
- Architecture decisions: See [00-architecture.md](00-architecture.md)
- Operational procedures: See [operations-runbook.md](operations-runbook.md)
- Original consolidated spec: See `ARCHIVE_original_consolidated_spec.md`

**Code Examples:**
- All examples in `examples/` directory
- Original spec lines referenced in each example file

**AWS Debugging:**
```bash
# Check ECS task logs
aws logs tail /ecs/airunner-prod --follow

# Verify SSM parameters
aws ssm get-parameter --name /airunner/prod/ca-cert

# Check DynamoDB tables
aws dynamodb describe-table --table-name airunner_prod_principals
```

## Next Steps

1. **Start Here:** Read [00-architecture.md](00-architecture.md) to understand the design
2. **Phase 1:** Follow [01-phase1-core-code.md](01-phase1-core-code.md) to implement core components
3. **Iterate:** Complete phases 2-5 sequentially
4. **Operate:** Use [operations-runbook.md](operations-runbook.md) for Day 2 operations

**Estimated Total Time:** 7-10 hours for complete implementation

**Questions?** Check the original consolidated spec at `ARCHIVE_original_consolidated_spec.md` for complete context and detailed explanations.
