# Certificate Bundle Support for mTLS CLI

[Architecture](00-architecture.md) | [Phase 1: Package](01-phase1-package.md) | [Phase 2: Integration](02-phase2-integration.md) | [Phase 3: Bootstrap](03-phase3-bootstrap.md)

## Overview

Add certificate bundle support to the Airunner CLI to reduce the number of certificate files required for mTLS authentication from 3 to 2, following cfssl security best practices.

**Current state:** Users must specify 3 separate files:
- `--ca-cert` - CA certificate
- `--client-cert` - Client certificate
- `--client-key` - Client private key

**Goal:** Support certificate bundles where public certificates are combined:
- `--cert-bundle` - Client cert + CA cert (not sensitive)
- `--client-key` - Client private key (sensitive, stored in 1Password)

**Benefits:**
- ✅ Reduces files from 3 to 2
- ✅ Follows cfssl security practices (public certs bundled, key separate)
- ✅ 1Password-friendly (only 1 sensitive file to store)
- ✅ Backward compatible with existing three-flag approach
- ✅ Reusable `internal/tlscerts` package

## Prerequisites

- Understanding of mTLS authentication
- Familiarity with PEM certificate format
- Go development environment

## Quick Start (5-Step Summary)

1. **Read** [00-architecture.md](00-architecture.md) to understand the design
2. **Implement** [01-phase1-package.md](01-phase1-package.md) to create `internal/tlscerts` package
3. **Integrate** [02-phase2-integration.md](02-phase2-integration.md) into CLI commands
4. **Update** [03-phase3-bootstrap.md](03-phase3-bootstrap.md) to generate bundles
5. **Test** end-to-end with bootstrap + CLI commands

## File Navigation

| File | Purpose | Duration | Status |
|------|---------|----------|--------|
| [README.md](README.md) | This file - entry point and navigation | 5 min | ✅ |
| [00-architecture.md](00-architecture.md) | Design decisions, API design, patterns | 15 min | ✅ |
| [01-phase1-package.md](01-phase1-package.md) | Create `internal/tlscerts` package | 45 min | Pending |
| [02-phase2-integration.md](02-phase2-integration.md) | Integrate bundle support into CLI | 30 min | Pending |
| [03-phase3-bootstrap.md](03-phase3-bootstrap.md) | Update bootstrap to create bundles | 20 min | Pending |

**Total estimated time:** ~2 hours

## Phase-by-Phase Execution

### Phase 1: Create Package ([01-phase1-package.md](01-phase1-package.md))

**Goal:** Build reusable `internal/tlscerts` package

**Success criteria:**
- [ ] `internal/tlscerts/loader.go` created with full API
- [ ] `internal/tlscerts/loader_test.go` created with comprehensive tests
- [ ] All tests pass
- [ ] Package can load from bundles and individual files

**Verification:**
```bash
go test ./internal/tlscerts/... -v
```

### Phase 2: CLI Integration ([02-phase2-integration.md](02-phase2-integration.md))

**Goal:** Add `--cert-bundle` flag to CLI commands

**Success criteria:**
- [ ] `internal/client/client.go` updated to use tlscerts package
- [ ] All CLI commands have `CertBundle` field
- [ ] Backward compatibility maintained
- [ ] CLI builds successfully

**Verification:**
```bash
make build-cli
./bin/airunner-cli list --help | grep cert-bundle
```

### Phase 3: Bootstrap Support ([03-phase3-bootstrap.md](03-phase3-bootstrap.md))

**Goal:** Generate certificate bundles during bootstrap

**Success criteria:**
- [ ] Bootstrap creates `admin-bundle.pem`
- [ ] Summary messages mention bundle usage
- [ ] Bundle works with CLI commands

**Verification:**
```bash
./bin/airunner-cli bootstrap --environment local
ls -la ./certs/admin-bundle.pem
./bin/airunner-cli list --cert-bundle=./certs/admin-bundle.pem --client-key=./certs/admin-key.pem
```

## Usage After Implementation

### New Approach (Recommended)
```bash
./bin/airunner-cli list \
  --server="https://airunner-prod.example.com:443" \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem
```

### Old Approach (Still Supported)
```bash
./bin/airunner-cli list \
  --server="https://airunner-prod.example.com:443" \
  --ca-cert=./certs/ca-cert.pem \
  --client-cert=./certs/admin-cert.pem \
  --client-key=./certs/admin-key.pem
```

## Troubleshooting

### Bundle parsing fails
**Error:** `cert bundle must contain at least 2 certificates`

**Solution:** Bundle must contain client cert first, then CA cert(s). Verify with:
```bash
openssl storeutl -noout -text -certs ./certs/admin-bundle.pem
```

### TLS handshake fails
**Error:** `tls: bad certificate`

**Solution:** Ensure client cert matches the private key:
```bash
# Extract public key from cert
openssl x509 -in ./certs/admin-cert.pem -pubkey -noout > /tmp/cert-pubkey.pem

# Extract public key from private key
openssl ec -in ./certs/admin-key.pem -pubout > /tmp/key-pubkey.pem

# Compare
diff /tmp/cert-pubkey.pem /tmp/key-pubkey.pem
```

## Next Steps

1. Review [00-architecture.md](00-architecture.md) to understand the design
2. Proceed to [01-phase1-package.md](01-phase1-package.md) to begin implementation
3. Follow phases sequentially for best results

## Related Documentation

- [specs/mtls/](../mtls/) - Complete mTLS authentication specification
- [AGENT.md](../../AGENT.md) - Project overview and development guidelines
- [internal/ssmcerts/](../../internal/ssmcerts/) - Similar pattern for SSM certificate loading

---

[Architecture →](00-architecture.md)
