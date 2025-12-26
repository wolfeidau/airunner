# Phase 1: Core Code Implementation

[← Back to README](README.md) | [← Architecture](00-architecture.md) | [Phase 2: Integration →](02-phase2-integration.md)

## Overview

**Goal:** Implement core authentication components including store interfaces, authentication logic, authorization, and Protocol Buffers definitions.

**Duration:** 2-3 hours

**Prerequisites:** None

**Success Criteria:**
- [ ] All code compiles without errors
- [ ] `make proto-generate` completes successfully
- [ ] Unit tests pass (`make test`)
- [ ] No linting errors (`make lint`)

## Package: PKI Utilities

**Location:** `internal/pki/oid.go`

**Reference:** `examples/pki/oid.go` (complete implementation, 80 lines)

### Custom OID Extensions

We use custom X.509 extensions under a private enterprise arc to store principal metadata in certificates:

```go
// OID definitions
var (
    OIDAirunnerArc   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
    OIDPrincipalType = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1} // admin, worker, user, service
    OIDPrincipalID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2} // unique identifier
)

// Extraction functions
func ExtractPrincipalType(cert *x509.Certificate) (string, error)
func ExtractPrincipalID(cert *x509.Certificate) (string, error)
func MustExtractPrincipal(cert *x509.Certificate) (principalType, principalID string, err error)
```

**Implementation Steps:**
1. Create `internal/pki/oid.go`
2. Copy from `examples/pki/oid.go` or implement based on architecture doc
3. Add unit tests for OID extraction

## Package: Store Interfaces

**Location:** `internal/store/`

**References:**
- `examples/store/principal_store.go` (complete, 85 lines)
- `examples/store/certificate_store.go` (complete, 95 lines)

### PrincipalStore Interface

Manages principal metadata (users, workers, services, admins):

```go
type PrincipalStore interface {
    Get(ctx context.Context, principalID string) (*PrincipalMetadata, error)
    Create(ctx context.Context, principal *PrincipalMetadata) error
    Update(ctx context.Context, principal *PrincipalMetadata) error
    Suspend(ctx context.Context, principalID string, reason string) error
    Activate(ctx context.Context, principalID string) error
    Delete(ctx context.Context, principalID string) error
    List(ctx context.Context, opts ListPrincipalsOptions) ([]*PrincipalMetadata, error)
}
```

**Key Types:**
- `PrincipalType`: admin, worker, user, service
- `PrincipalStatus`: active, suspended, deleted
- `PrincipalMetadata`: Full principal record with audit fields

### CertificateStore Interface

Manages certificate metadata for revocation checking:

```go
type CertificateStore interface {
    Get(ctx context.Context, serialNumber string) (*CertMetadata, error)
    GetByPrincipal(ctx context.Context, principalID string) ([]*CertMetadata, error)
    GetByFingerprint(ctx context.Context, fingerprint string) (*CertMetadata, error)
    Register(ctx context.Context, cert *CertMetadata) error
    Revoke(ctx context.Context, serialNumber string, reason string) error
    List(ctx context.Context, opts ListCertificatesOptions) ([]*CertMetadata, error)
}
```

**Implementation Steps:**
1. Create `internal/store/principal_store.go` with interfaces and types
2. Create `internal/store/certificate_store.go` with interfaces and types
3. Create `internal/store/memory_principal_store.go` (in-memory implementation for dev/testing)
4. Create `internal/store/memory_cert_store.go` (in-memory implementation for dev/testing)
5. Add unit tests for both memory implementations

**Note:** DynamoDB implementations will be added in Phase 2.

## Package: Authentication

**Location:** `internal/auth/mtls.go`

**Reference:** `examples/auth/mtls.go` (complete, 270 lines)

### MTLSAuthenticator

Handles mTLS authentication with principal and certificate validation:

```go
type PrincipalInfo struct {
    PrincipalID  string
    Type         store.PrincipalType
    SerialNumber string
    Fingerprint  string
}

type MTLSAuthenticator struct {
    principalStore store.PrincipalStore
    certStore      store.CertificateStore
    cache          *authCache  // 5-minute TTL
}

func NewMTLSAuthenticator(ps store.PrincipalStore, cs store.CertificateStore) *MTLSAuthenticator

func (a *MTLSAuthenticator) AuthFunc() authn.AuthFunc  // Returns Connect RPC middleware func
```

### Validation Flow

The `validate()` method performs these checks:

1. **Extract principal metadata from certificate**
   - Extract principal type from OID extension
   - Extract principal ID from OID extension (fallback to CN)
   - Validate principal type is valid (admin/worker/user/service)

2. **Check principal status in database**
   - Query `PrincipalStore.Get(principalID)`
   - Return error if principal not found
   - Return error if principal suspended or deleted
   - Verify type in cert matches type in database

3. **Check certificate revocation**
   - Query `CertificateStore.Get(serialNumber)`
   - Allow if certificate not registered (supports pre-tracking certs)
   - Return error if certificate revoked

4. **Cache result**
   - Cache both successful and failed validations
   - 5-minute TTL
   - Background cleanup goroutine

**Implementation Steps:**
1. Create `internal/auth/mtls.go`
2. Implement `MTLSAuthenticator` struct and `NewMTLSAuthenticator` constructor
3. Implement `AuthFunc()` method returning Connect RPC middleware
4. Implement `validate()` method with full validation logic
5. Implement `authCache` with TTL and cleanup
6. Add unit tests mocking stores

## Package: Authorization

**Location:** `internal/auth/authz.go`

**Reference:** `examples/auth/authz.go` (complete, 100 lines)

### Permission System

Role-based authorization mapping principal types to permissions:

```go
type Permission string

const (
    PermManagePrincipals Permission = "principals:manage"
    PermManageCerts      Permission = "certs:manage"
    PermJobsSubmit       Permission = "jobs:submit"
    PermJobsDequeue      Permission = "jobs:dequeue"
    PermJobsComplete     Permission = "jobs:complete"
    PermJobsList         Permission = "jobs:list"
    PermJobsCancel       Permission = "jobs:cancel"
    PermEventsPublish    Permission = "events:publish"
    PermEventsStream     Permission = "events:stream"
)

var RolePermissions = map[store.PrincipalType][]Permission{
    store.PrincipalTypeAdmin:   {/* all permissions */},
    store.PrincipalTypeWorker:  {PermJobsDequeue, PermJobsComplete, ...},
    store.PrincipalTypeUser:    {PermJobsSubmit, PermJobsList, ...},
    store.PrincipalTypeService: {PermJobsSubmit, PermJobsDequeue, ...},
}

func HasPermission(principalType store.PrincipalType, perm Permission) bool
func RequirePermission(ctx context.Context, perm Permission) error
```

**Implementation Steps:**
1. Create `internal/auth/authz.go`
2. Define all `Permission` constants
3. Create `RolePermissions` mapping (see architecture doc for complete matrix)
4. Implement `HasPermission` and `RequirePermission` functions
5. Add unit tests for permission checks

## Protocol Buffers

**Location:** `api/job/v1/principal.proto`

**Reference:** `examples/proto/principal.proto` (complete, 165 lines)

### PrincipalService Definition

```protobuf
service PrincipalService {
    // Principal management (admin only)
    rpc CreatePrincipal(CreatePrincipalRequest) returns (CreatePrincipalResponse);
    rpc GetPrincipal(GetPrincipalRequest) returns (GetPrincipalResponse);
    rpc ListPrincipals(ListPrincipalsRequest) returns (ListPrincipalsResponse);
    rpc SuspendPrincipal(SuspendPrincipalRequest) returns (SuspendPrincipalResponse);
    rpc ActivatePrincipal(ActivatePrincipalRequest) returns (ActivatePrincipalResponse);

    // Certificate management (admin only)
    rpc RegisterCertificate(RegisterCertificateRequest) returns (RegisterCertificateResponse);
    rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);
    rpc ListCertificates(ListCertificatesRequest) returns (ListCertificatesResponse);
}
```

**Key Enums:**
- `PrincipalType`: ADMIN, WORKER, USER, SERVICE
- `PrincipalStatus`: ACTIVE, SUSPENDED, DELETED

**Implementation Steps:**
1. Create `api/job/v1/principal.proto`
2. Copy from `examples/proto/principal.proto` or implement based on spec
3. Run `make proto-generate` to generate Go code
4. Verify generated files in `gen/job/v1/`

## Implementation Checklist

- [ ] Create `internal/pki/oid.go` with OID extraction
- [ ] Create `internal/store/principal_store.go` with interface
- [ ] Create `internal/store/certificate_store.go` with interface
- [ ] Create `internal/store/memory_principal_store.go` (in-memory impl)
- [ ] Create `internal/store/memory_cert_store.go` (in-memory impl)
- [ ] Create `internal/auth/mtls.go` with MTLSAuthenticator
- [ ] Create `internal/auth/authz.go` with permissions
- [ ] Create `api/job/v1/principal.proto` with PrincipalService
- [ ] Run `make proto-generate`
- [ ] Write unit tests for all packages
- [ ] Run `make test` - all tests pass
- [ ] Run `make lint` - no errors

## Verification

```bash
# Generate protocol buffers
make proto-generate

# Run tests
make test

# Check test coverage
make test-coverage

# Run linter
make lint
```

**Expected Output:**
- All packages compile
- All tests pass
- Proto files generate successfully
- No linting errors

## Next Steps

Once Phase 1 is complete and all tests pass, proceed to **[Phase 2: Local Integration Testing](02-phase2-integration.md)**.

---

[← Back to README](README.md) | [← Architecture](00-architecture.md) | [Phase 2: Integration →](02-phase2-integration.md)
