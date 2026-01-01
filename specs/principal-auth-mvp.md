# Principal Authentication MVP - OIDC + JWT

## Overview

**Goal:** Implement principal-based authentication where:
- Website acts as OIDC provider (owns principals, signs JWTs for users)
- API verifies JWTs (stateless, in-memory cache only)
- Two types of authentication:
  - **User JWTs**: Signed by website for web frontend → API calls
  - **Worker JWTs**: Self-signed by CLI/workers for direct API access

**MVP Simplifications:**
- ✅ In-memory cache for public keys (no Redis)
- ✅ Shared credentials for worker pools (not per-worker)
- ✅ UUIDv7 for all identity columns (sortable, time-ordered)
- ✅ PostgreSQL native UUID type

## Architecture

```
┌─────────────────┐
│    Website      │ ← Identity Provider (OIDC)
│   (Port 443)    │
│                 │
│  Owns:          │
│  - principals   │ ← PostgreSQL
│  - organizations│
│  - OIDC keypair │
│                 │
│  Exposes:       │
│  - /.well-known/jwks.json (website public key)
│  - PrincipalService gRPC (worker keys + revocation)
└────────┬────────┘
         │
         │ API fetches via Connect RPC (with client-side caching)
         │
         ▼
┌─────────────────┐
│   API Server    │ ← Stateless JWT verification
│  (Port 8993)    │
│                 │
│  In-memory:     │
│  - Public key cache (map[fingerprint]key)
│  - Revocation blocklist (map[fingerprint]bool)
│                 │
│  NO database!   │
│  NO Redis!      │
└─────────────────┘
```

## Key Design: Shared Credentials for Worker Pools

**Recommended pattern:**
```
Organization: "acme-corp" (UUIDv7: 018f1234-5678-7abc-def0-123456789abc)
  │
  ├── Worker Pool: "production-workers"
  │   └── 1 shared keypair
  │       ├── 50 workers all use same private key
  │       └── 1 public key cached by API
  │
  ├── Worker Pool: "staging-workers"
  │   └── 1 shared keypair
  │       ├── 10 workers all use same private key
  │       └── 1 public key cached by API
  │
  └── CI/CD: "github-actions"
      └── 1 shared keypair
          └── Stored in GitHub Secrets
```

**Benefits:**
- ✅ Minimal cache overhead (2-5 keys per org, not 100+)
- ✅ Easy to rotate (update pool credential, restart workers)
- ✅ Natural security boundaries (prod vs staging vs CI)
- ✅ Scales with org sharding (each API instance caches ~10 keys max)

## Data Models

### Organization

```go
type Organization struct {
    OrgID            uuid.UUID  // UUIDv7
    Name             string
    OwnerPrincipalID uuid.UUID  // UUIDv7, FK to principals
    CreatedAt        time.Time
    UpdatedAt        time.Time
}
```

### Principal

```go
type Principal struct {
    PrincipalID  uuid.UUID  // UUIDv7
    OrgID        uuid.UUID  // UUIDv7, FK to organizations
    Type         string     // "user", "worker", "service"
    Name         string     // e.g., "production-workers", "Jane Doe"

    // For user principals (GitHub OAuth)
    GitHubID     *string    // GitHub user ID

    // For worker/service principals
    PublicKey    string     // PEM format (for display/export)
    PublicKeyDER []byte     // DER format (for JWT verification)
    Fingerprint  string     // Base58-encoded SHA256(PublicKeyDER)

    // Authorization
    Roles        []string   // ["admin", "worker", "user", "readonly"]

    // Metadata
    CreatedAt    time.Time
    UpdatedAt    time.Time
    LastUsedAt   *time.Time
    DeletedAt    *time.Time  // Soft delete for revocation tracking
}
```

## PostgreSQL Schema

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    org_id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner_principal_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_owner
    ON organizations(owner_principal_id);

-- Principals table
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    deleted_at TIMESTAMP,  -- Soft delete for revocation tracking

    -- Constraints
    CONSTRAINT principal_type_fields CHECK (
        (type = 'user' AND github_id IS NOT NULL AND fingerprint IS NULL) OR
        (type IN ('worker', 'service') AND fingerprint IS NOT NULL AND github_id IS NULL)
    )
);

-- Critical indexes
CREATE INDEX IF NOT EXISTS idx_principals_fingerprint
    ON principals(fingerprint) WHERE fingerprint IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_principals_github_id
    ON principals(github_id) WHERE github_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_principals_org_type
    ON principals(org_id, type) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_principals_revoked
    ON principals(deleted_at) WHERE deleted_at IS NOT NULL;
```

## Store Interfaces

### PrincipalStore

```go
package store

import (
    "context"
    "github.com/google/uuid"
    "github.com/wolfeidau/airunner/internal/models"
)

type PrincipalStore interface {
    Create(ctx context.Context, principal *models.Principal) error
    Get(ctx context.Context, principalID uuid.UUID) (*models.Principal, error)
    GetByFingerprint(ctx context.Context, fingerprint string) (*models.Principal, error)
    GetByGitHubID(ctx context.Context, githubID string) (*models.Principal, error)
    Update(ctx context.Context, principal *models.Principal) error
    Delete(ctx context.Context, principalID uuid.UUID) error
    ListByOrg(ctx context.Context, orgID uuid.UUID, principalType *string) ([]*models.Principal, error)
    ListRevoked(ctx context.Context) ([]*models.Principal, error) // For revocation list
    UpdateLastUsed(ctx context.Context, principalID uuid.UUID) error
}
```

### OrganizationStore

```go
package store

import (
    "context"
    "github.com/google/uuid"
    "github.com/wolfeidau/airunner/internal/models"
)

type OrganizationStore interface {
    Create(ctx context.Context, org *models.Organization) error
    Get(ctx context.Context, orgID uuid.UUID) (*models.Organization, error)
    Update(ctx context.Context, org *models.Organization) error
    Delete(ctx context.Context, orgID uuid.UUID) error
    ListByOwner(ctx context.Context, ownerPrincipalID uuid.UUID) ([]*models.Organization, error)
}
```

## JWT Structures

### User JWT (Signed by Website)

**Header:**
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "5K3JmN8xQz2PwRvT6YsLqC9Hf"
}
```

**Claims:**
```json
{
  "iss": "https://website.airunner.dev",
  "sub": "018f1234-5678-7abc-def0-123456789abc",
  "aud": "https://api.airunner.dev",
  "org": "018f1234-5678-7abc-def0-abcdef123456",
  "roles": ["admin", "user"],
  "iat": 1234567890,
  "exp": 1234571490
}
```

### Worker JWT (Self-Signed)

**Header:**
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "7RpMx9NqK4WvBz5FsLcY3TgHm"
}
```

**Claims:**
```json
{
  "iss": "airunner-cli",
  "sub": "7RpMx9NqK4WvBz5FsLcY3TgHm",
  "org": "018f1234-5678-7abc-def0-abcdef123456",
  "roles": ["worker"],
  "principal_id": "018f1234-5678-7abc-def0-fedcba987654",
  "pool": "production-workers",
  "iat": 1234567890,
  "exp": 1234571490
}
```

## OIDC Endpoints (Website)

### 1. Discovery: `GET /.well-known/openid-configuration`

**Response:**
```json
{
  "issuer": "https://website.airunner.dev",
  "jwks_uri": "https://website.airunner.dev/.well-known/jwks.json",
  "token_endpoint": "https://website.airunner.dev/auth/token",
  "response_types_supported": ["token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

### 2. JWKS: `GET /.well-known/jwks.json`

**Response:**
```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "5K3JmN8xQz2PwRvT6YsLqC9Hf",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate",
      "alg": "ES256"
    }
  ]
}
```

### 3. Token: `POST /auth/token`

**Request:** (session cookie required)

**Response:**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVLM0ptTjh4UXoyUHdSdlQ2WXNMcUM5SGYifQ...",
  "token_type": "Bearer",
  "expires_in": "3600"
}
```

## Principal Service (Connect RPC)

**Proto file:** `api/principal/v1/principal.proto`

```protobuf
syntax = "proto3";

package principal.v1;

option go_package = "github.com/wolfeidau/airunner/gen/principal/v1;principalv1";

// PrincipalService provides public key lookup and revocation info
// for API servers to verify worker JWTs.
// These endpoints are PUBLIC (no auth required) for MVP.
service PrincipalService {
  // GetPublicKey fetches a worker's public key by fingerprint.
  // Used by API server to verify worker JWTs (cached).
  rpc GetPublicKey(GetPublicKeyRequest) returns (GetPublicKeyResponse);

  // ListRevokedPrincipals returns all currently revoked fingerprints.
  // Used by API server to maintain revocation blocklist (polled every 5 min).
  rpc ListRevokedPrincipals(ListRevokedPrincipalsRequest) returns (ListRevokedPrincipalsResponse);
}

message GetPublicKeyRequest {
  string fingerprint = 1; // Base58-encoded fingerprint
}

message GetPublicKeyResponse {
  string fingerprint = 1;
  string public_key_pem = 2; // PEM-encoded ECDSA P-256 public key
  string org_id = 3;         // UUIDv7 as string
}

message ListRevokedPrincipalsRequest {
  // Empty for MVP (future: pagination, since timestamp, etc.)
}

message ListRevokedPrincipalsResponse {
  repeated string fingerprints = 1; // List of revoked fingerprints
}
```

**Implementation notes:**
- Public endpoints (no authentication required for MVP)
- Website implements `PrincipalService`
- API server uses Connect RPC client with caching interceptor
- Served alongside OIDC endpoints on website server

## Credential Management Service (Connect RPC)

**Proto file:** `api/principal/v1/principal.proto` (same file as PrincipalService)

```protobuf
// CredentialService provides credential management for web UI.
// These endpoints require authentication (session-based).
service CredentialService {
  // ImportCredential imports a worker credential from a base58-encoded blob.
  // Creates a new worker principal and stores the public key.
  rpc ImportCredential(ImportCredentialRequest) returns (ImportCredentialResponse);

  // ListCredentials returns all credentials (principals) for the current user's org.
  rpc ListCredentials(ListCredentialsRequest) returns (ListCredentialsResponse);

  // RevokeCredential revokes a credential by principal ID.
  // Adds fingerprint to revocation list and deletes principal.
  rpc RevokeCredential(RevokeCredentialRequest) returns (RevokeCredentialResponse);
}

message ImportCredentialRequest {
  string blob = 1; // Base58-encoded credential blob
}

message ImportCredentialResponse {
  string principal_id = 1; // UUIDv7 as string
  string org_id = 2;       // UUIDv7 as string
  repeated string roles = 3;
  string fingerprint = 4;  // Base58-encoded fingerprint
  string name = 5;         // Credential name from blob
}

message ListCredentialsRequest {
  string principal_type = 1; // Optional filter: "user", "worker", "service"
}

message Credential {
  string principal_id = 1;
  string org_id = 2;
  string type = 3;          // "user", "worker", "service"
  string name = 4;
  string fingerprint = 5;   // Empty for user principals
  repeated string roles = 6;
  string created_at = 7;    // RFC3339 timestamp
  string last_used_at = 8;  // RFC3339 timestamp (optional)
}

message ListCredentialsResponse {
  repeated Credential credentials = 1;
}

message RevokeCredentialRequest {
  string principal_id = 1; // UUIDv7 as string
}

message RevokeCredentialResponse {
  // Empty response (success indicated by no error)
}
```

**Implementation notes:**
- Authenticated endpoints (require valid session)
- Website implements `CredentialService`
- Session middleware validates user before calling RPCs
- Used by web UI for credential management

## HTTP Caching (API Server)

Use Connect's built-in GET request and HTTP caching support instead of custom in-memory caches.

**Reference:** https://connectrpc.com/docs/go/get-requests-and-caching/

### Server Side (Website)

**PrincipalService implementation adds cache headers:**

```go
// In principal_service.go
func (s *PrincipalServiceServer) GetPublicKey(
    ctx context.Context,
    req *connect.Request[principalv1.GetPublicKeyRequest],
) (*connect.Response[principalv1.GetPublicKeyResponse], error) {
    // Fetch principal from database
    principal, err := s.principalStore.GetByFingerprint(ctx, req.Msg.Fingerprint)
    if err != nil {
        return nil, connect.NewError(connect.CodeNotFound, err)
    }

    resp := connect.NewResponse(&principalv1.GetPublicKeyResponse{
        Fingerprint:  principal.Fingerprint,
        PublicKeyPem: principal.PublicKey,
        OrgId:        principal.OrgID.String(),
    })

    // Add HTTP cache headers (public keys rarely change)
    resp.Header().Set("Cache-Control", "public, max-age=86400") // 24 hours
    resp.Header().Set("ETag", fmt.Sprintf(`"%s"`, principal.Fingerprint))

    return resp, nil
}

func (s *PrincipalServiceServer) ListRevokedPrincipals(
    ctx context.Context,
    req *connect.Request[principalv1.ListRevokedPrincipalsRequest],
) (*connect.Response[principalv1.ListRevokedPrincipalsResponse], error) {
    // Fetch all principals where deleted_at IS NOT NULL or similar
    revoked, err := s.principalStore.ListRevoked(ctx)
    if err != nil {
        return nil, err
    }

    fingerprints := make([]string, len(revoked))
    for i, p := range revoked {
        fingerprints[i] = p.Fingerprint
    }

    resp := connect.NewResponse(&principalv1.ListRevokedPrincipalsResponse{
        Fingerprints: fingerprints,
    })

    // Shorter cache for revocation list (5 minutes)
    resp.Header().Set("Cache-Control", "public, max-age=300")

    return resp, nil
}
```

### Client Side (API Server)

**Use HTTP caching transport with Connect RPC client:**

```go
import (
    "github.com/gregjones/httpcache"
    "github.com/gregjones/httpcache/diskcache"
    "connectrpc.com/connect"
)

// Create HTTP client with caching transport
func NewCachingHTTPClient() *http.Client {
    // Use in-memory cache (or disk cache for persistence)
    cache := httpcache.NewMemoryCache()
    transport := httpcache.NewTransport(cache)

    return &http.Client{
        Transport: transport,
    }
}

// Create Connect RPC client with caching HTTP client
func NewPrincipalServiceClient(baseURL string) principalv1connect.PrincipalServiceClient {
    httpClient := NewCachingHTTPClient()

    return principalv1connect.NewPrincipalServiceClient(
        httpClient,
        baseURL,
        connect.WithGRPC(), // or connect.WithGRPCWeb()
    )
}
```

**Usage in JWT middleware:**

```go
func JWTAuthMiddleware(principalClient principalv1connect.PrincipalServiceClient) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // ... extract JWT, parse header ...

            if issuer == "airunner-cli" {
                // Worker JWT - fetch public key via cached RPC
                resp, err := principalClient.GetPublicKey(r.Context(),
                    connect.NewRequest(&principalv1.GetPublicKeyRequest{
                        Fingerprint: fingerprint,
                    }),
                )
                // HTTP cache handles caching automatically!
                // First call hits website, subsequent calls served from cache

                publicKey := parsePublicKeyPEM(resp.Msg.PublicKeyPem)
                orgID := uuid.Parse(resp.Msg.OrgId)

                // Verify JWT signature...
            }

            // ... continue with auth ...
        })
    }
}
```

**Revocation check with periodic refresh:**

```go
type RevocationChecker struct {
    client     principalv1connect.PrincipalServiceClient
    revoked    map[string]bool
    mu         sync.RWMutex
}

func (r *RevocationChecker) IsRevoked(fingerprint string) bool {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.revoked[fingerprint]
}

func (r *RevocationChecker) StartRefresh(ctx context.Context) {
    // Initial load
    r.refresh(ctx)

    // Refresh every 5 minutes
    ticker := time.NewTicker(5 * time.Minute)
    go func() {
        for {
            select {
            case <-ticker.C:
                r.refresh(ctx)
            case <-ctx.Done():
                return
            }
        }
    }()
}

func (r *RevocationChecker) refresh(ctx context.Context) {
    resp, err := r.client.ListRevokedPrincipals(ctx,
        connect.NewRequest(&principalv1.ListRevokedPrincipalsRequest{}),
    )
    if err != nil {
        log.Error().Err(err).Msg("failed to refresh revocation list")
        return
    }

    // Update in-memory set
    newRevoked := make(map[string]bool)
    for _, fp := range resp.Msg.Fingerprints {
        newRevoked[fp] = true
    }

    r.mu.Lock()
    r.revoked = newRevoked
    r.mu.Unlock()
}
```

**Benefits of HTTP caching approach:**
- ✅ Leverage standard HTTP caching (Cache-Control, ETag, If-None-Match)
- ✅ No custom cache implementation needed
- ✅ Works with any HTTP cache library (`httpcache`, `groupcache`, etc.)
- ✅ Can use disk cache for persistence across restarts
- ✅ Standard HTTP debugging tools work
- ✅ Automatic revalidation with ETags
- ✅ Connect RPC handles GET requests automatically for idempotent RPCs

## Authentication Flows

### User Flow (Web → API)

```
1. User → Website: Login via GitHub OAuth
2. Website → User: Set session cookie
3. User → Website: POST /auth/token (with session cookie)
4. Website: Validate session, sign JWT with private key
5. Website → User: Return JWT
6. User → API: Request with Authorization: Bearer <JWT>
7. API: Parse JWT, extract issuer = "https://website.airunner.dev"
8. API: Fetch public key from JWKS (cached)
9. API: Verify JWT signature
10. API: Extract org, roles from claims
11. API: Process request (no DB lookup!)
```

### Worker Flow (CLI → API)

```
1. Admin → CLI: airunner-cli init --name "production-workers"
2. CLI: Generate ECDSA P-256 keypair
3. CLI: Display credential blob
4. Admin → Website: Paste blob, import credential
5. Website: Create principal, store public key in DB
6. Website → Admin: Return {principal_id, org_id, roles}
7. Admin: Distribute private key to worker pool (K8s secret, etc.)
8. Worker: Load private key
9. Worker: Create JWT with claims (org, roles), sign with private key
10. Worker → API: Request with Authorization: Bearer <JWT>
11. API: Parse JWT, extract issuer = "airunner-cli"
12. API: Check revocation blocklist (cached)
13. API: Fetch public key (cached or Connect RPC call to PrincipalService)
14. API: Verify JWT signature
15. API: Extract org, roles from claims
16. API: Process request (no DB lookup!)
```

## Implementation Phases

### Phase 1: Data Models and Interfaces

**Files:**
- `internal/models/principal.go`
- `internal/models/organization.go`
- `internal/store/principal_store.go`
- `internal/store/organization_store.go`

**Use:** `github.com/google/uuid` for UUIDv7 generation

### Phase 2: PostgreSQL Stores

**Files:**
- `internal/store/postgres/principal_store.go`
- `internal/store/postgres/organization_store.go`
- `internal/store/postgres/schema.sql`

**Key points:**
- Use `uuid.NewV7()` for ID generation
- Store as PostgreSQL UUID type
- Auto-migration on startup (like JobStore)
- Use pgx for connection pool

### Phase 3: Memory Stores (Testing)

**Files:**
- `internal/store/memory/principal_store.go`
- `internal/store/memory/organization_store.go`

**Implementation:**
- `map[uuid.UUID]*Principal` with `sync.RWMutex`
- Follow pattern from `memory/job_store.go`

### Phase 4: OIDC Implementation (Website)

**Files:**
- `internal/website/oidc/keys.go`
- `internal/website/oidc/handlers.go`

**Endpoints:**
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `POST /auth/token`

### Phase 5: gRPC Services Implementation (Website)

**Files:**
- `api/principal/v1/principal.proto` (new proto file with both services)
- `internal/server/principal_service.go` (implements PrincipalService)
- `internal/server/credential_service.go` (implements CredentialService)

**PrincipalService (public, no auth):**
- `GetPublicKey` - Fetch worker public key by fingerprint
- `ListRevokedPrincipals` - List all revoked fingerprints

**CredentialService (authenticated, session-based):**
- `ImportCredential` - Import worker credential blob
- `ListCredentials` - List credentials for current user's org
- `RevokeCredential` - Revoke credential and add to blocklist

### Phase 6: HTTP Caching Setup (API)

**Files:**
- `internal/auth/client.go` (HTTP caching client setup)
- `internal/auth/revocation.go` (RevocationChecker with periodic refresh)

**Components:**
- Connect RPC client with HTTP caching transport (`github.com/gregjones/httpcache`)
- RevocationChecker with background refresh goroutine
- Website adds Cache-Control headers to PrincipalService responses

**Key implementation:**
- Use `httpcache.NewMemoryCache()` for public key caching (24h TTL)
- RevocationChecker refreshes list every 5 minutes via RPC
- No custom cache code - leverage HTTP standards

### Phase 7: JWT Verification (API)

**Files:**
- `internal/auth/middleware.go`
- `internal/auth/jwks_cache.go`

**Implementation:**
- Dual JWT verification (user + worker)
- JWKS cache for website's public key
- Public key cache for worker keys
- Revocation check

### Phase 8: Wire Everything Together

**Files:**
- `cmd/server/internal/commands/website.go`
- `cmd/server/internal/commands/rpc.go`

**Website server changes:**
- Register PrincipalService (public) alongside JobService
- Register CredentialService (authenticated) with session middleware
- Inject PrincipalStore and OrganizationStore into both services

**API server changes:**
- Create Connect RPC client for PrincipalService
- Initialize PublicKeyCache and RevocationCache with client
- Configure caching interceptor for RPC client
- Wire JWT middleware with caches

## Testing Strategy

### Unit Tests
- Store implementations (memory)
- OIDC key manager (key generation, JWK conversion)
- JWT signing/verification
- In-memory caches
- Middleware

### Integration Tests
- PostgreSQL stores (testcontainers)
- Full auth flow (GitHub → token → API)
- OIDC endpoints
- CredentialService RPCs (import/list/revoke)
- PrincipalService RPCs (public key lookup, revocation list)
- Cache refresh and RPC client caching

### Manual Testing
1. Start PostgreSQL (testcontainers or docker-compose)
2. Start website server
3. Start API server
4. Login via GitHub → request JWT → call API
5. Import worker credential → sign JWT → call API
6. Revoke credential → verify API rejects

## Configuration

### Website Server

```yaml
# PostgreSQL
postgres_connection_string: "postgres://user:pass@localhost:5432/airunner"

# OIDC
oidc_issuer: "https://website.airunner.dev"

# Session
session_secret: "<32-byte-secret>"
session_ttl: "168h" # 7 days

# GitHub OAuth
github_client_id: "<client-id>"
github_client_secret: "<client-secret>"
github_callback_url: "https://website.airunner.dev/github/callback"
```

### API Server

```yaml
# Website gRPC endpoint (for PrincipalService)
principal_service_url: "https://website.airunner.dev"

# Cache refresh
revocation_refresh_interval: "5m"
public_key_ttl: "24h"

# Job store (existing)
store_type: "postgres"
postgres_connection_string: "postgres://user:pass@localhost:5432/airunner"
```

## Success Criteria

- [ ] User can login via GitHub, get JWT, call API successfully
- [ ] Worker pool can import shared credential via CredentialService RPC
- [ ] Workers can sign JWTs and call API successfully
- [ ] API verifies both JWT types using HTTP caching (no DB lookups)
- [ ] PrincipalService RPCs work with Cache-Control headers
- [ ] CredentialService RPCs work (ImportCredential, ListCredentials, RevokeCredential)
- [ ] HTTP caching transport works with httpcache library
- [ ] Revocation works (periodic refresh, max 5 min delay)
- [ ] All tests pass (unit + integration)
- [ ] PostgreSQL uses UUID type for all IDs
- [ ] UUIDv7 generation works correctly (time-ordered)
- [ ] Soft delete works for revocation tracking (deleted_at column)
- [ ] No Redis dependency

## Out of Scope (Future)

- Token refresh
- KMS-backed credentials
- Multi-org membership
- Advanced metrics/monitoring
- Per-worker credentials (use pools instead)
- Immediate revocation (5 min delay acceptable)
- Redis caching (in-memory sufficient for MVP)
