# Principal Authentication MVP - OIDC + JWT

## Implementation Status

**Status:** 🟢 Core Implementation Complete

| Component | Status | Notes |
|-----------|--------|-------|
| Data Models | ✅ Complete | Principal, Organization, Session |
| Store Interfaces | ✅ Complete | PrincipalStore, OrganizationStore, SessionStore |
| PostgreSQL Stores | ✅ Complete | All 3 stores with migrations |
| Memory Stores | ✅ Complete | For testing |
| GitHub OAuth | ✅ Complete | Login, callback, logout, auto org creation |
| Session Management | ✅ Complete | Server-side sessions, opaque cookies |
| OIDC Provider | ✅ Complete | Discovery, JWKS, token endpoint |
| JWT Middleware | ✅ Complete | User + Worker JWT verification |
| Public Key Cache | ✅ Complete | JWKS + worker key caching |
| Revocation Checker | ✅ Complete | Background polling |
| PrincipalService RPC | ✅ Implemented | GetPublicKey, ListRevokedPrincipals |
| CredentialService RPC | ⚪ Stubbed | Waiting for auth context extraction |
| Website RPC Registration | ⚪ Not done | Services not registered on mux |
| RPC Server Wiring | ✅ Complete | JWT middleware, caching, revocation |
| Integration Tests | ✅ Partial | OIDC + JWT signing tests |

---

## Overview

**Goal:** Principal-based authentication where:
- Website acts as OIDC provider (owns principals, signs JWTs for users)
- API verifies JWTs (stateless, in-memory cache only)
- Two authentication types:
  - **User JWTs**: Signed by website for web frontend → API calls
  - **Worker JWTs**: Self-signed by CLI/workers for direct API access

**Key Simplifications:**
- In-memory cache for public keys (no Redis)
- Shared credentials for worker pools (not per-worker)
- UUIDv7 for all identity columns
- Server-side sessions with opaque cookie IDs

---

## Architecture

```
┌─────────────────┐
│  Website (443)  │  OIDC Provider + Principal Management
│                 │
│  Components:    │
│  • PrincipalStore (PostgreSQL)
│  • OrganizationStore
│  • SessionStore
│  • OIDC KeyManager
│  • PrincipalService (RPC, public)
│  • CredentialService (RPC, authenticated)
│  • GitHub OAuth handlers
│  • OIDC endpoints (HTTP)
└────────┬────────┘
         │
         │ Connect RPC (HTTP caching)
         │
┌────────▼────────┐
│ API Server      │  Stateless JWT Verification
│    (8993)       │
│                 │
│  Components:    │
│  • JWT Middleware (user + worker)
│  • PublicKeyCache (in-memory)
│  • RevocationChecker (background)
│  • PrincipalServiceClient
└─────────────────┘
```

---

## Files Created

```
internal/models/
├── principal.go           # Principal model with UUIDv7, soft delete
├── organization.go        # Organization model
└── session.go             # Session model with expiration

internal/store/
├── principal_store.go     # PrincipalStore interface (9 methods)
├── organization_store.go  # OrganizationStore interface (5 methods)
├── session_store.go       # SessionStore interface (6 methods)
├── postgres/
│   ├── migrations/
│   │   ├── 1_initial_schema.sql    # Jobs, job_events tables
│   │   ├── 2_principal_auth.sql    # Organizations, principals tables
│   │   └── 3_sessions.sql          # Sessions table, principal profile fields
│   ├── principal_store.go          # PostgreSQL implementation (493 lines)
│   ├── organization_store.go       # PostgreSQL implementation (182 lines)
│   ├── session_store.go            # PostgreSQL implementation (194 lines)
│   └── errors.go                   # isUniqueViolation helper
└── memory/
    ├── principal_store.go          # In-memory for tests (232 lines)
    ├── organization_store.go       # In-memory for tests (111 lines)
    └── session_store.go            # In-memory for tests (161 lines)

api/principal/v1/
└── principal.proto        # PrincipalService + CredentialService

api/gen/proto/go/principal/v1/
├── principal.pb.go        # Generated proto messages
└── principalv1connect/
    └── principal.connect.go   # Generated Connect RPC interfaces

internal/server/
├── principal_service.go   # PrincipalService implementation (complete)
└── credential_service.go  # CredentialService implementation (stubbed)

internal/website/oidc/
├── key_manager.go         # ECDSA keypair management, JWT signing
├── handlers.go            # OIDC discovery, JWKS, token endpoints
└── session_adapter.go     # Bridges login session to OIDC interface

internal/login/
└── login.go               # GitHub OAuth (login, callback, logout, auto org)

internal/auth/
├── jwt_middleware.go      # Dual JWT verification (user + worker), context helpers
├── public_key_cache.go    # JWKS and database key caching
└── revocation_checker.go  # Periodic revocation list refresh

internal/client/
├── caching_transport.go       # HTTP caching wrapper for Connect RPC
└── principal_store_adapter.go # RPC-based PrincipalStore for API servers

cmd/server/internal/commands/
├── website.go             # Website server wiring (OAuth, OIDC, sessions)
└── rpc.go                 # RPC server wiring (JWT middleware, revocation)
```

---

## Data Models

### Principal

```go
type Principal struct {
    PrincipalID  uuid.UUID  // UUIDv7
    OrgID        uuid.UUID  // FK to organizations
    Type         string     // "user", "worker", "service"
    Name         string     // Display name

    // User principals (GitHub OAuth)
    GitHubID     *string    // GitHub numeric ID
    GitHubLogin  *string    // GitHub username
    Email        *string    // Primary email
    AvatarURL    *string    // Profile picture

    // Worker/service principals
    PublicKey    *string    // PEM format
    PublicKeyDER []byte     // DER format for verification
    Fingerprint  *string    // Base58-encoded SHA256(PublicKeyDER)

    // Authorization
    Roles        []string   // ["admin", "worker", "user", "readonly"]

    // Timestamps
    CreatedAt    time.Time
    UpdatedAt    time.Time
    LastUsedAt   *time.Time
    DeletedAt    *time.Time  // Soft delete for revocation tracking
}
```

### Organization

```go
type Organization struct {
    OrgID            uuid.UUID  // UUIDv7
    Name             string     // Typically GitHub username
    OwnerPrincipalID uuid.UUID  // FK to principals
    CreatedAt        time.Time
    UpdatedAt        time.Time
}
```

### Session

```go
type Session struct {
    SessionID   uuid.UUID  // UUIDv7 - stored in opaque cookie
    PrincipalID uuid.UUID  // Who is logged in
    OrgID       uuid.UUID  // Denormalized for fast JWT claims
    CreatedAt   time.Time
    ExpiresAt   time.Time
    LastUsedAt  time.Time
    UserAgent   string     // Audit trail
    IPAddress   string     // Audit trail (INET type)
}
```

---

## Authentication Flows

### User Flow (Web → API)

```
1. User → GET /login
2. Website → Redirect to GitHub OAuth
3. GitHub → Callback with code
4. Website → Exchange code for access token
5. Website → Fetch GitHub user info
6. Website → Create org + principal (first login) OR update principal (returning)
7. Website → Create session in SessionStore
8. Website → Set cookie: _session=<UUIDv7> (HttpOnly, Secure, SameSite=Lax)
9. User → POST /auth/token (with session cookie)
10. Website → Look up session, get principal
11. Website → Sign JWT with claims (sub, org, roles, principal_id)
12. Website → Return JWT
13. User → API request with Authorization: Bearer <JWT>
14. API → Verify JWT signature against JWKS
15. API → Extract principal from claims (zero DB lookups)
```

### Worker Flow (CLI → API)

```
1. Admin → CLI: airunner-cli init --name "production-workers"
2. CLI → Generate ECDSA P-256 keypair
3. CLI → Display credential blob (base58-encoded)
4. Admin → Website: Import credential blob
5. Website → Create worker principal, store public key
6. Admin → Distribute private key to workers (K8s secret, etc.)
7. Worker → Create JWT, sign with private key
8. Worker → API request with Authorization: Bearer <JWT>
9. API → Check revocation blocklist (in-memory)
10. API → Fetch public key (cached or RPC call)
11. API → Verify JWT signature
12. API → Extract claims (zero DB lookups)
```

---

## JWT Structures

### User JWT (Signed by Website)

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "5K3JmN8xQz..."
}
{
  "iss": "https://website.airunner.dev",
  "sub": "018f1234-5678-7abc-def0-123456789abc",
  "aud": "https://api.airunner.dev",
  "org": "018f1234-5678-7abc-def0-abcdef123456",
  "roles": ["admin", "user"],
  "principal_id": "018f1234-5678-7abc-def0-123456789abc",
  "iat": 1234567890,
  "exp": 1234571490
}
```

### Worker JWT (Self-Signed)

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "7RpMx9NqK4..."
}
{
  "iss": "airunner-cli",
  "sub": "7RpMx9NqK4...",
  "org": "018f1234-5678-7abc-def0-abcdef123456",
  "roles": ["worker"],
  "principal_id": "018f1234-5678-7abc-def0-fedcba987654",
  "pool": "production-workers",
  "iat": 1234567890,
  "exp": 1234571490
}
```

---

## OIDC Endpoints (Website)

| Endpoint | Method | Description | Cache |
|----------|--------|-------------|-------|
| `/.well-known/openid-configuration` | GET | OIDC discovery | 24h |
| `/.well-known/jwks.json` | GET | Website public key | 1h |
| `/auth/token` | POST | Issue user JWT (requires session) | - |

---

## Proto Services

### PrincipalService (Public, No Auth)

```protobuf
service PrincipalService {
  rpc GetPublicKey(GetPublicKeyRequest) returns (GetPublicKeyResponse);
  rpc ListRevokedPrincipals(ListRevokedPrincipalsRequest) returns (ListRevokedPrincipalsResponse);
}
```

- `GetPublicKey`: Fetch worker public key by fingerprint (cached 24h)
- `ListRevokedPrincipals`: List all revoked fingerprints (polled every 5min)

### CredentialService (Authenticated, Session-Based)

```protobuf
service CredentialService {
  rpc ImportCredential(ImportCredentialRequest) returns (ImportCredentialResponse);
  rpc ListCredentials(ListCredentialsRequest) returns (ListCredentialsResponse);
  rpc RevokeCredential(RevokeCredentialRequest) returns (RevokeCredentialResponse);
}
```

- `ImportCredential`: Import worker credential from base58 blob
- `ListCredentials`: List credentials for current user's org
- `RevokeCredential`: Soft-delete credential, add to revocation list

---

## Remaining Work

### 1. Register RPC Services on Website

**Status:** Not wired

The `PrincipalService` and `CredentialService` servers are implemented but not registered on the website's HTTP mux.

**Files to modify:**
- `cmd/server/internal/commands/website.go` - Register Connect RPC handlers

```go
// Add to website.go imports
principalv1connect "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"

// Add after OIDC endpoints registration
principalService := server.NewPrincipalServiceServer(principalStore)
credentialService := server.NewCredentialServiceServer(principalStore, organizationStore)

principalPath, principalHandler := principalv1connect.NewPrincipalServiceHandler(principalService)
mux.Handle(principalPath, principalHandler)

credentialPath, credentialHandler := principalv1connect.NewCredentialServiceHandler(credentialService)
mux.Handle(credentialPath, credentialHandler)
```

### 2. CredentialService Implementation

**Status:** Stubbed with TODO comments

**Blocking Issue:** Need to extract authenticated principal from request context.

The handlers need to:

1. Extract the Principal from session/JWT context
2. Verify the principal has permission (same org, admin role)
3. Perform the operation

**Files to modify:**
- `internal/server/credential_service.go` - Implement the 3 RPC methods

**Example pattern (from code comments):**

```go
func (s *CredentialServiceServer) ListCredentials(
    ctx context.Context,
    req *connect.Request[principalv1.ListCredentialsRequest],
) (*connect.Response[principalv1.ListCredentialsResponse], error) {
    // Extract current user from context
    principal, ok := auth.PrincipalFromContext(ctx)
    if !ok {
        return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
    }

    // List credentials for user's org
    credentials, err := s.principalStore.ListByOrg(ctx, principal.OrgID, req.Msg.PrincipalType)
    // ... convert to response
}
```

### 2. Credential Blob Format

**Status:** Not specified

Need to define the base58-encoded blob format for `ImportCredential`:

```
Proposed format:
- Version byte (1)
- Name length (1 byte) + Name (UTF-8)
- Public key DER (variable)
- Checksum (4 bytes, SHA256 prefix)
```

### 3. Additional Integration Tests

**Current coverage:**
- OIDC discovery endpoint
- JWT signing/verification

**Missing:**
- Worker JWT verification flow
- Revocation checking
- CredentialService RPCs (once implemented)
- Full end-to-end user flow

---

## Configuration

### Website Server

```bash
./bin/airunner-server website \
  --store-type=postgres \
  --postgres-conn-string="postgres://user:pass@localhost:5432/airunner" \
  --github-client-id="<client-id>" \
  --github-client-secret="<client-secret>" \
  --github-callback-url="https://website.airunner.dev/github/callback" \
  --base-url="https://website.airunner.dev" \
  --api-base-url="https://api.airunner.dev"
```

### RPC Server

```bash
./bin/airunner-server rpc \
  --store-type=postgres \
  --postgres-conn-string="postgres://user:pass@localhost:5432/airunner" \
  --website-base-url="https://website.airunner.dev" \
  --revocation-refresh-interval="5m"
```

---

## Performance Characteristics

At scale (100k workers, 1.2M requests/min):

| Operation | Latency | Notes |
|-----------|---------|-------|
| JWT Verification | ~1ms | ECDSA signature verification |
| Public Key Cache | >99% hit | Keys rarely change |
| Revocation Check | <1ms | In-memory map lookup |
| Database Queries | 0 | All data in JWT claims |

Compare to database-backed auth: ~10-50ms per request

---

## Security Considerations

- **Session cookies**: HttpOnly, Secure, SameSite=Lax
- **Immediate revocation**: Delete session = instant logout for users
- **Delayed revocation for workers**: 5-minute polling window (acceptable for MVP)
- **No secrets in cookies**: Opaque session ID only
- **ECDSA P-256**: Standard curve for JWT signing
- **UUIDv7**: Time-ordered, no information leakage

---

## Out of Scope (Future)

- Token refresh
- KMS-backed credentials
- Multi-org membership
- Advanced metrics/monitoring
- Per-worker credentials (use pools instead)
- Immediate worker revocation (5 min delay acceptable)
- Redis caching (in-memory sufficient)
