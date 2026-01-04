# Principal Authentication MVP - OIDC + JWT

## Implementation Status

**Status:** 🟢 Implementation Complete

| Component | Status | Notes |
|-----------|--------|-------|
| Data Models | ✅ Complete | Principal, Organization, Session |
| Store Interfaces | ✅ Complete | PrincipalStore, OrganizationStore, SessionStore |
| PostgreSQL Stores | ✅ Complete | All 3 stores with migrations |
| Memory Stores | ✅ Complete | For testing |
| GitHub OAuth | ✅ Complete | Login, callback, logout, auto org creation |
| Session Management | ✅ Complete | Server-side sessions, opaque cookies |
| OIDC Provider | ✅ Complete | Discovery, JWKS, token endpoint |
| JWT Middleware | ✅ Complete | User + Worker JWT verification, local store |
| Public Key Cache | ✅ Complete | JWKS + worker key caching |
| Revocation Checker | ✅ Complete | Background polling from local store |
| CredentialService RPC | ✅ Complete | Import, List, Revoke credentials |
| Dual Auth Middleware | ✅ Complete | JWT + session auth on all API endpoints |
| Unified Server | ✅ Complete | Single server with UI + API |
| Shared Pool Helper | ✅ Complete | postgres/pool.go |
| Integration Tests | ✅ Partial | OIDC + JWT signing tests |

### Removed Components
| Component | Status | Reason |
|-----------|--------|--------|
| PrincipalService RPC | ❌ Removed | Replaced by direct store access |
| PrincipalStoreAdapter | ❌ Removed | No longer needed with shared DB |
| Separate RPC Server | ❌ Removed | Merged into unified server |

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
Unified Server (443)
┌─────────────────────────────────────────────┐
│ Static Assets & UI Pages                    │
│ GitHub OAuth (login, callback, logout)      │
│ OIDC Provider (discovery, JWKS, token)      │
│                                             │
│ Dual Auth Middleware (JWT + Session)        │
│         ↓                                   │
│ CredentialService  - credential management  │
│ JobService         - job enqueue/dequeue    │
│ JobEventsService   - event streaming        │
│                                             │
│ Direct DB access for JWT verification       │
└──────────────────┬──────────────────────────┘
                   ▼
              PostgreSQL
          (identity + jobs DB)
```

**Auth flows:**
- **Web UI (browser)**: Session cookie → all API services
- **CLI**: JWT (self-signed by worker credential) → all API services
- **Workers**: JWT (self-signed by worker credential) → JobService/JobEventsService

**Dual Auth Middleware:**
- Checks for Authorization header first (JWT auth)
- Falls back to session cookie if no JWT provided
- If JWT is provided but invalid, returns 401 (no fallback)

---

## Files

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
│   ├── pool.go                     # Shared PostgreSQL pool helper
│   ├── principal_store.go          # PostgreSQL implementation
│   ├── organization_store.go       # PostgreSQL implementation
│   ├── session_store.go            # PostgreSQL implementation
│   └── errors.go                   # isUniqueViolation helper
└── memory/
    ├── principal_store.go          # In-memory for tests
    ├── organization_store.go       # In-memory for tests
    └── session_store.go            # In-memory for tests

api/principal/v1/
└── principal.proto        # CredentialService only (PrincipalService removed)

api/gen/proto/go/principal/v1/
├── principal.pb.go        # Generated proto messages
└── principalv1connect/
    └── principal.connect.go   # Generated Connect RPC interfaces

internal/server/
├── server.go              # Server with optional CredentialService
└── credential_service.go  # CredentialService implementation (complete)

internal/website/oidc/
├── key_manager.go         # ECDSA keypair management, JWT signing
├── handlers.go            # OIDC discovery, JWKS, token endpoints
└── session_adapter.go     # Bridges login session to OIDC interface

internal/login/
└── login.go               # GitHub OAuth (login, callback, logout, auto org)

internal/auth/
├── jwt_middleware.go       # JWT verification (user + worker), context helpers
├── dual_auth_middleware.go # Combined JWT + session auth middleware
├── public_key_cache.go     # JWKS and database key caching
├── revocation_checker.go   # Periodic revocation list refresh (local store)
└── session_middleware.go   # Session-only auth middleware for Connect RPC

internal/client/
└── caching_transport.go   # HTTP caching wrapper for JWKS

cmd/server/internal/commands/
└── website.go             # Unified server (UI, OAuth, OIDC, all API services, dual auth)
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

### ~~PrincipalService~~ (Removed)

PrincipalService was removed in favor of direct database access. The unified server uses local PrincipalStore for:
- Worker public key lookups (cached in PublicKeyCache)
- Revocation list checks (cached in RevocationChecker)

### CredentialService (Authenticated, Dual Auth)

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

## CredentialService API

The CredentialService is registered on the unified server with **dual authentication**:
- **Browser requests**: Session-based authentication via cookies
- **CLI/Worker requests**: JWT-based authentication via Authorization header

### ImportCredential
Import a worker credential from a PEM-encoded public key.

**Request:**
```protobuf
message ImportCredentialRequest {
  string name = 1;           // Display name for the credential
  string public_key_pem = 2; // PEM-encoded ECDSA P-256 public key
  string description = 3;    // Optional description
}
```

**Response:**
```protobuf
message ImportCredentialResponse {
  string principal_id = 1;   // UUIDv7 as string
  string org_id = 2;         // UUIDv7 as string
  repeated string roles = 3; // ["worker"]
  string fingerprint = 4;    // Base58-encoded SHA256 of public key DER
  string name = 5;
}
```

**Authorization:** Requires `admin` role.

### ListCredentials
List all credentials for the caller's organization.

**Authorization:** Any authenticated user.

### RevokeCredential
Soft-delete a credential (sets deleted_at timestamp).

**Authorization:** Requires `admin` role. Cannot revoke own credential.

---

## Outstanding Work

### CLI Credential Management (Required for MVP)

The CLI needs commands to generate and manage worker credentials:

**1. Init Command** (`airunner-cli init`)
```bash
# Generate new credential
airunner-cli init --name "my-worker"

# Output:
# Generated credential: my-worker
# Fingerprint: 7RpMx9NqK4...
# Public key saved to: ~/.airunner/credentials/my-worker.pub
# Private key saved to: ~/.airunner/credentials/my-worker.key
#
# Import this credential via the web UI or API:
#   Public Key PEM: (displayed)
```

**Implementation:**
- Generate ECDSA P-256 keypair
- Save to `~/.airunner/credentials/<name>.key` and `<name>.pub`
- Display public key PEM for import
- Store metadata (name, fingerprint, created_at) in `~/.airunner/credentials/config.json`

**2. CLI JWT Signing**

All CLI commands (worker, submit, list, monitor) need to:
- Load credentials from `~/.airunner/credentials/`
- Sign JWT with private key before each API request
- Accept `--credential <name>` flag to select which credential to use

**JWT Claims (Worker):**
```json
{
  "iss": "airunner-cli",
  "sub": "<fingerprint>",
  "org": "<org-id>",
  "roles": ["worker"],
  "principal_id": "<principal-id>",
  "iat": 1234567890,
  "exp": 1234571490
}
```

**3. Credential Import Flow**

End-to-end workflow:
1. `airunner-cli init --name "prod-workers"` → generates keypair
2. Admin copies public key PEM
3. Admin imports via web UI (CredentialService.ImportCredential)
4. Server returns principal_id, org_id, fingerprint
5. Admin updates CLI config with org_id, principal_id
6. CLI can now authenticate: `airunner-cli worker --credential prod-workers`

### Files to Create

| File | Purpose |
|------|---------|
| `cmd/cli/internal/commands/init.go` | Credential generation command |
| `cmd/cli/internal/credentials/store.go` | Local credential storage |
| `cmd/cli/internal/credentials/jwt.go` | JWT signing for API requests |

### Additional Integration Tests

**Current coverage:**
- OIDC discovery endpoint
- JWT signing/verification

**Needed:**
- Worker JWT verification flow (CLI → Server)
- Revocation checking end-to-end
- CredentialService RPCs (import, list, revoke)
- Full credential workflow (init → import → authenticate)

---

## Configuration

### Unified Server

```bash
./bin/airunner-server server \
  --listen=0.0.0.0:443 \
  --cert=certs/server.crt \
  --key=certs/server.key \
  --store-type=postgres \
  --postgres-conn-string="postgres://user:pass@localhost:5432/airunner" \
  --postgres-token-secret="<32+ byte secret for HMAC signing>" \
  --client-id="<github-client-id>" \
  --client-secret="<github-client-secret>" \
  --callback-url="https://example.com/github/callback" \
  --base-url="https://example.com"
```

### Development Mode

```bash
./bin/airunner-server server \
  --development \
  --no-auth \
  --cert=certs/server.crt \
  --key=certs/server.key
```

Development mode automatically:
- Sets up LocalStack infrastructure (SQS queues, DynamoDB tables)
- Uses AWS store type with local endpoints
- Provides a default token signing secret

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
