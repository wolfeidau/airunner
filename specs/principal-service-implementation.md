# Principal-Based Authentication with JWT

## Overview

This specification describes a principal-based authentication system for Airunner that replaces the current mTLS implementation. The new system is designed for SaaS deployment with the following goals:

**Key Design Principles:**
- **Private keys never leave the user's machine** - Users generate keypairs locally; only public keys are uploaded
- **Social auth for humans** - GitHub OAuth for easy onboarding, Google/others later
- **Self-signed JWTs for machines** - Workers and API clients sign their own tokens
- **Org-scoped permissions** - Multi-tenant model with role-based access control
- **Simple CLI handoff** - Copy/paste workflow from CLI to web UI
- **Protobuf + base58 encoding** - Credential blobs use protobuf for compact, safe binary format with base58 encoding for easy copy/paste (63% smaller than JSON)

**What's changing:**
- ❌ Remove mTLS certificate distribution complexity
- ❌ Remove CA management, certificate rotation, certificate stores
- ✅ Add GitHub OAuth for web users
- ✅ Add keypair-based JWT authentication for CLI/workers
- ✅ Add organization model for multi-tenancy
- ✅ Keep RBAC and principal concepts

**Key Benefits:**
- No certificate distribution nightmare for web clients
- Private keys stay on user's machine (or in KMS)
- Standard OAuth2/JWT patterns
- Easy onboarding: login with GitHub, paste one blob
- Machine users (workers, CI/CD) get keypairs like service accounts

---

## Security Model

### Core Principle: Private Keys Never Leave the User's Machine

**Traditional SaaS auth pattern (we're NOT doing this):**
```
User → Login to web → Server generates API key → User downloads secret
❌ Problem: Server sees the private key/secret
```

**Our pattern (inspired by SSH keys):**
```
User → Generates keypair locally → Uploads public key → Server never sees private key
✅ Benefit: Private key never transmitted or stored on server
```

### Authentication Flows

#### 1. Human User Flow (Web Login)

**Goal:** User signs up with GitHub, gets access to web UI and can create machine credentials.

```mermaid
sequenceDiagram
    participant Browser
    participant Server
    participant GitHub

    Browser->>Server: 1. Click "Login with GitHub"
    Server->>Browser: 2. Redirect to GitHub OAuth
    Browser->>GitHub: 3. GitHub OAuth flow
    GitHub->>Browser: (authorization)
    Browser->>Server: 4. Callback with code
    Server->>GitHub: 5. Exchange code for GitHub user info
    GitHub->>Server: (user info)
    Note over Server: 6. Create user principal<br/>and personal org<br/>(if first login)
    Server->>Browser: 7. Set session cookie
    Server->>Browser: 8. Redirect to dashboard
```

**What happens:**
1. User clicks "Login with GitHub" in web UI
2. Server redirects to GitHub OAuth authorization URL
3. User authorizes Airunner on GitHub
4. GitHub redirects back with authorization code
5. Server exchanges code for GitHub access token and user info
6. Server checks if user principal exists (by github_id):
   - **First login**: Create user principal + personal org (name = GitHub username)
   - **Returning user**: Look up existing principal
7. Server creates session (cookie or session token)
8. User lands on dashboard

**Database changes:**
```
INSERT INTO organizations (org_id, name, owner_principal_id, created_at)
VALUES (uuid(), 'wolfeidau', 'principal-abc123', now())

INSERT INTO principals (principal_id, org_id, type, name, github_id, roles, created_at)
VALUES ('principal-abc123', 'org-xyz', 'user', 'wolfeidau', '12345', ['admin'], now())
```

**Session management:**
- Web UI uses HTTP-only session cookies
- No JWT needed for web UI (traditional session-based auth)

---

#### 2. CLI Machine Credential Flow (Standard Keypair)

**Goal:** User generates a keypair on their machine, uploads public key to server, uses private key to sign JWTs for API access.

**The private key NEVER leaves the user's machine.**

```mermaid
sequenceDiagram
    participant CLI
    participant Browser
    participant Server

    Note over CLI: 1. Generate keypair locally<br/>(ECDSA P-256)<br/>Save private key to<br/>~/.airunner/credentials<br/>Display public key blob
    Note over CLI,Browser: [User copies blob]
    Browser->>Server: 2. Login to web UI (GitHub OAuth)
    Browser->>Server: 3. Navigate to "Import Credential"<br/>and paste blob
    Note over Server: 4. Parse blob, create<br/>machine principal<br/>with public key
    Server->>Browser: 5. Show success
    Note over CLI: 6. Run CLI command<br/>Load private key<br/>Create & sign JWT
    CLI->>Server: 6. Send request with JWT
    Note over Server: 7. Verify JWT signature<br/>with stored public key,<br/>authorize
    Server->>CLI: 8. Response
```

**Step-by-step:**

**Step 1: Generate keypair locally**
```bash
$ airunner-cli init --name "my-laptop"
Generating ECDSA P-256 keypair...
Saved credentials to: /Users/mark/.airunner/credentials

Copy this credential and import it in the web UI at https://airunner.dev/credentials/import

-----BEGIN AIRUNNER CREDENTIAL-----
3yZe7d4WFGpvr8uNQJzKxM2HnBqS9fXjC5RkT
-----END AIRUNNER CREDENTIAL-----

Or copy to clipboard: airunner-cli export | pbcopy
```

**What's in the blob?** (base58-encoded protobuf)

The blob contains a serialized protobuf message (defined in `api/auth/v1/credential.proto`):
```protobuf
message Credential {
  uint32 version = 1;           // 1
  CredentialType type = 2;      // WORKER
  string name = 3;              // "my-laptop"
  bytes public_key_der = 4;     // Raw DER bytes (91 bytes for P-256)
  bytes fingerprint = 5;        // SHA-256 hash (32 bytes)
  int64 created_at = 6;         // Unix timestamp
  string kms_key_id = 7;        // Optional, for KMS-backed credentials
}

enum CredentialType {
  CREDENTIAL_TYPE_UNSPECIFIED = 0;
  CREDENTIAL_TYPE_WORKER = 1;
  CREDENTIAL_TYPE_SERVICE = 2;
}
```

**Size:** ~150 bytes protobuf → ~200 bytes base58 (63% smaller than JSON)

**What's saved locally?** (`~/.airunner/credentials`)

The local credentials file uses JSON for readability (not transmitted):
```json
{
  "version": 1,
  "type": "worker",
  "name": "my-laptop",
  "privateKey": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "publicKeyDER": "MFkwEwYHKoZIzj0CAQY...",  // Base64 DER (for blob export)
  "fingerprint": "5K3JmN8xQz2PwRvT6YsLqC9Hf",
  "fingerprintBytes": "aGVsbG8gd29ybGQ...",  // Base64 raw hash (for blob export)
  "createdAt": "2025-12-28T10:00:00Z"
}
```

**Key points:**
- Private key is saved locally, never transmitted
- PEM format for human readability and compatibility
- DER bytes cached for efficient protobuf encoding
- Fingerprint stored in both base58 (display) and raw bytes (protobuf)

**Step 2-5: Import public key in web UI**

User pastes blob into web form. Server parses it:

```go
// Pseudo-code
blobBytes := base58.Decode(userInput)

// Unmarshal protobuf
cred := &authv1.Credential{}
err := proto.Unmarshal(blobBytes, cred)
if err != nil { return error }

// Validate
if cred.Version != 1 { return error }
if cred.Type != authv1.CREDENTIAL_TYPE_WORKER &&
   cred.Type != authv1.CREDENTIAL_TYPE_SERVICE { return error }

// Parse and validate public key DER
publicKey, err := x509.ParsePKIXPublicKey(cred.PublicKeyDer)
if err != nil { return error }
ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
if !ok || ecdsaKey.Curve != elliptic.P256() { return error }

// Verify fingerprint matches public key
computedFingerprint := sha256.Sum256(cred.PublicKeyDer)
if !bytes.Equal(computedFingerprint[:], cred.Fingerprint) {
  return error("fingerprint mismatch")
}

// Convert to PEM for storage (optional, could store DER)
publicKeyPEM := encodePEMPublicKey(ecdsaKey)
fingerprintBase58 := base58.Encode(cred.Fingerprint)

// Create machine principal
principalID := uuid.New()
orgID := currentUser.OrgID

db.Insert(Principal{
  PrincipalID: principalID,
  OrgID: orgID,
  Type: credTypeToString(cred.Type),
  Name: cred.Name,
  PublicKey: publicKeyPEM,          // Store as PEM for compatibility
  PublicKeyDER: cred.PublicKeyDer,  // Also store DER for JWT verification
  Fingerprint: fingerprintBase58,   // Store base58 for display/lookup
  Roles: defaultRoles(cred.Type),
  CreatedAt: time.Now(),
})
```

**Default roles by type:**
- `type=worker` → `roles=["worker"]` (can dequeue jobs, publish events)
- `type=service` → `roles=["readonly"]` (can list jobs, read events)
- User can bump permissions in UI: `readonly` → `user` → `admin`

**Step 6-8: CLI authenticates with JWT**

```bash
$ airunner-cli worker --server https://api.airunner.dev
Loading credentials from /Users/mark/.airunner/credentials
Starting worker...
```

**What the CLI does:**
1. Load private key from `~/.airunner/credentials`
2. Create JWT with claims:
   ```json
   {
     "iss": "airunner-cli",
     "sub": "5K3JmN8xQz2PwRvT6YsLqC9Hf",  // fingerprint
     "iat": 1735380000,
     "exp": 1735383600,  // 1 hour later
     "org": ""  // Not known yet, server will fill in
   }
   ```
3. Sign JWT with private key (ECDSA ES256)
4. Add fingerprint to JWT header as `kid`:
   ```json
   {
     "alg": "ES256",
     "typ": "JWT",
     "kid": "5K3JmN8xQz2PwRvT6YsLqC9Hf"
   }
   ```
5. Send request with `Authorization: Bearer <JWT>`

**What the server does:**
1. Extract JWT from `Authorization` header
2. Extract `kid` from JWT header → this is the fingerprint
3. Look up principal by fingerprint:
   ```sql
   SELECT * FROM principals WHERE fingerprint = '5K3JmN8xQz2PwRvT6YsLqC9Hf'
   ```
4. Get public key from principal record
5. Verify JWT signature with public key
6. Check principal roles and org_id
7. Authorize request based on roles
8. Process request

**Security properties:**
- ✅ Private key never leaves user's machine
- ✅ Server only sees public key and JWT signatures
- ✅ JWT is signed by user's private key (proves possession)
- ✅ Server verifies with stored public key
- ✅ Fingerprint uniquely identifies the credential

---

#### 3. CLI Machine Credential Flow (KMS-Backed)

**Goal:** For production workers (CI/CD, long-running agents), use AWS KMS to hold the private key. The private key NEVER leaves AWS KMS.

```mermaid
sequenceDiagram
    participant CLI
    participant KMS
    participant Server

    CLI->>KMS: 1. Create KMS key or use existing
    CLI->>KMS: 2. Get public key from KMS
    KMS->>CLI: (public key)
    Note over CLI: 3. Display blob with<br/>KMS key ARN and<br/>public key
    Note over CLI: [User copies blob to web UI,<br/>same as standard flow]
    Note over CLI: 4. When running...
    CLI->>KMS: Sign JWT using KMS
    KMS->>CLI: (signature)
    CLI->>Server: 5. Send JWT to server
    Note over Server: 6. Verify signature<br/>(same as standard)
    Server->>CLI: (response)
```

**Step 1-3: Generate KMS-backed credential**

```bash
$ airunner-cli init --kms arn:aws:kms:us-east-1:123456789012:key/abc-123
Using AWS KMS key: arn:aws:kms:us-east-1:123456789012:key/abc-123
Fetching public key from KMS...

Copy this credential and import it in the web UI:

-----BEGIN AIRUNNER CREDENTIAL-----
2nD8fK5vPwMxQzR7HgTjYcLsB9VmN
-----END AIRUNNER CREDENTIAL-----
```

**Blob includes KMS key ARN** (protobuf message):
```protobuf
message Credential {
  version: 1
  type: CREDENTIAL_TYPE_WORKER
  name: "ci-worker"
  public_key_der: <91 bytes>
  fingerprint: <32 bytes>
  created_at: 1735380000
  kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/abc-123"
}
```

**Credentials saved locally** (`~/.airunner/credentials`):
```json
{
  "version": 1,
  "type": "worker",
  "name": "ci-worker",
  "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "publicKeyDER": "MFkwEwYHKoZIzj0CAQY...",
  "fingerprint": "7TgPqW5xRmK9CvNz3YsHfL2",
  "fingerprintBytes": "aGVsbG8gd29ybGQ...",
  "createdAt": "2025-12-28T10:00:00Z"
}
```

**Note:** No `privateKey` field! The private key is in KMS.

**Step 4-6: Sign JWT with KMS**

When CLI runs, it detects KMS-backed credential and uses KMS to sign:

```go
// Pseudo-code
if cred.KMSKeyID != "" {
  // Sign using KMS
  message := createJWTSigningInput(claims)
  signature := kms.Sign(kmsKeyID, message, SigningAlgorithm_ECDSA_SHA_256)
  jwt := createJWT(header, claims, signature)
} else {
  // Sign using local private key
  signature := ecdsa.Sign(privateKey, message)
  jwt := createJWT(header, claims, signature)
}
```

**Security properties:**
- ✅ Private key NEVER leaves AWS KMS (FIPS 140-2 Level 2 HSM)
- ✅ CLI only calls KMS Sign API
- ✅ Public key is uploaded to server for verification
- ✅ Perfect for production workers (CI/CD, ECS tasks)

---

## Data Models

### Organizations

**Purpose:** Multi-tenant isolation. Each user gets a personal org; future support for team orgs.

```
organizations
├── org_id (PK, UUID)
├── name (string) - Display name (e.g., "wolfeidau")
├── owner_principal_id (FK → principals.principal_id)
├── created_at (timestamp)
└── updated_at (timestamp)
```

**DynamoDB schema:**
```
Table: airunner_{env}_organizations
PartitionKey: org_id
Attributes:
  - org_id: string (UUID)
  - name: string
  - owner_principal_id: string (UUID)
  - created_at: string (ISO8601)
  - updated_at: string (ISO8601)
```

**Usage:**
- User signs up → create org with `name = github_username`
- Org is created before user principal (chicken-egg: use a placeholder owner initially, update after principal created)

**Future:**
- User can create additional orgs (for teams)
- Invite other users to orgs
- Org-level billing, quotas, settings

---

### Principals

**Purpose:** Represent all actors in the system (human users, workers, services).

```
principals
├── principal_id (PK, UUID)
├── org_id (FK → organizations.org_id)
├── type (enum: user | worker | service)
├── name (string) - Display name
├── github_id (string, nullable) - For type=user
├── public_key (string, nullable) - PEM-encoded, for type=worker|service (compatibility)
├── public_key_der (bytes, nullable) - DER-encoded public key, for type=worker|service (efficient verification)
├── fingerprint (string, nullable) - Base58-encoded SHA-256 hash of public_key_der, for lookups
├── kms_key_id (string, nullable) - AWS KMS key ARN, for KMS-backed credentials
├── roles (string[]) - Role names: admin, worker, user, readonly
├── created_at (timestamp)
├── updated_at (timestamp)
└── last_used_at (timestamp, nullable) - Last authentication time
```

**DynamoDB schema:**
```
Table: airunner_{env}_principals
PartitionKey: principal_id
GSI1: fingerprint (for JWT auth lookups)
GSI2: org_id + type (for listing principals by org)
GSI3: github_id (for OAuth lookups)

Attributes:
  - principal_id: string (UUID)
  - org_id: string (UUID)
  - type: string (user | worker | service)
  - name: string
  - github_id: string (optional)
  - public_key: string (PEM, optional, for compatibility)
  - public_key_der: binary (optional, DER bytes for JWT verification)
  - fingerprint: string (optional, base58-encoded)
  - kms_key_id: string (optional)
  - roles: string[] (DynamoDB list)
  - created_at: string (ISO8601)
  - updated_at: string (ISO8601)
  - last_used_at: string (ISO8601, optional)
```

**GSI Details:**

**GSI1 - Fingerprint Lookup (for JWT auth):**
```
PartitionKey: fingerprint
ProjectionType: ALL
```
Used when CLI sends JWT with `kid=fingerprint` header. Server looks up principal by fingerprint to get public key for verification.

**GSI2 - Org Listing:**
```
PartitionKey: org_id
SortKey: type
ProjectionType: ALL
```
Used to list all principals in an org, filtered by type (e.g., "show all workers in my org").

**GSI3 - GitHub Lookup (for OAuth):**
```
PartitionKey: github_id
ProjectionType: ALL
```
Used during GitHub OAuth callback to find existing user by GitHub ID.

**Principal Types:**

| Type    | Description                  | Has public_key? | Has github_id? | Example Roles        |
|---------|------------------------------|-----------------|----------------|----------------------|
| user    | Human user (GitHub OAuth)    | No              | Yes            | admin, user          |
| worker  | Job execution worker         | Yes             | No             | worker               |
| service | API client, automation       | Yes             | No             | readonly, user       |

**Role Hierarchy:**
- `admin` - Full access to org (create/delete principals, manage org, all job operations)
- `worker` - Dequeue jobs, publish events, complete jobs
- `user` - Submit jobs, list jobs, monitor events
- `readonly` - List jobs, read events (no mutations)

**Roles are org-scoped:** A principal's roles apply only within their org. Future: Multi-org membership with different roles per org.

---

## JWT Structure

### JWT Header
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "5K3JmN8xQz2PwRvT6YsLqC9Hf"
}
```

- `alg`: Always `ES256` (ECDSA P-256)
- `kid`: Fingerprint of public key (for principal lookup) - base58 encoded

### JWT Claims
```json
{
  "iss": "airunner-cli",
  "sub": "5K3JmN8xQz2PwRvT6YsLqC9Hf",
  "org": "org-xyz-789",
  "iat": 1735380000,
  "exp": 1735383600,
  "jti": "unique-request-id"
}
```

- `iss`: Always `"airunner-cli"` or `"airunner-worker"`
- `sub`: Fingerprint of public key (same as `kid`) - base58 encoded
- `org`: Organization ID (filled in by server after first lookup, optional in CLI)
- `iat`: Issued at (Unix timestamp)
- `exp`: Expiration (Unix timestamp, default 1 hour)
- `jti`: Unique JWT ID (for replay protection, optional)

### JWT Signature
```
ECDSA-SHA256(header + claims, privateKey)
```

Signed by the CLI using the user's private key (or KMS).

---

## API Authentication Flow

**Request:**
```
GET /api/v1/jobs HTTP/1.1
Host: api.airunner.dev
Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVLM0ptTjh4UXoyUHdSdlQ2WXNMcUM5SGYifQ.eyJpc3MiOiJhaXJ1bm5lci1jbGkiLCJzdWIiOiI1SzNKbU44eFF6MlB3UnZUNllzTHFDOUhmIiwib3JnIjoib3JnLXh5eiIsImlhdCI6MTczNTM4MDAwMCwiZXhwIjoxNzM1MzgzNjAwfQ.MEUCIQDx...
```

**Server middleware flow:**
```go
func JWTAuthMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // 1. Extract JWT from Authorization header
    authHeader := r.Header.Get("Authorization")
    if !strings.HasPrefix(authHeader, "Bearer ") {
      return unauthorized(w)
    }
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")

    // 2. Parse JWT (but don't verify yet)
    token := jwt.Parse(tokenString, jwt.WithoutValidation())

    // 3. Extract kid from header
    kid := token.Header["kid"]
    if kid == "" {
      return unauthorized(w, "missing kid in JWT header")
    }

    // 4. Look up principal by fingerprint (kid)
    principal, err := principalStore.GetByFingerprint(ctx, kid)
    if err != nil {
      return unauthorized(w, "invalid credential")
    }

    // 5. Parse public key from principal
    publicKey, err := parsePEMPublicKey(principal.PublicKey)
    if err != nil {
      return internalError(w)
    }

    // 6. Verify JWT signature
    claims, err := jwt.Verify(tokenString, publicKey)
    if err != nil {
      return unauthorized(w, "invalid signature")
    }

    // 7. Verify expiration
    if claims.Exp < time.Now().Unix() {
      return unauthorized(w, "token expired")
    }

    // 8. Update last_used_at (async)
    go principalStore.UpdateLastUsed(ctx, principal.PrincipalID)

    // 9. Add principal to request context
    ctx := context.WithValue(r.Context(), "principal", principal)

    // 10. Continue to authorization middleware
    next.ServeHTTP(w, r.WithContext(ctx))
  })
}
```

**Authorization middleware:**
```go
func RequireRole(roles ...string) func(http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      principal := r.Context().Value("principal").(Principal)

      // Check if principal has any of the required roles
      if !hasAnyRole(principal.Roles, roles) {
        return forbidden(w, "insufficient permissions")
      }

      next.ServeHTTP(w, r)
    })
  }
}

// Usage:
router.Handle("/api/v1/jobs",
  JWTAuthMiddleware(
    RequireRole("worker", "admin")(
      http.HandlerFunc(handleEnqueueJob)
    )
  )
)
```

---

## CLI Commands

### `init` - Generate Keypair

**Purpose:** Generate a new ECDSA P-256 keypair for authentication.

**Usage:**
```bash
airunner-cli init [--name NAME] [--type TYPE] [--kms KMS_KEY_ARN]
```

**Flags:**
- `--name` - Friendly name for the credential (default: hostname)
- `--type` - Credential type: `worker` or `service` (default: `worker`)
- `--kms` - AWS KMS key ARN for KMS-backed credential (optional)

**Standard flow:**
```bash
$ airunner-cli init --name "my-laptop" --type worker
Generating ECDSA P-256 keypair...
Saved credentials to: /Users/mark/.airunner/credentials

Copy this credential and import it in the web UI at https://airunner.dev/credentials/import

-----BEGIN AIRUNNER CREDENTIAL-----
4QSYu8VxZmhDKwFP3fLCKSeHv9vMCgN7D8KQPxRzTmGnB5sVk2Y6wHpN9cEjRtF3uX8zLmQaK2dJhWrPb4VfSgY7NnEpMxCvU6ZsBqT5LwDj
-----END AIRUNNER CREDENTIAL-----

Or copy to clipboard: airunner-cli export | pbcopy
```

**KMS flow:**
```bash
$ airunner-cli init --name "ci-worker" --type worker --kms arn:aws:kms:us-east-1:123:key/abc
Using AWS KMS key: arn:aws:kms:us-east-1:123:key/abc
Fetching public key from KMS...

Copy this credential and import it in the web UI at https://airunner.dev/credentials/import

-----BEGIN AIRUNNER CREDENTIAL-----
7RpMx9NqK4WvBz5FsLcY3TgHm8PnQjE2VdXuCbA6ZwK5JyNrU8DhVf4GpStMwL9Bx
-----END AIRUNNER CREDENTIAL-----
```

**What it does:**
1. Generate ECDSA P-256 keypair (or fetch public key from KMS)
2. Encode public key to DER format
3. Compute fingerprint: sha256(publicKeyDER) → 32 bytes
4. Create protobuf Credential message
5. Serialize to binary (proto.Marshal)
6. Base58-encode the binary protobuf
7. Save credentials to `~/.airunner/credentials` (JSON format for local use)
8. Display base58-encoded blob to terminal

**Credentials file format** (`~/.airunner/credentials`):
```json
{
  "version": 1,
  "type": "worker",
  "name": "my-laptop",
  "privateKey": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "publicKeyDER": "MFkwEwYHKoZIzj0CAQY...",
  "fingerprint": "5K3JmN8xQz2PwRvT6YsLqC9Hf",
  "fingerprintBytes": "aGVsbG8gd29ybGQ...",
  "createdAt": "2025-12-28T10:00:00Z"
}
```

For KMS-backed credentials, `privateKey` is omitted and `kmsKeyId` is included.

**Note:** Local file uses JSON for human readability. Exported blobs use protobuf for efficiency.

---

### `export` - Export Public Credential Blob

**Purpose:** Output the public credential blob to stdout (for piping to clipboard).

**Usage:**
```bash
airunner-cli export [--credentials PATH]
```

**Flags:**
- `--credentials` - Path to credentials file (default: `~/.airunner/credentials`)

**Example:**
```bash
$ airunner-cli export | pbcopy
# Blob copied to clipboard, ready to paste in web UI
```

**What it does:**
1. Load credentials from JSON file
2. Create protobuf Credential message:
   - version, type, name, created_at
   - public_key_der (decode from base64)
   - fingerprint (decode from base64 bytes)
   - kms_key_id (if present)
3. Serialize to binary (proto.Marshal)
4. Base58 encode the binary protobuf
5. Wrap in `-----BEGIN AIRUNNER CREDENTIAL-----` header/footer
6. Write to stdout

**Output format:**
```
-----BEGIN AIRUNNER CREDENTIAL-----
3yZe7d4WFGpvr8uNQJzKxM2HnBqS9fXjC5RkT
-----END AIRUNNER CREDENTIAL-----
```

**Size:** ~200 bytes (63% smaller than JSON equivalent)

---

### `worker` - Run Job Worker

**Purpose:** Run a long-running worker that dequeues and executes jobs.

**Usage:**
```bash
airunner-cli worker [--server URL] [--queue NAME] [--credentials PATH]
```

**Flags:**
- `--server` - Server URL (default: `https://api.airunner.dev`)
- `--queue` - Queue name (default: `default`)
- `--credentials` - Path to credentials file (default: `~/.airunner/credentials`)

**Example:**
```bash
$ airunner-cli worker --server https://api.airunner.dev --queue default
Loading credentials from /Users/mark/.airunner/credentials
Authenticating...
Connected to Airunner (org: wolfeidau, principal: my-laptop)
Polling queue 'default' for jobs...
```

**What it does:**
1. Load credentials from file
2. Create JWT signer (local private key or KMS)
3. For each request:
   - Create JWT with claims
   - Sign JWT
   - Add `Authorization: Bearer <JWT>` header
   - Send request
4. Poll for jobs, execute, publish events (existing worker logic)

**Authentication happens per-request:**
- Each API call generates a new JWT (short-lived, 1 hour expiration)
- JWT is signed with private key (or KMS)
- Server verifies signature with stored public key

---

### `submit` - Submit Job

**Purpose:** Submit a single job to the queue.

**Usage:**
```bash
airunner-cli submit [--server URL] [--queue NAME] [--credentials PATH] <repository-url>
```

**Example:**
```bash
$ airunner-cli submit --server https://api.airunner.dev github.com/example/repo
Authenticating...
Submitting job...
Job submitted: job-abc123
```

**Authentication:** Same as `worker` - load credentials, sign JWT, send with request.

---

## Web UI Flows

### User Signup/Login Flow

**UI Pages:**
1. **Landing Page** (`/`)
   - "Login with GitHub" button
   - Redirects to `/auth/github`

2. **GitHub OAuth Callback** (`/auth/github/callback`)
   - Exchange code for GitHub user info
   - Create or lookup user principal + personal org
   - Set session cookie
   - Redirect to dashboard

3. **Dashboard** (`/dashboard`)
   - Shows user's org, jobs, workers
   - Navigation to credentials, settings, etc.

**Server endpoints:**
```
GET  /auth/github           → Redirect to GitHub OAuth
GET  /auth/github/callback  → Handle OAuth callback, create session
GET  /auth/logout           → Clear session
GET  /api/v1/me             → Get current user principal info (requires session)
```

---

### Import Credential Flow

**UI Pages:**
1. **Credentials List** (`/credentials`)
   - Shows all machine principals in user's org
   - "Import Credential" button

2. **Import Form** (`/credentials/import`)
   - Textarea for pasting blob
   - "Import" button
   - Shows preview after pasting (name, type, fingerprint)

3. **Credential Details** (`/credentials/:principal_id`)
   - Shows name, type, roles, fingerprint, created_at, last_used_at
   - "Edit Roles" button
   - "Revoke" button (deletes principal)

**Server endpoints:**
```
POST   /api/v1/credentials/import  → Parse blob, create machine principal
GET    /api/v1/credentials         → List all principals in user's org
GET    /api/v1/credentials/:id     → Get principal details
PATCH  /api/v1/credentials/:id     → Update principal (name, roles)
DELETE /api/v1/credentials/:id     → Delete principal (revoke)
```

**Import endpoint logic:**
```go
func handleImportCredential(w http.ResponseWriter, r *http.Request) {
  // 1. Get current user from session
  user := getUserFromSession(r)

  // 2. Parse request body
  var req struct {
    Blob string `json:"blob"`
  }
  json.NewDecoder(r.Body).Decode(&req)

  // 3. Decode blob
  blob := strings.TrimPrefix(req.Blob, "-----BEGIN AIRUNNER CREDENTIAL-----")
  blob = strings.TrimSuffix(blob, "-----END AIRUNNER CREDENTIAL-----")
  blob = strings.TrimSpace(blob)
  blobBytes, err := base58.Decode(blob)
  if err != nil { return badRequest(w, "invalid base58 encoding") }

  // 4. Parse protobuf credential
  cred := &authv1.Credential{}
  err = proto.Unmarshal(blobBytes, cred)
  if err != nil { return badRequest(w, "invalid protobuf message") }

  // 5. Validate
  if cred.Version != 1 { return badRequest(w, "unsupported version") }
  if cred.Type != authv1.CREDENTIAL_TYPE_WORKER &&
     cred.Type != authv1.CREDENTIAL_TYPE_SERVICE {
    return badRequest(w, "invalid type")
  }

  // 6. Parse and validate public key DER
  publicKey, err := x509.ParsePKIXPublicKey(cred.PublicKeyDer)
  if err != nil { return badRequest(w, "invalid public key DER") }
  ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
  if !ok || ecdsaKey.Curve != elliptic.P256() {
    return badRequest(w, "public key must be ECDSA P-256")
  }

  // 7. Verify fingerprint matches public key
  computedFingerprint := sha256.Sum256(cred.PublicKeyDer)
  if !bytes.Equal(computedFingerprint[:], cred.Fingerprint) {
    return badRequest(w, "fingerprint mismatch")
  }

  // 8. Convert fingerprint to base58 for storage/lookup
  fingerprintBase58 := base58.Encode(cred.Fingerprint)

  // 9. Check for duplicate fingerprint
  existing, _ := principalStore.GetByFingerprint(ctx, fingerprintBase58)
  if existing != nil { return conflict(w, "credential already imported") }

  // 10. Convert public key to PEM for storage (optional)
  publicKeyPEM := encodePEMPublicKey(ecdsaKey)

  // 11. Create principal
  principal := &Principal{
    PrincipalID:  uuid.New().String(),
    OrgID:        user.OrgID,
    Type:         credTypeToString(cred.Type),
    Name:         cred.Name,
    PublicKey:    publicKeyPEM,
    PublicKeyDER: cred.PublicKeyDer,
    Fingerprint:  fingerprintBase58,
    KMSKeyID:     cred.KmsKeyId,
    Roles:        defaultRoles(cred.Type),
    CreatedAt:    time.Now(),
  }

  err = principalStore.Create(ctx, principal)
  if err != nil { return internalError(w) }

  // 9. Return principal
  json.NewEncoder(w).Encode(principal)
}

func defaultRoles(credType string) []string {
  switch credType {
  case "worker":
    return []string{"worker"}
  case "service":
    return []string{"readonly"}
  default:
    return []string{}
  }
}
```

---

## Implementation Phases

### Phase 1: Remove mTLS Authentication

**Goal:** Clean slate - remove all mTLS code and infrastructure.

**Tasks:**
- [ ] Remove mTLS code:
  - `internal/pki/` (oid.go, signer.go)
  - `internal/auth/mtls.go`
  - `internal/auth/authz.go` (we'll rewrite this)
  - `internal/store/principal_store.go` (old version)
  - `internal/store/certificate_store.go`
  - `internal/store/memory_principal_store.go`
  - `internal/store/memory_cert_store.go`
  - `api/job/v1/principal.proto` (PrincipalService)
  - `cmd/cli/internal/commands/bootstrap.go` (old bootstrap)
- [ ] Remove mTLS Terraform:
  - `infra/dynamodb.tf` - Remove principals and certificates tables
  - `infra/ssm.tf` - Remove CA cert, server cert parameters
  - `infra/kms.tf` - Remove CA signing key
  - `infra/nlb.tf` - Remove TCP listener on port 443
  - `infra/ecs.tf` - Remove mTLS environment variables
- [ ] Remove mTLS specs:
  - `specs/mtls/` (entire directory → move to `specs/ARCHIVE_mtls/`)
- [ ] Update server:
  - Remove mTLS listener configuration
  - Remove certificate loading logic
  - Add `--no-auth` flag as default (for now)
- [ ] Update CLI:
  - Remove certificate flags (`--cacert`, `--client-cert`, `--client-key`)
  - Remove certificate loading logic
- [ ] Verify:
  - [ ] `make build` succeeds
  - [ ] `make test` passes
  - [ ] Server starts without errors
  - [ ] CLI can connect to server (no auth)

**Estimated time:** 1 hour

---

### Phase 2: Implement Data Models and Stores

**Goal:** Create organizations and principals tables in DynamoDB, implement store interfaces, define protobuf schema.

**Tasks:**
- [ ] Define protobuf schema:
  - `api/auth/v1/credential.proto` - Credential message and CredentialType enum
  - Run `make proto-generate` to generate Go code
- [ ] Define data models:
  - `internal/models/organization.go` - Organization struct
  - `internal/models/principal.go` - Principal struct (with public_key_der field)
- [ ] Create store interfaces:
  - `internal/store/organization_store.go` - OrganizationStore interface
  - `internal/store/principal_store.go` - PrincipalStore interface (new version)
- [ ] Implement DynamoDB stores:
  - `internal/store/dynamodb_organization_store.go`
  - `internal/store/dynamodb_principal_store.go`
- [ ] Implement in-memory stores (for testing):
  - `internal/store/memory_organization_store.go`
  - `internal/store/memory_principal_store.go`
- [ ] Create Terraform for DynamoDB tables:
  - `infra/dynamodb.tf` - organizations and principals tables with GSIs
- [ ] Write tests:
  - Store interface tests (common test suite for both memory and DynamoDB)
  - GSI query tests
  - Protobuf serialization/deserialization tests

**Organization Store Interface:**
```go
type OrganizationStore interface {
  Create(ctx context.Context, org *Organization) error
  Get(ctx context.Context, orgID string) (*Organization, error)
  Update(ctx context.Context, org *Organization) error
  Delete(ctx context.Context, orgID string) error
  ListByOwner(ctx context.Context, ownerPrincipalID string) ([]*Organization, error)
}
```

**Principal Store Interface:**
```go
type PrincipalStore interface {
  Create(ctx context.Context, principal *Principal) error
  Get(ctx context.Context, principalID string) (*Principal, error)
  GetByFingerprint(ctx context.Context, fingerprint string) (*Principal, error)
  GetByGitHubID(ctx context.Context, githubID string) (*Principal, error)
  Update(ctx context.Context, principal *Principal) error
  Delete(ctx context.Context, principalID string) error
  ListByOrg(ctx context.Context, orgID string, principalType *string) ([]*Principal, error)
  UpdateLastUsed(ctx context.Context, principalID string) error
}
```

**Verification:**
- [ ] `make test` passes
- [ ] Can create organizations and principals in DynamoDB (integration test)
- [ ] GSI queries work (fingerprint, github_id, org_id lookups)

**Estimated time:** 2-3 hours

---

### Phase 3: Implement JWT Authentication

**Goal:** Create JWT middleware, signing/verification logic, fingerprint computation.

**Tasks:**
- [ ] Create JWT utilities:
  - `internal/auth/jwt.go` - JWT signing, verification, claims parsing
  - `internal/auth/fingerprint.go` - Public key fingerprint computation
- [ ] Create authentication middleware:
  - `internal/auth/middleware.go` - JWTAuthMiddleware
- [ ] Create authorization helpers:
  - `internal/auth/authz.go` - RequireRole middleware, role checking
- [ ] Update server to use JWT middleware:
  - `internal/server/server.go` - Wire up JWT middleware for protected routes
  - Keep `--no-auth` flag for development
- [ ] Write tests:
  - JWT signing and verification
  - Fingerprint computation
  - Middleware authentication flow
  - Authorization with different roles

**JWT Functions:**
```go
// Sign a JWT with a private key
func SignJWT(claims jwt.Claims, privateKey *ecdsa.PrivateKey, fingerprint string) (string, error)

// Sign a JWT using AWS KMS
func SignJWTWithKMS(claims jwt.Claims, kmsKeyID string, fingerprint string) (string, error)

// Verify a JWT signature with a public key
func VerifyJWT(tokenString string, publicKey *ecdsa.PublicKey) (*jwt.Claims, error)

// Compute fingerprint from public key
func ComputeFingerprint(publicKey *ecdsa.PublicKey) string

// Parse PEM-encoded public key
func ParsePublicKey(pemString string) (*ecdsa.PublicKey, error)
```

**Middleware:**
```go
func JWTAuthMiddleware(principalStore store.PrincipalStore) func(http.Handler) http.Handler

func RequireRole(roles ...string) func(http.Handler) http.Handler

func RequireOrgMembership(orgID string) func(http.Handler) http.Handler
```

**Verification:**
- [ ] `make test` passes
- [ ] Can authenticate with valid JWT
- [ ] Authentication fails with invalid/expired JWT
- [ ] Authorization works with different roles

**Estimated time:** 2-3 hours

---

### Phase 4: Implement CLI Commands

**Goal:** Create `init` and `export` commands, update `worker` and `submit` to use JWT auth.

**Tasks:**
- [ ] Add base58 encoding library:
  - Use `github.com/btcsuite/btcutil/base58` (Bitcoin's base58 implementation)
- [ ] Create credential management:
  - `internal/cli/credentials/credentials.go` - Load/save credentials file (JSON format)
  - `internal/cli/credentials/keypair.go` - Generate ECDSA keypair
  - `internal/cli/credentials/kms.go` - KMS keypair operations
  - `internal/cli/credentials/blob.go` - Encode/decode credential blobs (protobuf + base58)
- [ ] Create `init` command:
  - `cmd/cli/internal/commands/init.go`
  - Flags: `--name`, `--type`, `--kms`
  - Generate keypair (or use KMS)
  - Compute DER and fingerprint
  - Save to `~/.airunner/credentials` (JSON)
  - Create protobuf Credential message
  - Serialize to binary (proto.Marshal)
  - Base58 encode
  - Display blob
- [ ] Create `export` command:
  - `cmd/cli/internal/commands/export.go`
  - Load credentials from JSON file
  - Create protobuf message from stored fields
  - Serialize and base58 encode
  - Output blob to stdout
- [ ] Update `worker` command:
  - Load credentials from file
  - Sign JWT for each request
  - Add Authorization header
- [ ] Update `submit` command:
  - Same authentication as worker
- [ ] Write tests:
  - Keypair generation
  - Protobuf blob encoding/decoding
  - Base58 encoding/decoding
  - Credential file save/load
  - JWT signing in CLI
  - Fingerprint computation

**Credentials File Format:**
```go
type Credentials struct {
  Version          int       `json:"version"`
  Type             string    `json:"type"`             // "worker" or "service"
  Name             string    `json:"name"`
  PrivateKey       string    `json:"privateKey,omitempty"`    // PEM (omitted for KMS)
  PublicKey        string    `json:"publicKey"`               // PEM
  PublicKeyDER     string    `json:"publicKeyDER"`            // Base64-encoded DER bytes
  Fingerprint      string    `json:"fingerprint"`             // Base58-encoded (for display)
  FingerprintBytes string    `json:"fingerprintBytes"`        // Base64-encoded raw SHA-256
  KMSKeyID         string    `json:"kmsKeyId,omitempty"`      // AWS KMS key ARN
  CreatedAt        time.Time `json:"createdAt"`
}
```

**Note:** Local file uses JSON with base64 for binary data. Exported blobs use protobuf with raw bytes.

**Verification:**
- [ ] `airunner-cli init` generates keypair and displays blob
- [ ] `airunner-cli export` outputs blob
- [ ] Blob can be decoded successfully
- [ ] `airunner-cli worker` authenticates with JWT
- [ ] `--kms` flag works with AWS KMS

**Estimated time:** 3-4 hours

---

### Phase 5: Implement Web UI (Server-Side)

**Goal:** GitHub OAuth, session management, credential import API.

**Tasks:**
- [ ] Create GitHub OAuth:
  - `internal/auth/github.go` - GitHub OAuth client
  - `internal/server/auth_handlers.go` - `/auth/github`, `/auth/github/callback`, `/auth/logout`
- [ ] Create session management:
  - `internal/auth/session.go` - Session creation, validation, storage
  - Use gorilla/sessions or similar
- [ ] Create credential import API:
  - `internal/server/credential_handlers.go` - POST `/api/v1/credentials/import`, GET/PATCH/DELETE
- [ ] Create "current user" API:
  - `GET /api/v1/me` - Returns current user principal info
- [ ] Update server:
  - Wire up OAuth routes
  - Wire up credential management routes
  - Add session middleware for web UI routes
  - Add JWT middleware for API routes
- [ ] Write tests:
  - OAuth callback flow (mock GitHub)
  - Credential import endpoint
  - Session creation and validation

**OAuth Flow:**
```go
// GET /auth/github
func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
  // Redirect to GitHub OAuth authorization URL
}

// GET /auth/github/callback
func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
  // Exchange code for access token
  // Get GitHub user info
  // Look up or create user principal + org
  // Create session
  // Redirect to dashboard
}
```

**Import Flow:**
```go
// POST /api/v1/credentials/import
func handleImportCredential(w http.ResponseWriter, r *http.Request) {
  // Get current user from session
  // Parse blob
  // Validate
  // Create machine principal
  // Return principal
}
```

**Verification:**
- [ ] Can login with GitHub OAuth (integration test with mock)
- [ ] Session is created and validated
- [ ] Can import credential blob
- [ ] Can list, update, delete credentials
- [ ] Authorization works (can't import to other user's org)

**Estimated time:** 3-4 hours

---

### Phase 6: Integration Testing

**Goal:** End-to-end testing of all flows.

**Tasks:**
- [ ] Set up test environment:
  - LocalStack for DynamoDB
  - Mock GitHub OAuth server
- [ ] Test user signup flow:
  - Mock GitHub OAuth callback
  - Verify user principal and org created
  - Verify session created
- [ ] Test CLI credential flow:
  - Run `airunner-cli init`
  - Import credential via API
  - Run `airunner-cli worker`
  - Verify JWT authentication works
- [ ] Test KMS credential flow:
  - Use LocalStack KMS or real AWS KMS
  - Run `airunner-cli init --kms`
  - Import credential
  - Verify KMS signing works
- [ ] Test authorization:
  - Create principals with different roles
  - Verify role-based access control
  - Verify org isolation (can't access other org's resources)
- [ ] Performance testing:
  - JWT signing/verification performance
  - DynamoDB query performance (GSIs)

**Verification:**
- [ ] All integration tests pass
- [ ] Can run full flow: signup → init → import → worker → submit → monitor
- [ ] No auth bypass vulnerabilities
- [ ] Org isolation works

**Estimated time:** 2-3 hours

---

### Phase 7: Documentation and Deployment

**Goal:** Update docs, deploy to production, clean up.

**Tasks:**
- [ ] Update documentation:
  - `AGENT.md` - Remove mTLS references, add JWT auth section
  - `README.md` - Update authentication section
  - Add `docs/authentication.md` - Detailed auth guide for users
- [ ] Create migration guide:
  - `docs/mtls-to-jwt-migration.md` - For anyone who deployed mTLS
- [ ] Update Terraform:
  - Apply infrastructure changes (new DynamoDB tables)
  - Remove old mTLS resources
- [ ] Deploy to production:
  - Build new binaries
  - Update ECS task definitions
  - Deploy server
  - Verify health checks
- [ ] Clean up:
  - Archive mTLS specs (`specs/ARCHIVE_mtls/`)
  - Remove unused code
  - Run `make lint`, fix issues
  - Run `make test`, ensure 100% pass

**Verification:**
- [ ] Documentation is up to date
- [ ] Production deployment successful
- [ ] Can sign up and use the system
- [ ] No mTLS references remain in active code

**Estimated time:** 2-3 hours

---

## Security Considerations

### Private Key Security

**✅ Correct: Private key never leaves user's machine**
- CLI generates keypair locally
- Only public key is uploaded to server
- Server never sees or stores private key
- For KMS: Private key never leaves AWS HSM

**❌ Incorrect patterns we're avoiding:**
- Server generating keys and sending private key to user
- User uploading private key to server
- Storing private keys in server database

### JWT Security

**Token expiration:**
- Short-lived tokens (1 hour default)
- CLI generates new token for each request (or caches for a few minutes)
- No refresh tokens initially (can add later)

**Replay protection:**
- Optional `jti` (JWT ID) claim for single-use tokens
- Server can track used `jti` values in Redis/DynamoDB (future enhancement)

**Key rotation:**
- User can generate new keypair anytime
- Import new credential, delete old one
- No server-side key rotation needed (each principal has their own key)

### Org Isolation

**Enforcement:**
- All API endpoints check principal's org_id
- Can't access resources from other orgs
- GSI queries include org_id partition key

**Example:**
```go
func handleListJobs(w http.ResponseWriter, r *http.Request) {
  principal := r.Context().Value("principal").(*Principal)

  // Only return jobs from principal's org
  jobs, err := jobStore.ListByOrg(ctx, principal.OrgID)

  // ...
}
```

### GitHub OAuth Security

**State parameter:**
- Use CSRF token in OAuth state parameter
- Verify state on callback

**Token storage:**
- Don't store GitHub access token long-term (not needed after initial user creation)
- Only store github_id for future logins

**Scope:**
- Request minimal GitHub scopes: `read:user` (just need user ID and username)

---

## Future Enhancements

### Multi-Org Support

**Currently:** 1 user : 1 personal org : N machine principals

**Future:** 1 user : N orgs : N machine principals per org

**Changes needed:**
- Add org membership table (principal_id, org_id, roles)
- User can create orgs, invite other users
- CLI needs to specify which org context to use (different keypair per org)
- Web UI org switcher

### Refresh Tokens

**Currently:** Short-lived JWTs, CLI generates new token each time

**Future:** Refresh token flow
- CLI gets refresh token after initial auth
- Refresh token has long expiration (30 days)
- Use refresh token to get new short-lived access tokens
- Revoke refresh tokens (store in database)

### Audit Logging

**Track:**
- All authentication attempts (success/failure)
- Principal creation, deletion, role changes
- Credential imports
- API access (which principal, which endpoint, when)

**Storage:**
- DynamoDB table with TTL (30 days)
- Or CloudWatch Logs

### Rate Limiting

**Per principal:**
- Limit requests per minute (e.g., 100/min)
- Track in Redis or DynamoDB

**Per org:**
- Limit job submissions per hour
- Limit concurrent workers

### Web UI (Frontend)

**Tech stack:** React, Next.js, TailwindCSS (example)

**Pages:**
- Landing page with "Login with GitHub"
- Dashboard (jobs, workers, org overview)
- Credentials management (import, list, revoke)
- Job details, monitoring
- Settings (org settings, user profile)

---

## Appendix: Blob Format Specification

### Structure

```
-----BEGIN AIRUNNER CREDENTIAL-----
<base58-encoded protobuf binary>
-----END AIRUNNER CREDENTIAL-----
```

**Why protobuf + base58?**
- **Protobuf advantages:**
  - 63% smaller than JSON (150 bytes vs 400 bytes)
  - Strongly typed schema (no parsing ambiguities)
  - No JSON escaping issues (strings, newlines, quotes)
  - Binary format is safer (no injection attacks)
  - Schema evolution built-in
- **Base58 advantages:**
  - No special characters (`+`, `/`, `=`) that break on double-click
  - Double-click selectable in terminals
  - URL-safe without encoding
  - Used by Bitcoin, IPFS for similar reasons

### Protobuf Schema

**File:** `api/auth/v1/credential.proto`

```protobuf
syntax = "proto3";

package auth.v1;

option go_package = "github.com/wolfeidau/airunner/gen/auth/v1;authv1";

// Credential represents an exported public credential for CLI/worker authentication.
// This message is serialized to protobuf binary and then base58-encoded for
// easy copy/paste workflows.
message Credential {
  // Version of the credential format (always 1 for now)
  uint32 version = 1;

  // Type of credential (worker or service)
  CredentialType type = 2;

  // Friendly name for the credential (e.g., "my-laptop", "ci-worker")
  string name = 3;

  // Public key in DER format (ECDSA P-256)
  // This is the raw X.509 SubjectPublicKeyInfo DER bytes (91 bytes for P-256)
  bytes public_key_der = 4;

  // SHA-256 fingerprint of public_key_der (32 bytes)
  // Used for principal lookup during JWT authentication
  bytes fingerprint = 5;

  // Unix timestamp when the credential was created
  int64 created_at = 6;

  // Optional: AWS KMS key ARN for KMS-backed credentials
  // If present, the private key is in KMS and CLI will use KMS Sign API
  string kms_key_id = 7;
}

// CredentialType identifies the type of credential
enum CredentialType {
  // Unspecified (invalid)
  CREDENTIAL_TYPE_UNSPECIFIED = 0;

  // Worker credential (can dequeue and execute jobs)
  CREDENTIAL_TYPE_WORKER = 1;

  // Service credential (API access, typically readonly)
  CREDENTIAL_TYPE_SERVICE = 2;
}
```

### Example

**Protobuf message (before serialization):**
```protobuf
message Credential {
  version: 1
  type: CREDENTIAL_TYPE_WORKER
  name: "my-laptop"
  public_key_der: [91 bytes of DER-encoded ECDSA P-256 public key]
  fingerprint: [32 bytes SHA-256 hash]
  created_at: 1735380000
  kms_key_id: ""  // Empty for local keypairs
}
```

**Size breakdown:**
- version (varint): 1 byte
- type (enum): 1 byte
- name (string): 1 + 9 = 10 bytes
- public_key_der (bytes): 1 + 91 = 92 bytes
- fingerprint (bytes): 1 + 32 = 33 bytes
- created_at (int64): 8 bytes
- kms_key_id (string): 1 byte (empty)
- **Total: ~146 bytes**

**After protobuf serialization:**
```
Binary protobuf: 146 bytes
```

**After base58 encoding:**
```
3yZe7d4WFGpvr8uNQJzKxM2HnBqS9fXjC5RkT
(~200 bytes base58, due to ~37% encoding overhead)
```

**Final blob:**
```
-----BEGIN AIRUNNER CREDENTIAL-----
3yZe7d4WFGpvr8uNQJzKxM2HnBqS9fXjC5RkT
-----END AIRUNNER CREDENTIAL-----
```

**Benefits of protobuf + base58:**
- **63% smaller** than JSON equivalent (200 bytes vs 550 bytes)
- **Strongly typed** - no parsing ambiguities
- **Binary safe** - no string escaping issues
- **Double-click selectable** - no special characters
- **Easy to copy** from terminal
- **URL-safe** without additional encoding
- **Debuggable** - can decode with `protoc --decode`

### Fingerprint Computation

```go
func ComputeFingerprint(publicKey *ecdsa.PublicKey) ([]byte, string, error) {
  // 1. Encode public key to DER format (X.509 SubjectPublicKeyInfo)
  derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
  if err != nil {
    return nil, "", err
  }

  // 2. Hash with SHA-256
  hash := sha256.Sum256(derBytes)

  // 3. Base58 encode for display/lookup (Bitcoin alphabet)
  fingerprintBase58 := base58.Encode(hash[:])

  // Return both raw bytes (for protobuf) and base58 (for display/lookup)
  return hash[:], fingerprintBase58, nil
}
```

**Usage in credential export:**
```go
// Generate keypair
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Get DER bytes and fingerprint
derBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
fingerprintBytes, fingerprintBase58, _ := ComputeFingerprint(&privateKey.PublicKey)

// Create protobuf message
cred := &authv1.Credential{
  Version:      1,
  Type:         authv1.CREDENTIAL_TYPE_WORKER,
  Name:         "my-laptop",
  PublicKeyDer: derBytes,          // Raw DER bytes (91 bytes)
  Fingerprint:  fingerprintBytes,  // Raw SHA-256 hash (32 bytes)
  CreatedAt:    time.Now().Unix(),
}

// Serialize and encode
protoBytes, _ := proto.Marshal(cred)
blob := base58.Encode(protoBytes)
```

**Base58 Alphabet (Bitcoin):**
```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Note: Excludes `0`, `O`, `I`, `l` to avoid visual ambiguity.

### Validation Rules

**Server must validate:**
1. Blob is valid base58 encoding
2. Protobuf unmarshals successfully
3. Version is `1`
4. Type is `CREDENTIAL_TYPE_WORKER` or `CREDENTIAL_TYPE_SERVICE`
5. Public key DER is valid (can be parsed with `x509.ParsePKIXPublicKey`)
6. Public key is ECDSA P-256 (not RSA, not other curves)
7. Fingerprint is exactly 32 bytes (SHA-256 output)
8. Fingerprint matches computed SHA-256 of `public_key_der`
9. Fingerprint (base58-encoded) doesn't already exist in database (no duplicates)
10. If `kms_key_id` is present, it's a valid AWS KMS ARN format
11. `created_at` is a reasonable Unix timestamp (not in future, not before 2020)

**Reject if:**
- Blob contains malformed protobuf
- Public key is not ECDSA P-256
- Fingerprint mismatch (tampering detected)
- Duplicate fingerprint (credential already imported)

---

## Summary

This specification defines a principal-based authentication system for Airunner with the following key properties:

**Security:**
- ✅ Private keys never leave the user's machine (or KMS)
- ✅ Server only stores public keys
- ✅ Self-signed JWTs prove key possession
- ✅ Org-scoped permissions prevent cross-tenant access

**Usability:**
- ✅ Social auth (GitHub) for easy onboarding
- ✅ Simple CLI handoff (copy/paste one blob)
- ✅ Works for humans (web UI) and machines (CLI, workers, CI/CD)
- ✅ KMS support for production deployments

**Architecture:**
- ✅ Multi-tenant with organizations
- ✅ Role-based access control
- ✅ Standard OAuth2/JWT patterns
- ✅ Clean separation of concerns (auth, authz, stores)

**Implementation time:** ~15-20 hours total (7 phases)

**Next steps:** Begin Phase 1 (remove mTLS code).
