# CLI Credentials Architecture

[← README](README.md) | [Phase 1: Local Storage →](01-phase1-local-storage.md)

## Overview

The CLI credential system enables workers and CLI users to authenticate with the airunner API using self-signed JWTs. Unlike user authentication (which uses OIDC tokens issued by the website), worker authentication uses locally-generated ECDSA P-256 keypairs where the public key is registered server-side.

## Design Goals

1. **Offline key generation** - Keys generated locally without server interaction
2. **Simple import workflow** - Copy/paste public key PEM via web UI
3. **Secure key storage** - Private keys stored with restricted permissions (0600)
4. **Multiple credentials** - Support for multiple named credentials with default selection
5. **Transparent authentication** - JWT signing happens automatically via interceptor

## Directory Structure

```
~/.airunner/
└── credentials/
    ├── config.json              # Metadata and default credential
    ├── production-workers.key   # Private key (PEM, 0600 permissions)
    ├── production-workers.pub   # Public key (PEM, 0644 permissions)
    ├── staging-workers.key
    └── staging-workers.pub
```

## Config Schema

The `config.json` file stores credential metadata and tracks import status:

```json
{
  "version": 1,
  "default_credential": "production-workers",
  "credentials": {
    "production-workers": {
      "name": "production-workers",
      "fingerprint": "7RpMx9NqK4vBwE8mJdHnLpQrYtUzXcAf2sGiW6hN3oS",
      "org_id": "018f1234-5678-7abc-def0-abcdef123456",
      "principal_id": "018f5678-90ab-cdef-1234-567890abcdef",
      "imported": true,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T11:00:00Z"
    },
    "staging-workers": {
      "name": "staging-workers",
      "fingerprint": "3KpLm8NqR5vCwF9nJeIoMpSrZtVzYdBg4tHjX7iO4pT",
      "org_id": "",
      "principal_id": "",
      "imported": false,
      "created_at": "2024-01-16T09:00:00Z",
      "updated_at": "2024-01-16T09:00:00Z"
    }
  }
}
```

### Config Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Schema version for future migrations |
| `default_credential` | string | Name of credential to use when `--credential` not specified |
| `credentials` | map | Map of credential name to metadata |

### Credential Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Credential name (matches filename) |
| `fingerprint` | string | Base58-encoded SHA256 of public key DER (used as JWT `kid`) |
| `org_id` | string | Organization ID from server (empty until imported) |
| `principal_id` | string | Principal ID from server (empty until imported) |
| `imported` | bool | Whether credential has been imported to server |
| `created_at` | string | RFC3339 timestamp of key generation |
| `updated_at` | string | RFC3339 timestamp of last metadata update |

## Fingerprint Calculation

The fingerprint serves as the key identifier (`kid` in JWT header) and is calculated as:

```go
// 1. Parse PEM to get DER bytes
block, _ := pem.Decode(publicKeyPEM)
derBytes := block.Bytes

// 2. SHA256 hash
hash := sha256.Sum256(derBytes)

// 3. Base58 encode (Bitcoin alphabet)
fingerprint := base58.Encode(hash[:])
```

This matches the server-side calculation in `credential_service.go:80-81`.

## JWT Structure (Worker)

Workers sign their own JWTs using the private key:

```json
{
  "header": {
    "alg": "ES256",
    "typ": "JWT",
    "kid": "7RpMx9NqK4vBwE8mJdHnLpQrYtUzXcAf2sGiW6hN3oS"
  },
  "payload": {
    "iss": "airunner-cli",
    "sub": "7RpMx9NqK4vBwE8mJdHnLpQrYtUzXcAf2sGiW6hN3oS",
    "aud": "https://api.airunner.dev",
    "org": "018f1234-5678-7abc-def0-abcdef123456",
    "roles": ["worker"],
    "principal_id": "018f5678-90ab-cdef-1234-567890abcdef",
    "iat": 1705312200,
    "exp": 1705315800
  }
}
```

### JWT Claims

| Claim | Source | Description |
|-------|--------|-------------|
| `iss` | Hardcoded | Always `"airunner-cli"` for worker tokens |
| `sub` | Fingerprint | Public key fingerprint (matches `kid`) |
| `aud` | Server URL | Target API server URL |
| `org` | config.json | Organization ID from import |
| `roles` | Hardcoded | Always `["worker"]` for CLI credentials |
| `principal_id` | config.json | Principal ID from import |
| `iat` | Generated | Issue time (current timestamp) |
| `exp` | Generated | Expiry time (iat + 1 hour) |

## Authentication Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CLI Command   │     │   Interceptor   │     │     Server      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  Load credential      │                       │
         │──────────────────────>│                       │
         │                       │                       │
         │                       │  Sign JWT with        │
         │                       │  private key          │
         │                       │                       │
         │                       │  Add Authorization    │
         │                       │  header               │
         │                       │                       │
         │                       │  gRPC request         │
         │                       │──────────────────────>│
         │                       │                       │
         │                       │                       │  Extract kid
         │                       │                       │  from header
         │                       │                       │
         │                       │                       │  Lookup public
         │                       │                       │  key by kid
         │                       │                       │
         │                       │                       │  Verify JWT
         │                       │                       │  signature
         │                       │                       │
         │                       │         Response      │
         │                       │<──────────────────────│
         │       Response        │                       │
         │<──────────────────────│                       │
         │                       │                       │
```

## Error Handling

### Credential Not Found

When `--credential <name>` specifies a non-existent credential:

```
Error: credential "prod-workers" not found

Available credentials:
  - staging-workers (not imported)

Run 'airunner-cli init <name>' to create a new credential.
```

### Credential Not Imported

When using a credential that hasn't been imported to the server:

```
Error: credential "staging-workers" not imported

This credential has not been registered with the server yet.
To import:
  1. Copy the public key: airunner-cli credentials show staging-workers
  2. Import via web UI at https://example.com/credentials
  3. Update with server IDs: airunner-cli credentials update staging-workers \
       --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>
```

### Expired or Revoked Credential

When the server rejects the JWT (401 Unauthorized):

```
Error: authentication failed

The credential "production-workers" may have been revoked.
Check credential status in the web UI or contact your administrator.
```

### Invalid Private Key

When the private key file is corrupted or invalid:

```
Error: failed to load credential "production-workers"

The private key file may be corrupted. Details: invalid PEM block type

You may need to delete and recreate this credential:
  airunner-cli credentials delete production-workers
  airunner-cli init production-workers
```

## Security Considerations

1. **Private key permissions** - Files created with 0600 (owner read/write only)
2. **No key export** - Private keys never leave the local machine
3. **Short-lived tokens** - JWTs expire after 1 hour
4. **Fingerprint as kid** - Server looks up public key by fingerprint, not principal_id
5. **Revocation** - Server maintains revocation list; revoked credentials fail authentication

## Package Structure

```
cmd/cli/internal/
├── credentials/
│   ├── store.go        # CredentialStore - file I/O, config management
│   ├── jwt.go          # JWTSigner - token creation and signing
│   └── interceptor.go  # AuthInterceptor - Connect RPC middleware
└── commands/
    ├── init.go         # InitCmd - key generation
    └── credentials.go  # CredentialsCmd - management subcommands
```

## Dependencies

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"

    "github.com/golang-jwt/jwt/v5"
    "github.com/mr-tron/base58"
)
```

The `github.com/golang-jwt/jwt/v5` package is already used server-side and should be added to CLI dependencies.

---

[← README](README.md) | [Phase 1: Local Storage →](01-phase1-local-storage.md)
