# UI Credentials Architecture

[← README](README.md) | [Implementation →](01-phase1-implementation.md)

## Overview

The credentials UI adds a new tab to the dashboard for managing worker credentials. It follows existing React patterns and uses the generated Connect RPC client to communicate with the CredentialService.

## Component Architecture

```
AppWithToken
└── TransportProvider (with auth transport)
    └── QueryClientProvider
        └── Dashboard
            ├── Topbar (with tab navigation)
            └── Content (conditional rendering)
                ├── JobEventsView (when #job-{id})
                ├── CredentialsView (when #credentials)
                │   ├── ImportCredentialForm
                │   └── CredentialsTable
                └── JobsView (default)
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         Dashboard                                │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Hash Routing                                             │   │
│  │                                                          │   │
│  │  URL Hash          →  State                              │   │
│  │  #credentials      →  activeTab: "credentials"           │   │
│  │  #job-{id}         →  activeTab: "jobs", selectedJobId   │   │
│  │  (empty)           →  activeTab: "jobs"                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ CredentialsView                                          │   │
│  │                                                          │   │
│  │  useQuery(listCredentials)  →  credentials[]             │   │
│  │                                                          │   │
│  │  ImportCredentialForm                                    │   │
│  │    └── useMutation(importCredential)                     │   │
│  │    └── onSuccess → refetch() + show inline result        │   │
│  │                                                          │   │
│  │  CredentialsTable                                        │   │
│  │    └── useMutation(revokeCredential)                     │   │
│  │    └── onRevoke → confirm() + refetch()                  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## API Reference

### CredentialService RPC Methods

All methods available at `/principal.v1.CredentialService/`

#### ImportCredential

Imports a worker credential from a PEM-encoded public key.

**Request:**
```typescript
interface ImportCredentialRequest {
  name: string;           // Display name (required)
  publicKeyPem: string;   // PEM-encoded ECDSA P-256 public key (required)
  description: string;    // Optional description
}
```

**Response:**
```typescript
interface ImportCredentialResponse {
  principalId: string;    // UUIDv7 as string
  orgId: string;          // UUIDv7 as string
  roles: string[];        // Roles assigned (e.g., ["worker"])
  fingerprint: string;    // Base58-encoded SHA256 of public key DER
  name: string;           // Credential name
}
```

**Authorization:** Requires `admin` role

#### ListCredentials

Lists all credentials for the caller's organization.

**Request:**
```typescript
interface ListCredentialsRequest {
  principalType: string;  // Optional filter: "user", "worker", "service" (empty = all)
}
```

**Response:**
```typescript
interface ListCredentialsResponse {
  credentials: Credential[];
}

interface Credential {
  principalId: string;
  orgId: string;
  type: string;           // "user", "worker", "service"
  name: string;
  fingerprint: string;    // Empty for user principals
  roles: string[];
  createdAt: string;      // RFC3339 timestamp
  lastUsedAt: string;     // RFC3339 timestamp (optional)
}
```

**Authorization:** Any authenticated user

#### RevokeCredential

Soft-deletes a credential by principal ID.

**Request:**
```typescript
interface RevokeCredentialRequest {
  principalId: string;    // UUIDv7 as string (required)
}
```

**Response:**
```typescript
interface RevokeCredentialResponse {}  // Empty on success
```

**Authorization:** Requires `admin` role. Cannot revoke own credential.

### Generated TypeScript Clients

The Connect RPC TypeScript clients are already generated:

```
api/gen/proto/es/principal/v1/
├── principal_pb.ts                              # Type definitions
└── principal-CredentialService_connectquery.ts  # RPC methods
```

**Usage:**
```typescript
import {
  listCredentials,
  importCredential,
  revokeCredential
} from "../../api/gen/proto/es/principal/v1/principal-CredentialService_connectquery";
import { useQuery, useMutation } from "@connectrpc/connect-query";

// List credentials
const { data, refetch, isLoading } = useQuery(listCredentials, { principalType: "" });

// Import credential
const importMutation = useMutation(importCredential);
await importMutation.mutateAsync({ name, publicKeyPem, description });

// Revoke credential
const revokeMutation = useMutation(revokeCredential);
await revokeMutation.mutateAsync({ principalId });
```

## UI Components

### Tab Navigation

Hash-based routing for tabs:

| Hash | Active Tab | View |
|------|-----------|------|
| `#credentials` | credentials | CredentialsView |
| `#job-{id}` | jobs | JobEventsView |
| (empty) | jobs | JobsView (list) |

### ImportCredentialForm

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| Name | text input | Yes | Credential display name |
| Public Key PEM | textarea | Yes | PEM-encoded ECDSA P-256 public key |
| Description | text input | No | Optional description |

**Success State:**
Shows inline message with:
- Success text
- Principal ID (copyable)
- Org ID (copyable)
- Pre-formatted CLI command

### CredentialsTable

| Column | Description |
|--------|-------------|
| Name | Credential display name |
| Type | Principal type badge (user/worker/service) |
| Fingerprint | Truncated, copy on click |
| Created | Formatted timestamp |
| Last Used | Formatted timestamp or "Never" |
| Actions | Revoke button (for workers, not self) |

## Styling

Follow existing Nord theme variables from `ui/pages/app.css`:

```css
--nord0: #2E3440;   /* Background dark */
--nord1: #3B4252;   /* Background lighter */
--nord2: #434C5E;   /* Selection */
--nord3: #4C566A;   /* Borders */
--nord4: #D8DEE9;   /* Text secondary */
--nord6: #ECEFF4;   /* Text primary */
--nord11: #BF616A;  /* Red (errors, revoke) */
--nord14: #A3BE8C;  /* Green (success) */
```

## Error Handling

| Error | Display |
|-------|---------|
| Import failed | Inline error below form |
| List failed | Error state with retry button |
| Revoke failed | Alert/toast message |
| Network error | Generic connection error |

## Security Considerations

- Only `admin` role can import or revoke credentials
- Cannot revoke own credential (prevents lockout)
- Session-based auth automatically handled by cookie
- All data scoped to user's organization

---

[← README](README.md) | [Implementation →](01-phase1-implementation.md)
