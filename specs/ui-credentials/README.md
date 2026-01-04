# UI Credential Management

## Overview

This specification covers the web UI for managing worker credentials, enabling admins to import, list, and revoke credentials through the dashboard.

**Parent Spec:** [Principal Auth MVP](../principal-auth-mvp.md)

## Prerequisites

- Completed [CLI Credentials](../cli-credentials/README.md) implementation
- CredentialService RPC implemented on server
- Existing dashboard UI (`ui/pages/dashboard.tsx`)
- Understanding of React + Connect RPC patterns

## Quick Start

1. Read this overview and the end-to-end workflow
2. Review [00-architecture.md](00-architecture.md) for component design and data flow
3. Implement [01-phase1-implementation.md](01-phase1-implementation.md) - all UI changes

## File Navigation

| File | Purpose |
|------|---------|
| [00-architecture.md](00-architecture.md) | Component design, data flow, API reference |
| [01-phase1-implementation.md](01-phase1-implementation.md) | Step-by-step implementation guide |

## End-to-End Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. CLI: airunner-cli init prod-workers                                  │
│    └── Generates ECDSA P-256 keypair                                    │
│    └── Displays public key PEM for import                               │
│                                                                         │
│ 2. Web UI: Admin clicks "Credentials" tab                               │
│    └── Dashboard shows credentials list (ListCredentials RPC)           │
│                                                                         │
│ 3. Web UI: Admin fills import form                                      │
│    └── Name: "prod-workers"                                             │
│    └── Public Key: (paste PEM from CLI)                                 │
│    └── Clicks "Import Credential"                                       │
│                                                                         │
│ 4. Web UI: Shows inline success message                                 │
│    └── Principal ID: 018f1234-5678-...                                  │
│    └── Org ID: 018f1234-5678-...                                        │
│    └── CLI command to copy:                                             │
│        airunner-cli credentials update prod-workers \                   │
│          --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>                │
│                                                                         │
│ 5. CLI: Admin runs update command                                       │
│    └── Marks credential as imported locally                             │
│                                                                         │
│ 6. CLI/Worker: Can now authenticate with JWT                            │
│    └── airunner-cli worker --credential prod-workers                    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Files to Modify

| File | Changes |
|------|---------|
| `ui/lib/createAuthTransport.ts` | Add `credentials: 'include'` for session cookie support |
| `ui/pages/dashboard.tsx` | Fix hardcoded URL, add tab navigation, credentials components |
| `ui/pages/dashboard.css` | Add styles for tabs, import form, credentials table |

## Success Criteria

- [ ] Fix hardcoded server URL (`https://localhost:8993` → `window.location.origin`)
- [ ] Add `credentials: 'include'` to transport for session cookie support
- [ ] Tab navigation switches between Jobs and Credentials views
- [ ] Credentials list loads via `ListCredentials` RPC (using `useQuery`)
- [ ] Import form with name, public key PEM, and description fields
- [ ] Import calls `ImportCredential` RPC (using `useMutation`)
- [ ] Inline success message shows principal_id, org_id, and CLI command
- [ ] Revoke button calls `RevokeCredential` RPC with confirmation
- [ ] Cannot revoke own credential
- [ ] Error states displayed for failed operations
- [ ] Loading spinners during API calls

## Transport Fixes Required

Two issues with the current transport setup:

### 1. Hardcoded Server URL

**File:** `ui/pages/dashboard.tsx:637`

```typescript
// Current (broken for deployment)
createAuthTransport("https://localhost:8993", token)

// Fixed (works everywhere)
createAuthTransport(window.location.origin, token)
```

### 2. Missing Session Cookie Support

**File:** `ui/lib/createAuthTransport.ts`

The transport needs `credentials: 'include'` to send the session cookie. This allows the dual auth middleware to authenticate browser requests without requiring a JWT.

```typescript
return createConnectTransport({
  baseUrl,
  credentials: "include",  // ADD THIS
  interceptors: [...]
});
```

### Optional Cleanup

With session cookie support, the JWT token fetch (`ui/lib/token.ts`, `ui/lib/useToken.ts`) becomes optional for browser requests. The token machinery can be removed in a future cleanup.

## Related Documentation

- [Principal Auth MVP](../principal-auth-mvp.md) - Overall authentication architecture
- [CLI Credentials](../cli-credentials/README.md) - CLI-side credential management
- [CredentialService](../../internal/server/credential_service.go) - Server-side implementation
