# CLI Credential Management

## Overview

This specification covers the CLI-side credential management for airunner, enabling workers and CLI users to authenticate with the API using self-signed JWTs.

**Parent Spec:** [Principal Auth MVP](../principal-auth-mvp.md)

## Prerequisites

- Go 1.21+
- Existing CLI structure (`cmd/cli/`)
- CredentialService RPC already implemented on server
- Understanding of ECDSA P-256 key pairs and JWT signing

## Quick Start

1. Read [Architecture](00-architecture.md) for design decisions and config schema
2. Implement [Phase 1: Local Storage](01-phase1-local-storage.md) - credential file management
3. Implement [Phase 2: CLI Commands](02-phase2-cli-commands.md) - init and credentials subcommands
4. Implement [Phase 3: JWT Signing](03-phase3-jwt-signing.md) - interceptor for API authentication

## File Navigation

| File | Purpose | Estimated Duration |
|------|---------|-------------------|
| [00-architecture.md](00-architecture.md) | Design decisions, config schema, data flow | Reference |
| [01-phase1-local-storage.md](01-phase1-local-storage.md) | Credential storage package | 2-3 hours |
| [02-phase2-cli-commands.md](02-phase2-cli-commands.md) | CLI commands (init, credentials) | 2-3 hours |
| [03-phase3-jwt-signing.md](03-phase3-jwt-signing.md) | JWT signing and Connect interceptor | 2-3 hours |

## End-to-End Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. CLI: airunner-cli init prod-workers                                  │
│    └── Generates ECDSA P-256 keypair                                    │
│    └── Saves to ~/.airunner/credentials/prod-workers.{key,pub}          │
│    └── Displays public key PEM for import                               │
│                                                                         │
│ 2. Admin copies public key PEM from CLI output                          │
│                                                                         │
│ 3. Web UI: Admin imports credential (CredentialService.ImportCredential)│
│    └── Returns principal_id, org_id, fingerprint                        │
│                                                                         │
│ 4. CLI: airunner-cli credentials update prod-workers \                  │
│         --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>                 │
│    └── Marks credential as imported in config.json                      │
│                                                                         │
│ 5. CLI: airunner-cli worker --credential prod-workers                   │
│    └── Loads private key from ~/.airunner/credentials/                  │
│    └── Signs JWT with claims (sub, org, principal_id, roles)            │
│    └── Attaches Authorization: Bearer <JWT> to requests                 │
└─────────────────────────────────────────────────────────────────────────┘
```

## Files to Create

| File | Purpose |
|------|---------|
| `cmd/cli/internal/credentials/store.go` | Local credential storage (~/.airunner/credentials/) |
| `cmd/cli/internal/credentials/jwt.go` | JWT creation and signing |
| `cmd/cli/internal/credentials/interceptor.go` | Connect RPC interceptor for auth headers |
| `cmd/cli/internal/commands/init.go` | `airunner-cli init` command |
| `cmd/cli/internal/commands/credentials.go` | `airunner-cli credentials` subcommands |

## Success Criteria

- [ ] `airunner-cli init <name>` generates keypair and displays public key PEM
- [ ] `airunner-cli credentials list` shows all credentials with import status
- [ ] `airunner-cli credentials update` stores org_id and principal_id
- [ ] `airunner-cli credentials show` displays credential details including public key
- [ ] `airunner-cli credentials delete` removes credential files
- [ ] `airunner-cli credentials set-default` changes default credential
- [ ] `airunner-cli worker --credential <name>` authenticates via JWT
- [ ] `airunner-cli submit --credential <name>` authenticates via JWT
- [ ] Graceful error when credential not imported (missing org_id/principal_id)

## Related Documentation

- [Principal Auth MVP](../principal-auth-mvp.md) - Overall authentication architecture
- [CredentialService Implementation](../../internal/server/credential_service.go) - Server-side credential management
