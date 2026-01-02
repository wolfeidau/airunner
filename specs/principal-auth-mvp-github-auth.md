# Principal Authentication MVP - GitHub Auth + Session Store Integration

## Status: ✅ Complete

**Completed:** 2026-01-02

## Overview

This document describes the integration of GitHub OAuth with server-side session storage and automatic organization/principal creation on first login.

## Architecture

```
┌─────────────────┐
│    User         │
│   (Browser)     │
└────────┬────────┘
         │
         │ 1. GET /login
         ▼
┌─────────────────┐
│  Website (443)  │
│                 │
│  GitHub OAuth   │◄──── 2. Redirect to GitHub
│  SessionStore   │◄──── 3. Callback with code
│  PrincipalStore │      4. Exchange for token
│  OrgStore       │      5. Fetch user info
│                 │      6. Create org+principal (first login)
│                 │      7. Create session in store
│                 │      8. Set cookie (session_id only)
└────────┬────────┘
         │
         │ Cookie: _session=<UUIDv7>
         ▼
┌─────────────────┐
│  API Server     │
│    (8993)       │
│                 │
│  JWT Middleware │◄──── User requests JWT from /auth/token
│                 │      Session lookup → principal_id
│                 │      Issue JWT with claims
└─────────────────┘
```

## Key Design Decisions

### 1. Opaque Session IDs (Not HMAC-Signed Tokens)

**Before:** Cookie contained `{id, email, name, issued_at, expires_at}.hmac_signature`
**After:** Cookie contains only `session_id` (UUIDv7)

**Benefits:**
- Smaller cookies (~36 bytes vs ~200+ bytes)
- Immediate session revocation (delete from store)
- Session data not exposed to client
- No cryptographic signing overhead

### 2. Automatic Org + Principal Creation on First Login

When a user logs in via GitHub for the first time:
1. Organization created using GitHub username as org name
2. Principal created with `admin` + `user` roles
3. Principal linked to org as owner
4. GitHub profile info (name, email, avatar) stored on principal

### 3. GitHub Profile Synced on Each Login

Returning users have their principal updated with latest GitHub info:
- Name
- Email  
- Avatar URL
- GitHub username (login)

### 4. Session Contains Principal Reference

Session stores `principal_id` and `org_id` directly, avoiding database lookups for JWT issuance.

## Database Schema

### Migration 3: Sessions + Principal Fields

```sql
-- New columns for principals table
ALTER TABLE principals
    ADD COLUMN github_login VARCHAR(255),
    ADD COLUMN email VARCHAR(255),
    ADD COLUMN avatar_url TEXT;

-- Sessions table
CREATE TABLE sessions (
    session_id UUID PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_agent TEXT,
    ip_address INET
);

CREATE INDEX idx_sessions_principal ON sessions(principal_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
```

## Data Models

### Session

```go
type Session struct {
    SessionID   uuid.UUID // UUIDv7 - stored in cookie
    PrincipalID uuid.UUID // Who is logged in
    OrgID       uuid.UUID // Denormalized for fast JWT claims
    CreatedAt   time.Time
    ExpiresAt   time.Time
    LastUsedAt  time.Time
    UserAgent   string    // Optional audit trail
    IPAddress   string    // Optional audit trail
}
```

### Principal (Updated Fields)

```go
type Principal struct {
    // ... existing fields ...
    
    // For user principals (GitHub OAuth)
    GitHubID    *string // Numeric ID as string
    GitHubLogin *string // GitHub username
    Email       *string // Primary email
    AvatarURL   *string // Profile picture
}
```

## Store Interfaces

### SessionStore

```go
type SessionStore interface {
    Create(ctx, session) error
    Get(ctx, sessionID) (*Session, error)       // Returns ErrSessionExpired if expired
    UpdateLastUsed(ctx, sessionID) error
    Delete(ctx, sessionID) error                // Logout
    DeleteByPrincipal(ctx, principalID) (int, error)  // Logout everywhere
    DeleteExpired(ctx) (int, error)             // Cleanup job
}
```

## Authentication Flow

### First Login

```
1. User → GET /login
2. Website → Redirect to GitHub OAuth
3. GitHub → Callback with code
4. Website → Exchange code for access token
5. Website → Fetch GitHub user info (id, login, email, name, avatar_url)
6. Website → Look up principal by GitHub ID
7. NOT FOUND → Create organization (name = GitHub username)
8. Website → Create principal (admin role, linked to org)
9. Website → Create session in SessionStore
10. Website → Set cookie: _session=<session_id>
11. Website → Redirect to /dashboard
```

### Returning User

```
1-5. Same as above
6. Website → Look up principal by GitHub ID
7. FOUND → Update principal with latest GitHub info
8. Website → Create session in SessionStore
9. Website → Set cookie: _session=<session_id>
10. Website → Redirect to /dashboard
```

### Token Issuance

```
1. User → POST /auth/token (with _session cookie)
2. Website → Parse session_id from cookie
3. Website → Look up session in SessionStore
4. Website → Session contains principal_id, org_id
5. Website → Sign JWT with claims (sub, org, roles)
6. Website → Return JWT to user
```

### Logout

```
1. User → POST /logout (with _session cookie)
2. Website → Parse session_id from cookie
3. Website → Delete session from SessionStore
4. Website → Clear _session cookie (MaxAge=-1)
5. Website → Redirect to /
```

## Files Created/Modified

### New Files

| File | Description |
|------|-------------|
| `internal/models/session.go` | Session model |
| `internal/store/session_store.go` | SessionStore interface |
| `internal/store/postgres/session_store.go` | PostgreSQL implementation |
| `internal/store/memory/session_store.go` | Memory implementation (testing) |
| `internal/store/postgres/migrations/3_sessions.sql` | Database migration |

### Modified Files

| File | Changes |
|------|---------|
| `internal/models/principal.go` | Added `GitHubLogin`, `Email`, `AvatarURL` |
| `internal/store/postgres/principal_store.go` | Updated queries for new fields |
| `internal/login/login.go` | Refactored to use SessionStore, auto-create org+principal |
| `internal/website/oidc/session_adapter.go` | Simplified (session has principal_id) |
| `cmd/server/internal/commands/website.go` | Wired up all stores, removed SessionSecret flag |
| `internal/login/login_test.go` | Rewrote tests for new architecture |

## Configuration Changes

### Removed Flags

- `--session-secret` / `AIRUNNER_SESSION_SECRET` - No longer needed

### Store Type

The `--store-type` flag now controls all stores (sessions, principals, organizations):

```bash
# Memory stores (development)
./bin/airunner-server website --store-type=memory

# PostgreSQL stores (production)
./bin/airunner-server website --store-type=postgres --postgres-conn-string="..."
```

## Testing

All unit tests updated and passing:

```bash
go test ./internal/login/... -v
```

Key test cases:
- `TestGithub_GetSession` - Session lookup from cookie
- `TestGithub_GetSession_expired` - Expired session handling
- `TestGithub_RequireAuth_validSession` - Middleware with valid session
- `TestGithub_LogoutHandler` - Session deletion on logout
- `TestGithub_getOrCreatePrincipal_newUser` - First login flow
- `TestGithub_getOrCreatePrincipal_existingUser` - Returning user flow

## Security Considerations

1. **Session ID is opaque** - No user data in cookie
2. **Immediate revocation** - Delete session = instant logout
3. **HttpOnly + Secure cookies** - Protected from XSS, requires HTTPS
4. **SameSite=Lax** - CSRF protection
5. **IP + User-Agent tracking** - Optional audit trail

## Future Enhancements

1. **Session cleanup job** - Periodic deletion of expired sessions
2. **Concurrent session limits** - Max N sessions per user
3. **Session listing UI** - Show active sessions, allow remote logout
4. **Refresh tokens** - Extend session without re-authentication
5. **Multi-org support** - Users belonging to multiple organizations

## References

- Parent spec: `specs/principal-auth-mvp.md`
- Previous summary: `specs/principal-auth-implementation-summary.md`
- Integration guide: `internal/auth/README.md`
