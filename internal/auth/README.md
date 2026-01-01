# Authentication & Authorization - Integration Guide

This directory contains the JWT-based authentication system for airunner. This guide shows how to wire up the components.

## Overview

The authentication system uses:
- **Website** (port 443): OIDC provider, owns principals, signs user JWTs
- **API Server** (port 8993): Verifies JWTs (both user and worker), stateless auth

## Components Implemented

### Website Server Components
1. **OIDC Key Manager** (`internal/website/oidc/key_manager.go`) - Manages website's ECDSA keypair for signing user JWTs
2. **OIDC Handlers** (`internal/website/oidc/handlers.go`) - OIDC discovery, JWKS, and token endpoints
3. **Principal Service** (`internal/server/principal_service.go`) - GetPublicKey and ListRevokedPrincipals RPCs
4. **Credential Service** (`internal/server/credential_service.go`) - ImportCredential, ListCredentials, RevokeCredential RPCs
5. **Stores** (`internal/store/postgres/principal_store.go`, `organization_store.go`) - Database layer

### API Server Components
1. **JWT Middleware** (`internal/auth/jwt_middleware.go`) - Verifies both user and worker JWTs
2. **Public Key Cache** (`internal/auth/public_key_cache.go`) - Caches public keys from JWKS and database
3. **Revocation Checker** (`internal/auth/revocation_checker.go`) - Polls revocation list every 5 minutes
4. **HTTP Caching Client** (`internal/client/caching_transport.go`) - HTTP caching for PrincipalService calls

## Website Server Wiring

Add to `cmd/server/internal/commands/website.go`:

```go
import (
	"connectrpc.com/connect"
	principalv1connect "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/website/oidc"
)

// Add to WebsiteCmd struct
type WebsiteCmd struct {
	// ... existing fields ...

	// Principal auth configuration
	PostgresConnString string `help:"PostgreSQL connection string" env:"POSTGRES_CONNECTION_STRING"`
	WebsiteBaseURL     string `help:"website base URL for OIDC issuer" default:"https://localhost" env:"AIRUNNER_WEBSITE_BASE_URL"`
	APIBaseURL         string `help:"API base URL for JWT audience" default:"https://localhost:8993" env:"AIRUNNER_API_BASE_URL"`
}

func (c *WebsiteCmd) Run(globals *Globals) error {
	// ... existing code ...

	// 1. Create principal and organization stores
	principalStore, err := postgres.NewPrincipalStore(c.PostgresConnString)
	if err != nil {
		return fmt.Errorf("failed to create principal store: %w", err)
	}

	orgStore, err := postgres.NewOrganizationStore(c.PostgresConnString)
	if err != nil {
		return fmt.Errorf("failed to create organization store: %w", err)
	}

	// 2. Initialize OIDC key manager
	keyManager, err := oidc.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}

	// 3. Create OIDC handler
	oidcHandler := oidc.NewHandler(keyManager, principalStore, c.WebsiteBaseURL)

	// 4. Register OIDC endpoints (HTTP)
	mux.HandleFunc("/.well-known/openid-configuration", oidcHandler.DiscoveryHandler())
	mux.HandleFunc("/.well-known/jwks.json", oidcHandler.JWKSHandler())
	mux.HandleFunc("POST /auth/token", oidcHandler.TokenHandler(gh, c.APIBaseURL))

	// 5. Create principal service servers
	principalService := server.NewPrincipalServiceServer(principalStore)
	credentialService := server.NewCredentialServiceServer(principalStore, orgStore)

	// 6. Register Connect RPC handlers
	principalPath, principalHandler := principalv1connect.NewPrincipalServiceHandler(
		principalService,
		connect.WithInterceptors(/* logger, etc. */),
	)
	mux.Handle(principalPath, principalHandler)

	credentialPath, credentialHandler := principalv1connect.NewCredentialServiceHandler(
		credentialService,
		connect.WithInterceptors(/* auth middleware for session-based auth */),
	)
	mux.Handle(credentialPath, credentialHandler)

	// ... rest of existing code ...
}
```

## API Server Wiring

Add to `cmd/server/internal/commands/rpc.go`:

```go
import (
	"connectrpc.com/connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/client"
	principalv1connect "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
)

// Add to RPCServerCmd struct
type RPCServerCmd struct {
	// ... existing fields ...

	// Authentication configuration
	WebsiteBaseURL string `help:"website base URL for OIDC verification" default:"https://localhost" env:"AIRUNNER_WEBSITE_BASE_URL"`
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	// ... existing code ...

	// 1. Create HTTP client with caching for PrincipalService calls
	httpClient := client.NewInMemoryCachingHTTPClient()

	// 2. Create PrincipalService client (calls website server)
	principalClient := principalv1connect.NewPrincipalServiceClient(
		httpClient,
		s.WebsiteBaseURL, // e.g., "https://localhost"
	)

	// 3. Create public key cache
	publicKeyCache := auth.NewPublicKeyCache(nil /* no principal store on API */, httpClient)

	// 4. Create revocation checker (polls every 5 minutes)
	revocationChecker := auth.NewRevocationChecker(ctx, principalClient, 5*time.Minute)
	defer revocationChecker.Stop()

	// 5. Create JWT authentication middleware
	jwtMiddleware := auth.JWTAuthMiddleware(
		s.WebsiteBaseURL,
		publicKeyCache,
		revocationChecker,
	)

	// 6. Wrap job service handler with JWT middleware
	handler = jwtMiddleware(handler)

	// ... rest of existing code ...
}
```

## Usage Flow

### User Authentication (Web Frontend → API)

1. User logs in via GitHub OAuth on website → session created
2. Frontend calls `POST /auth/token` with session cookie → website returns JWT
3. Frontend stores JWT in memory
4. Frontend calls API with `Authorization: Bearer <JWT>`
5. API verifies JWT signature with website's public key from `/.well-known/jwks.json`
6. API extracts org_id, roles from JWT claims → adds Principal to request context

### Worker Authentication (CLI/Worker → API)

1. Worker imports credential blob via website UI → website returns principal_id, org_id, roles
2. Worker caches metadata locally
3. Worker creates self-signed JWT with claims (org, roles, principal_id)
4. Worker calls API with `Authorization: Bearer <JWT>`
5. API checks revocation list (in-memory, refreshed every 5min)
6. API verifies JWT signature with worker's public key (from database, cached 5min)
7. API extracts org_id, roles from JWT claims → adds Principal to request context

## Testing

```bash
# Start PostgreSQL (for principal storage)
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16

# Start website server
./bin/airunner-server website \
  --postgres-conn-string="postgres://postgres:postgres@localhost/postgres?sslmode=disable" \
  --website-base-url="https://localhost" \
  --api-base-url="https://localhost:8993"

# Start API server
./bin/airunner-server rpc \
  --website-base-url="https://localhost"

# Verify OIDC endpoints
curl https://localhost/.well-known/openid-configuration
curl https://localhost/.well-known/jwks.json
```

## Migration from mTLS

If migrating from mTLS authentication:

1. Keep mTLS middleware for backward compatibility
2. Add JWT middleware as alternative path
3. Check for JWT first, fall back to mTLS
4. Gradually migrate clients to JWT
5. Remove mTLS when all clients migrated

## Security Considerations

- Website's ECDSA private key should be rotated periodically (e.g., monthly)
- JWT expiration: 1 hour for user JWTs (configurable)
- Revocation list refresh: 5 minutes (configurable)
- Public key cache TTL: 5 minutes for workers, 1 hour for website JWKS
- Use HTTPS for all communication (TLS 1.2+)

## Performance

At scale (100k workers, 1.2M requests/min):

- JWT verification: ~1ms per request (ECDSA signature verification)
- Public key cache hit rate: >99% (keys rarely change)
- Revocation check: <1ms (in-memory map lookup)
- Database queries: Zero during JWT verification (all data in JWT claims)

Compare to database-backed auth: ~10-50ms per request (DB lookup + network)

## Troubleshooting

### "unauthorized" errors

- Check JWT issuer matches website base URL
- Verify JWT kid matches key in JWKS
- Check JWT expiration time
- Verify public key cache is populated

### "credential revoked" errors

- Check revocation list is being refreshed
- Verify fingerprint is in revoked set
- Check if credential was deleted from database

### "unknown issuer" errors

- Verify JWT issuer is either website base URL or "airunner-cli"/"airunner-worker"
- Check JWT header includes "iss" claim

## References

- JWT spec: https://datatracker.ietf.org/doc/html/rfc7519
- OIDC discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
- JWKS format: https://datatracker.ietf.org/doc/html/rfc7517
