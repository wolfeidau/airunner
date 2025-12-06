# API Authentication Design

## Overview

Implement JWT-based authentication for the airunner gRPC service using ECDSA (ES256) signing. Keys are stored in AWS SSM Parameter Store and injected into ECS task containers at startup via the task definition `secrets` block.

## Problem Statement

The airunner service requires authentication to prevent unauthorized access to job management operations. The solution must:
- Work seamlessly in AWS ECS with no additional runtime credentials
- Support key rotation without code changes
- Be cryptographically secure with minimal operational overhead
- Integrate cleanly with the existing Connect RPC framework

## Architecture

### Key Management

- **Private Key**: Stored in SSM Parameter Store as `SecureString`, used for signing tokens (admin/CLI only)
- **Public Key**: Stored in SSM Parameter Store as `String`, used for token verification (server)
- **Generation**: ECDSA P256 keys generated via Terraform `tls_private_key` resource
- **Injection**: ECS task definition `secrets` block maps parameters to environment variables at container startup

### Token Validation

1. Client includes JWT in `Authorization: Bearer <token>` header
2. Server extracts token from header using `authn-go` middleware
3. Token signature verified against public key (ECDSA P256)
4. Expiration time checked via `exp` claim
5. Subject claim (`sub`) available in request context via `authn.GetInfo(ctx)`

### Claim Structure

Tokens use standard JWT registered claims:
- `sub` (subject): User/service identifier
- `exp` (expiration): Unix timestamp, recommend 1 hour for API tokens
- `iat` (issued at): Unix timestamp
- `iss` (issuer): Set to "airunner" for identification

## Implementation

### 1. Dependencies

Add to `go.mod`:

```
require (
    connectrpc.com/authn v0.2.0
    github.com/golang-jwt/jwt/v5 v5.2.1
)
```

### 2. Terraform Setup

```hcl
# Generate ECDSA key pair (P256)
resource "tls_private_key" "jwt" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# Store private key (signing) - only needed by token issuer
resource "aws_ssm_parameter" "jwt_signing_key" {
  name  = "/airunner/jwt-signing-key"
  type  = "SecureString"
  value = tls_private_key.jwt.private_key_pem
}

# Store public key (verification) - needed by RPC server
resource "aws_ssm_parameter" "jwt_public_key" {
  name  = "/airunner/jwt-public-key"
  type  = "String"
  value = tls_private_key.jwt.public_key_pem
}

# ECS task definition secrets mapping (server only needs public key)
secrets = [
  {
    name      = "JWT_PUBLIC_KEY"
    valueFrom = aws_ssm_parameter.jwt_public_key.arn
  }
]
```

Task IAM role automatically receives permissions to read the parameter via ECS execution role.

### 3. Go Implementation

#### Authenticator (internal/auth/jwt.go)

```go
package auth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"os"
	"time"

	"connectrpc.com/authn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

type jwtVerifier struct {
	publicKey *ecdsa.PublicKey
}

func newJWTVerifierFromEnv() (*jwtVerifier, error) {
	publicKeyPEM := os.Getenv("JWT_PUBLIC_KEY")
	if publicKeyPEM == "" {
		return nil, errors.New("JWT_PUBLIC_KEY environment variable not set")
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil {
		return nil, err
	}

	return &jwtVerifier{publicKey: publicKey}, nil
}

// NewJWTAuthFunc returns an authn.AuthFunc that validates Bearer JWTs.
// The returned function extracts and validates JWT tokens from the Authorization header.
// On success, it returns the subject claim which can be retrieved via authn.GetInfo(ctx).
func NewJWTAuthFunc() (authn.AuthFunc, error) {
	v, err := newJWTVerifierFromEnv()
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, req *http.Request) (any, error) {
		// Allow health checks through without auth
		if req.URL.Path == "/health" {
			return nil, nil
		}

		tokenStr, ok := authn.BearerToken(req)
		if !ok {
			return nil, authn.Errorf("missing bearer token")
		}

		parsed, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodES256 {
				return nil, errors.New("invalid signing method")
			}
			return v.publicKey, nil
		})
		if err != nil {
			log.Debug().Err(err).Msg("JWT parse error")
			return nil, authn.Errorf("invalid token")
		}

		if !parsed.Valid {
			return nil, authn.Errorf("token invalid")
		}

		claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
		if !ok {
			return nil, authn.Errorf("invalid claims")
		}

		// jwt/v5 checks expiration automatically, but log for debugging
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			return nil, authn.Errorf("token expired")
		}

		// Return subject as auth info; handlers can read via authn.GetInfo(ctx)
		return claims.Subject, nil
	}, nil
}
```

#### Token Generation (internal/auth/token.go)

For admin tooling and testing:

```go
package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueToken creates a signed JWT token for the given subject.
// signingKeyPEM is the PEM-encoded ECDSA private key.
func IssueToken(signingKeyPEM string, subject string, ttl time.Duration) (string, error) {
	signingKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(signingKeyPEM))
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := &jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Issuer:    "airunner",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(signingKey)
}
```

#### Server Integration (cmd/server/internal/commands/rpc.go)

Integrate auth as HTTP middleware, preserving existing architecture:

```go
package commands

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/authn"
	connectcors "connectrpc.com/cors"
	"github.com/rs/cors"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/autossl"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
)

type RPCServerCmd struct {
	Listen   string `help:"listen address" default:"localhost:8993"`
	Cert     string `help:"path to TLS cert file" default:""`
	Key      string `help:"path to TLS key file" default:""`
	Hostname string `help:"hostname for TLS cert" default:"localhost:8993"`
	NoAuth   bool   `help:"disable JWT authentication (development only)" default:"false"`
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	log := logger.Setup(globals.Dev)

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")
	log.Info().Str("url", fmt.Sprintf("https://%s", s.Listen)).Msg("Listening for RPC connections")

	// Create and start the memory store
	memStore := store.NewMemoryJobStore()
	if err := memStore.Start(); err != nil {
		return err
	}
	defer func() {
		if err := memStore.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop memory store")
		}
	}()

	// Create server with store
	jobServer := server.NewServer(memStore)

	// Build handler chain: CORS -> Auth -> Connect handlers
	var handler http.Handler = jobServer.Handler(log)

	// Add JWT auth middleware unless disabled
	if !s.NoAuth {
		jwtAuthFunc, err := auth.NewJWTAuthFunc()
		if err != nil {
			return fmt.Errorf("failed to initialize JWT auth: %w", err)
		}
		middleware := authn.NewMiddleware(jwtAuthFunc)
		handler = middleware.Wrap(handler)
		log.Info().Msg("JWT authentication enabled")
	} else {
		log.Warn().Msg("JWT authentication disabled")
	}

	// Add CORS
	handler = withCORS(s.Hostname, handler)

	httpServer := &http.Server{
		Addr:              s.Listen,
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	if s.Cert != "" && s.Key != "" {
		return httpServer.ListenAndServeTLS(s.Cert, s.Key)
	}

	cert, err := autossl.GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate ssl cert: %w", err)
	}

	// print the cert fingerprint
	fingerprint := sha256.Sum256(cert.Certificate[0])
	log.Info().
		Str("fingerprint", fmt.Sprintf("%x", fingerprint)).
		Msg("generated self-signed certificate")

	httpServer.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return httpServer.ListenAndServeTLS("", "")
}

// withCORS adds CORS support to a Connect HTTP handler.
func withCORS(hostname string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins: []string{hostname},
		AllowedMethods: connectcors.AllowedMethods(),
		AllowedHeaders: append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders: connectcors.ExposedHeaders(),
	})
	return middleware.Handler(h)
}
```

Note: The CORS configuration includes `Authorization` in `AllowedHeaders` to support browser-based clients.

## Configuration

### Environment Variables

Set by ECS task definition `secrets` block:
- `JWT_PUBLIC_KEY`: PEM-encoded ECDSA public key for verification (server)

For token issuance (admin/CLI tools only):
- `JWT_SIGNING_KEY`: PEM-encoded ECDSA private key

### Development

For local development without authentication:

```bash
./bin/airunner-server rpc --no-auth
```

### Token Lifetime

Recommend 1 hour expiration for API access tokens. Clients must refresh periodically or use a token endpoint.

## Usage

### Accessing Auth Info in Handlers

Handlers can access the authenticated subject via `authn.GetInfo(ctx)`:

```go
func (s *JobServer) EnqueueJob(ctx context.Context, req *connect.Request[jobv1.EnqueueJobRequest]) (*connect.Response[jobv1.EnqueueJobResponse], error) {
    subject, ok := authn.GetInfo(ctx).(string)
    if ok {
        log.Info().Str("subject", subject).Msg("authenticated request")
    }
    // ... handle request
}
```

### Client Example

```bash
# Obtain token from admin/token endpoint or generate locally
TOKEN=$(go run ./cmd/admin token --subject="service-a" --ttl=1h)

# Use in API request
grpcurl -H "Authorization: Bearer $TOKEN" \
  localhost:8993 job.v1.JobService/ListJobs
```

## Security Considerations

- **Key Rotation**: Update SSM parameters, redeploy ECS tasks (no code changes needed)
- **Key Storage**: Private key stored as SecureString in SSM (encrypted at rest)
- **Transport**: All traffic requires TLS (enforced by Connect server)
- **Validation**: Token signature and expiration verified on every request
- **Separation**: Private key only deployed to token issuers, not RPC servers

## Error Handling

- Missing Authorization header: `UNAUTHENTICATED` (401)
- Invalid token format: `UNAUTHENTICATED` (401)
- Signature verification failure: `UNAUTHENTICATED` (401)
- Token expiration: `UNAUTHENTICATED` (401)
- Parse errors: Logged at DEBUG level, return generic 401 to client

## Future Enhancements

- Add `aud` (audience) claim validation for multi-service deployments
- Add `iss` (issuer) claim validation for external token sources
- Implement token refresh endpoint
- Add key versioning with `kid` header for zero-downtime rotation
- Support multiple public keys simultaneously during rotation window
