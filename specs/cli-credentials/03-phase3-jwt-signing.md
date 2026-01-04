# Phase 3: JWT Signing and Interceptor

[← README](README.md) | [← Phase 2: CLI Commands](02-phase2-cli-commands.md)

## Goal

Implement JWT signing and a Connect RPC interceptor that automatically attaches authentication headers to all API requests.

## Prerequisites

- [Phase 1: Local Storage](01-phase1-local-storage.md) completed
- [Phase 2: CLI Commands](02-phase2-cli-commands.md) completed
- Understanding of JWT structure from [Architecture](00-architecture.md)

## Success Criteria

- [ ] `JWTSigner` creates valid ES256 JWTs with correct claims
- [ ] JWT `kid` header matches credential fingerprint
- [ ] Tokens expire after 1 hour
- [ ] `AuthInterceptor` attaches Authorization header to all requests
- [ ] Existing commands (`worker`, `submit`, `list`, `monitor`) accept `--credential` flag
- [ ] Commands use default credential when `--credential` not specified
- [ ] Clear error when credential not imported

## Files to Create

1. `cmd/cli/internal/credentials/jwt.go` - JWT creation and signing
2. `cmd/cli/internal/credentials/interceptor.go` - Connect RPC auth interceptor

## JWT Signer

`cmd/cli/internal/credentials/jwt.go`:

```go
package credentials

import (
    "crypto/ecdsa"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

const (
    // TokenExpiry is the duration after which a token expires.
    TokenExpiry = 1 * time.Hour

    // Issuer identifies tokens as CLI-generated.
    Issuer = "airunner-cli"
)

// JWTSigner creates and signs JWTs for API authentication.
type JWTSigner struct {
    store *Store
}

// NewJWTSigner creates a new JWT signer.
func NewJWTSigner(store *Store) *JWTSigner {
    return &JWTSigner{store: store}
}

// Claims represents the JWT claims for worker authentication.
type Claims struct {
    jwt.RegisteredClaims
    Org         string   `json:"org"`
    Roles       []string `json:"roles"`
    PrincipalID string   `json:"principal_id"`
}

// SignToken creates a signed JWT for the specified credential.
// Returns an error if the credential is not imported.
func (s *JWTSigner) SignToken(credName string, audience string) (string, error) {
    // Load credential metadata
    cred, err := s.store.Get(credName)
    if err != nil {
        return "", err
    }

    // Verify credential is imported
    if !cred.IsImported() {
        return "", fmt.Errorf("%w: credential %q has not been imported to the server\n\n"+
            "To import:\n"+
            "  1. Copy the public key: airunner-cli credentials show %s\n"+
            "  2. Import via web UI\n"+
            "  3. Update: airunner-cli credentials update %s --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>",
            ErrCredentialNotImported, credName, credName, credName)
    }

    // Load private key
    privateKey, err := s.store.LoadPrivateKey(credName)
    if err != nil {
        return "", fmt.Errorf("failed to load private key: %w", err)
    }

    // Create token
    now := time.Now()
    claims := Claims{
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    Issuer,
            Subject:   cred.Fingerprint, // Subject is the key fingerprint
            Audience:  jwt.ClaimStrings{audience},
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiry)),
        },
        Org:         cred.OrgID,
        Roles:       []string{"worker"},
        PrincipalID: cred.PrincipalID,
    }

    token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

    // Set kid header to fingerprint (server uses this to look up public key)
    token.Header["kid"] = cred.Fingerprint

    // Sign with private key
    tokenString, err := token.SignedString(privateKey)
    if err != nil {
        return "", fmt.Errorf("failed to sign token: %w", err)
    }

    return tokenString, nil
}

// SignTokenWithKey creates a signed JWT using a provided private key.
// Used primarily for testing.
func SignTokenWithKey(
    privateKey *ecdsa.PrivateKey,
    fingerprint string,
    orgID string,
    principalID string,
    audience string,
) (string, error) {
    now := time.Now()
    claims := Claims{
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    Issuer,
            Subject:   fingerprint,
            Audience:  jwt.ClaimStrings{audience},
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiry)),
        },
        Org:         orgID,
        Roles:       []string{"worker"},
        PrincipalID: principalID,
    }

    token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
    token.Header["kid"] = fingerprint

    return token.SignedString(privateKey)
}
```

## Auth Interceptor

`cmd/cli/internal/credentials/interceptor.go`:

```go
package credentials

import (
    "context"
    "fmt"
    "sync"
    "time"

    "connectrpc.com/connect"
)

// AuthInterceptor adds JWT authentication to Connect RPC requests.
type AuthInterceptor struct {
    signer   *JWTSigner
    credName string
    audience string

    // Token caching
    mu          sync.RWMutex
    cachedToken string
    tokenExpiry time.Time
}

// NewAuthInterceptor creates an interceptor that authenticates requests.
// credName is the credential to use (empty string uses default).
// audience is the server URL (used in JWT aud claim).
func NewAuthInterceptor(store *Store, credName string, audience string) (*AuthInterceptor, error) {
    // Resolve credential name
    if credName == "" {
        defaultCred, err := store.GetDefault()
        if err != nil {
            if err == ErrNoDefaultCredential {
                return nil, fmt.Errorf("no credential specified and no default set\n\n" +
                    "Either specify a credential with --credential or set a default:\n" +
                    "  airunner-cli credentials set-default <name>")
            }
            return nil, fmt.Errorf("failed to get default credential: %w", err)
        }
        credName = defaultCred.Name
    }

    // Verify credential exists
    if _, err := store.Get(credName); err != nil {
        return nil, err
    }

    return &AuthInterceptor{
        signer:   NewJWTSigner(store),
        credName: credName,
        audience: audience,
    }, nil
}

// WrapUnary implements connect.UnaryInterceptorFunc.
func (i *AuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
    return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
        if err := i.addAuthHeader(req.Header()); err != nil {
            return nil, connect.NewError(connect.CodeUnauthenticated, err)
        }
        return next(ctx, req)
    }
}

// WrapStreamingClient implements connect.StreamingClientInterceptorFunc.
func (i *AuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
    return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
        conn := next(ctx, spec)
        // Note: For streaming, headers are sent with the initial request.
        // We need to add auth before the stream is established.
        // This is handled by the transport, not here.
        return conn
    }
}

// WrapStreamingHandler is not used for client interceptors.
func (i *AuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
    return next
}

// addAuthHeader adds the Authorization header with a valid JWT.
func (i *AuthInterceptor) addAuthHeader(headers interface{ Set(string, string) }) error {
    token, err := i.getToken()
    if err != nil {
        return err
    }
    headers.Set("Authorization", "Bearer "+token)
    return nil
}

// getToken returns a cached token or creates a new one.
func (i *AuthInterceptor) getToken() (string, error) {
    i.mu.RLock()
    if i.cachedToken != "" && time.Now().Add(5*time.Minute).Before(i.tokenExpiry) {
        // Token is valid for at least 5 more minutes
        token := i.cachedToken
        i.mu.RUnlock()
        return token, nil
    }
    i.mu.RUnlock()

    // Need to refresh token
    i.mu.Lock()
    defer i.mu.Unlock()

    // Double-check after acquiring write lock
    if i.cachedToken != "" && time.Now().Add(5*time.Minute).Before(i.tokenExpiry) {
        return i.cachedToken, nil
    }

    // Sign new token
    token, err := i.signer.SignToken(i.credName, i.audience)
    if err != nil {
        return "", err
    }

    i.cachedToken = token
    i.tokenExpiry = time.Now().Add(TokenExpiry)

    return token, nil
}

// GetAuthorizationHeader returns the Authorization header value for streaming requests.
// Use this when establishing streaming connections.
func (i *AuthInterceptor) GetAuthorizationHeader() (string, error) {
    token, err := i.getToken()
    if err != nil {
        return "", err
    }
    return "Bearer " + token, nil
}
```

## Update Existing Commands

Add `--credential` flag to `WorkerCmd`, `SubmitCmd`, `MonitorCmd`, and `ListCmd`:

### Worker Command Update

```go
// cmd/cli/internal/commands/worker.go

type WorkerCmd struct {
    Server     string `help:"Server URL" default:"https://localhost"`
    Queue      string `help:"Queue name" default:"default"`
    Credential string `help:"Credential name (uses default if not specified)"`
    // ... existing fields
}

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
    // Initialize credential store and interceptor
    store, err := credentials.NewStore("")
    if err != nil {
        return fmt.Errorf("failed to initialize credentials: %w", err)
    }

    authInterceptor, err := credentials.NewAuthInterceptor(store, w.Credential, w.Server)
    if err != nil {
        return err
    }

    otelInterceptor, err := otelconnect.NewInterceptor()
    if err != nil {
        return fmt.Errorf("failed to create otel interceptor: %w", err)
    }

    // Create clients with both interceptors
    config := client.Config{
        ServerURL: w.Server,
        Timeout:   w.Timeout,
        Debug:     globals.Debug,
    }
    clients, err := client.NewClients(config,
        connect.WithInterceptors(authInterceptor),
        connect.WithInterceptors(otelInterceptor),
    )
    if err != nil {
        return fmt.Errorf("failed to create clients: %w", err)
    }

    // ... rest of worker logic
}
```

### Submit Command Update

```go
// cmd/cli/internal/commands/submit.go

type SubmitCmd struct {
    Server     string `help:"Server URL" default:"https://localhost"`
    Queue      string `help:"Queue name" default:"default"`
    Credential string `help:"Credential name (uses default if not specified)"`
    // ... existing fields
}

func (s *SubmitCmd) Run(ctx context.Context, globals *Globals) error {
    // Load config file first if provided
    if s.Config != "" {
        if err := s.loadConfigFile(); err != nil {
            return fmt.Errorf("failed to load config file: %w", err)
        }
    }

    // Initialize credential store and interceptor
    store, err := credentials.NewStore("")
    if err != nil {
        return fmt.Errorf("failed to initialize credentials: %w", err)
    }

    authInterceptor, err := credentials.NewAuthInterceptor(store, s.Credential, s.Server)
    if err != nil {
        return err
    }

    otelInterceptor, err := otelconnect.NewInterceptor()
    if err != nil {
        return fmt.Errorf("failed to create otel interceptor: %w", err)
    }

    // Create clients with auth
    config := client.Config{
        ServerURL: s.Server,
        Timeout:   s.Timeout,
        Debug:     globals.Debug,
    }
    clients, err := client.NewClients(config,
        connect.WithInterceptors(authInterceptor),
        connect.WithInterceptors(otelInterceptor),
    )
    if err != nil {
        return fmt.Errorf("failed to create clients: %w", err)
    }

    // ... rest of submit logic
}
```

Similar updates needed for `MonitorCmd` and `ListCmd`.

## Testing

Create `cmd/cli/internal/credentials/jwt_test.go`:

```go
func TestJWTSigner_SignToken(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := credentials.NewStore(tmpDir)

    // Create and import credential
    cred, err := store.Create("test-workers")
    require.NoError(t, err)

    err = store.Update("test-workers", "org-123", "principal-456")
    require.NoError(t, err)

    // Sign token
    signer := credentials.NewJWTSigner(store)
    token, err := signer.SignToken("test-workers", "https://api.example.com")
    require.NoError(t, err)
    assert.NotEmpty(t, token)

    // Parse and verify claims
    parser := jwt.NewParser()
    parsed, _, err := parser.ParseUnverified(token, &credentials.Claims{})
    require.NoError(t, err)

    claims := parsed.Claims.(*credentials.Claims)
    assert.Equal(t, "airunner-cli", claims.Issuer)
    assert.Equal(t, cred.Fingerprint, claims.Subject)
    assert.Equal(t, "org-123", claims.Org)
    assert.Equal(t, "principal-456", claims.PrincipalID)
    assert.Equal(t, []string{"worker"}, claims.Roles)

    // Verify kid header
    assert.Equal(t, cred.Fingerprint, parsed.Header["kid"])
}

func TestJWTSigner_NotImported(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := credentials.NewStore(tmpDir)

    // Create but don't import
    _, err := store.Create("test-workers")
    require.NoError(t, err)

    signer := credentials.NewJWTSigner(store)
    _, err = signer.SignToken("test-workers", "https://api.example.com")
    assert.ErrorIs(t, err, credentials.ErrCredentialNotImported)
}
```

Create `cmd/cli/internal/credentials/interceptor_test.go`:

```go
func TestAuthInterceptor_TokenCaching(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := credentials.NewStore(tmpDir)

    _, _ = store.Create("test-workers")
    _ = store.Update("test-workers", "org-123", "principal-456")

    interceptor, err := credentials.NewAuthInterceptor(store, "test-workers", "https://api.example.com")
    require.NoError(t, err)

    // Get token twice - should return same cached token
    header1, err := interceptor.GetAuthorizationHeader()
    require.NoError(t, err)

    header2, err := interceptor.GetAuthorizationHeader()
    require.NoError(t, err)

    assert.Equal(t, header1, header2)
}

func TestAuthInterceptor_NoDefault(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := credentials.NewStore(tmpDir)

    // No credentials created, no default set
    _, err := credentials.NewAuthInterceptor(store, "", "https://api.example.com")
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "no credential specified")
}
```

## Integration Test

Test the full flow against a running server:

```go
func TestAuthInterceptor_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Setup: create credential and import to server
    tmpDir := t.TempDir()
    store, _ := credentials.NewStore(tmpDir)
    cred, _ := store.Create("integration-test")

    // Import to server (requires running server with session auth)
    // This part would be done via web UI in practice

    // After import, update local credential
    _ = store.Update("integration-test", "test-org-id", "test-principal-id")

    // Create interceptor
    interceptor, err := credentials.NewAuthInterceptor(store, "integration-test", "https://localhost:8993")
    require.NoError(t, err)

    // Create client with interceptor
    config := client.Config{
        ServerURL: "https://localhost:8993",
    }
    clients, err := client.NewClients(config, connect.WithInterceptors(interceptor))
    require.NoError(t, err)

    // Make authenticated request
    resp, err := clients.Job.ListJobs(context.Background(), connect.NewRequest(&jobv1.ListJobsRequest{}))
    require.NoError(t, err)
    assert.NotNil(t, resp)
}
```

## Verification

After implementing:

```bash
# Build CLI
make build-cli

# Setup credential
./bin/airunner-cli init test-cred
# (import via web UI)
./bin/airunner-cli credentials update test-cred --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>

# Test authenticated commands
./bin/airunner-cli list --server=https://localhost:8993 --credential test-cred

# Test with default credential
./bin/airunner-cli credentials set-default test-cred
./bin/airunner-cli list --server=https://localhost:8993

# Test error when not imported
./bin/airunner-cli init unimported-cred
./bin/airunner-cli list --credential unimported-cred
# Should show: credential "unimported-cred" has not been imported to the server

# Run tests
go test ./cmd/cli/internal/credentials/...
```

---

[← README](README.md) | [← Phase 2: CLI Commands](02-phase2-cli-commands.md)
