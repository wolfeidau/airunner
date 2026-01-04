package credentials

import (
	"context"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
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

	log.Debug().
		Str("credName", credName).
		Str("audience", audience).
		Msg("initialized auth interceptor")

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
		// Add Authorization header to streaming requests
		if err := i.addAuthHeader(conn.RequestHeader()); err != nil {
			log.Error().Err(err).Msg("Failed to add auth header to streaming request")
		}
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

	log.Debug().
		Str("credName", i.credName).
		Time("expiry", i.tokenExpiry).
		Msg("cached new JWT token")

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
