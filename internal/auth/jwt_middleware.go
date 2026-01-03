package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Principal represents an authenticated principal from a JWT.
// This is added to the request context after successful JWT verification.
type Principal struct {
	PrincipalID uuid.UUID
	OrgID       uuid.UUID
	Roles       []string
	Type        string // "user" or "worker"
	Fingerprint string // Only for worker JWTs
}

type contextKey int

const (
	principalContextKey contextKey = iota
)

// PrincipalFromContext extracts the authenticated principal from the request context.
// Returns nil if no principal is present (unauthenticated request).
func PrincipalFromContext(ctx context.Context) *Principal {
	principal, _ := ctx.Value(principalContextKey).(*Principal)
	return principal
}

// PublicKeyCache provides access to public keys for JWT verification.
// The cache fetches website public keys from JWKS endpoints and worker public keys from the database.
type PublicKeyCache interface {
	// GetWebsiteKey fetches the website's public key by kid from the JWKS endpoint
	GetWebsiteKey(ctx context.Context, jwksURL, kid string) (*ecdsa.PublicKey, error)

	// GetWorkerKey fetches a worker's public key by fingerprint from the cache/database
	GetWorkerKey(ctx context.Context, fingerprint string) (*ecdsa.PublicKey, error)
}

// RevocationChecker provides access to the revocation blocklist.
type RevocationChecker interface {
	// IsRevoked checks if a worker credential fingerprint is revoked
	IsRevoked(ctx context.Context, fingerprint string) bool
}

// JWTVerifier handles JWT verification for both user and worker tokens.
// It supports updating the website URL after creation, which is useful for testing
// with dynamically-created test servers.
type JWTVerifier struct {
	websiteBaseURL    string
	publicKeyCache    PublicKeyCache
	revocationChecker RevocationChecker
}

// NewJWTVerifier creates a new JWT verifier.
func NewJWTVerifier(
	websiteBaseURL string,
	publicKeyCache PublicKeyCache,
	revocationChecker RevocationChecker,
) *JWTVerifier {
	return &JWTVerifier{
		websiteBaseURL:    websiteBaseURL,
		publicKeyCache:    publicKeyCache,
		revocationChecker: revocationChecker,
	}
}

// SetWebsiteURL updates the website base URL used for user JWT verification.
// This is useful in tests where the URL is only known after creating an httptest.Server.
func (v *JWTVerifier) SetWebsiteURL(url string) {
	v.websiteBaseURL = url
}

// Middleware returns an HTTP middleware that verifies JWTs.
// It handles two types of JWTs:
//   - User JWTs: Signed by website, verified with website's public key from JWKS
//   - Worker JWTs: Self-signed by workers, verified with worker's public key from cache
func (v *JWTVerifier) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract JWT from Authorization header
			tokenString := extractBearerToken(r)
			if tokenString == "" {
				log.Warn().Msg("Missing Authorization header")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := r.Context()

			// Parse JWT header and claims (without verification)
			token, err := jwt.Parse(tokenString, nil)
			if err != nil && !errors.Is(err, jwt.ErrTokenUnverifiable) {
				log.Warn().Err(err).Msg("Failed to parse JWT")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				log.Warn().Msg("Invalid JWT claims")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			issuer, ok := claims["iss"].(string)
			if !ok || issuer == "" {
				log.Warn().Msg("Missing JWT issuer")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				log.Warn().Msg("Missing JWT kid")
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			var principal *Principal

			// Route based on issuer
			switch issuer {
			case v.websiteBaseURL:
				// ========================================
				// USER JWT (signed by website)
				// ========================================
				principal, err = verifyUserJWT(ctx, tokenString, v.websiteBaseURL, kid, v.publicKeyCache)
				if err != nil {
					log.Warn().Err(err).Msg("Failed to verify user JWT")
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

			case "airunner-cli", "airunner-worker":
				// ========================================
				// WORKER JWT (self-signed)
				// ========================================
				fingerprint := kid

				// Check revocation list FIRST
				if v.revocationChecker.IsRevoked(ctx, fingerprint) {
					log.Warn().Str("fingerprint", fingerprint).Msg("Credential revoked")
					http.Error(w, "credential revoked", http.StatusUnauthorized)
					return
				}

				principal, err = verifyWorkerJWT(ctx, tokenString, fingerprint, v.publicKeyCache)
				if err != nil {
					log.Warn().Err(err).Str("fingerprint", fingerprint).Msg("Failed to verify worker JWT")
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

			default:
				// Unknown issuer
				log.Warn().Str("issuer", issuer).Msg("Unknown JWT issuer")
				http.Error(w, "unknown issuer", http.StatusUnauthorized)
				return
			}

			// Add principal to context (NO DATABASE LOOKUP!)
			ctx = context.WithValue(ctx, principalContextKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JWTAuthMiddleware is a deprecated alias for backward compatibility.
// Use NewJWTVerifier().Middleware() instead.
func JWTAuthMiddleware(
	websiteBaseURL string,
	publicKeyCache PublicKeyCache,
	revocationChecker RevocationChecker,
) func(http.Handler) http.Handler {
	return NewJWTVerifier(websiteBaseURL, publicKeyCache, revocationChecker).Middleware()
}

// verifyUserJWT verifies a user JWT signed by the website.
func verifyUserJWT(
	ctx context.Context,
	tokenString string,
	websiteBaseURL string,
	kid string,
	publicKeyCache PublicKeyCache,
) (*Principal, error) {
	// Fetch website's public key from JWKS endpoint
	jwksURL := websiteBaseURL + "/.well-known/jwks.json"
	publicKey, err := publicKeyCache.GetWebsiteKey(ctx, jwksURL, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch website public key: %w", err)
	}

	// Verify JWT signature with website's public key
	verifiedClaims, err := verifyJWT(tokenString, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	// Extract principal from claims (user principal)
	principalID, err := parseUUID(verifiedClaims, "principal_id")
	if err != nil {
		return nil, err
	}

	orgID, err := parseUUID(verifiedClaims, "org")
	if err != nil {
		return nil, err
	}

	roles, err := parseStringSlice(verifiedClaims, "roles")
	if err != nil {
		return nil, err
	}

	return &Principal{
		PrincipalID: principalID,
		OrgID:       orgID,
		Roles:       roles,
		Type:        "user",
	}, nil
}

// verifyWorkerJWT verifies a worker JWT self-signed by a worker.
func verifyWorkerJWT(
	ctx context.Context,
	tokenString string,
	fingerprint string,
	publicKeyCache PublicKeyCache,
) (*Principal, error) {
	// Get worker's public key from cache
	publicKey, err := publicKeyCache.GetWorkerKey(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("unknown credential: %w", err)
	}

	// Verify JWT signature with worker's public key
	verifiedClaims, err := verifyJWT(tokenString, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	// Extract principal from claims (worker principal)
	principalID, err := parseUUID(verifiedClaims, "principal_id")
	if err != nil {
		return nil, err
	}

	orgID, err := parseUUID(verifiedClaims, "org")
	if err != nil {
		return nil, err
	}

	roles, err := parseStringSlice(verifiedClaims, "roles")
	if err != nil {
		return nil, err
	}

	return &Principal{
		PrincipalID: principalID,
		OrgID:       orgID,
		Roles:       roles,
		Type:        "worker",
		Fingerprint: fingerprint,
	}, nil
}

// verifyJWT verifies a JWT signature with the given public key and returns the claims.
func verifyJWT(tokenString string, publicKey *ecdsa.PublicKey) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}

// extractBearerToken extracts the JWT from the Authorization header.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// parseUUID extracts a UUID from JWT claims.
func parseUUID(claims jwt.MapClaims, key string) (uuid.UUID, error) {
	value, ok := claims[key].(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("missing or invalid %s claim", key)
	}

	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid %s UUID: %w", key, err)
	}

	return id, nil
}

// parseStringSlice extracts a string slice from JWT claims.
func parseStringSlice(claims jwt.MapClaims, key string) ([]string, error) {
	value, ok := claims[key]
	if !ok {
		return nil, fmt.Errorf("missing %s claim", key)
	}

	// Handle both []interface{} and []string
	switch v := value.(type) {
	case []any:
		result := make([]string, len(v))
		for i, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid %s claim: expected string array", key)
			}
			result[i] = str
		}
		return result, nil
	case []string:
		return v, nil
	default:
		return nil, fmt.Errorf("invalid %s claim: expected array", key)
	}
}

// ParsePublicKeyPEM parses a PEM-encoded ECDSA public key.
func ParsePublicKeyPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaPub, nil
}
