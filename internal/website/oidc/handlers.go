package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/store"
)

// Handler provides OIDC endpoints for the website server.
// The website acts as an OpenID Connect (OIDC) provider.
type Handler struct {
	keyManager     *KeyManager
	principalStore store.PrincipalStore
	baseURL        string // Base URL for the website (e.g., "https://website.airunner.dev")
}

// NewHandler creates a new OIDC handler with the given key manager and base URL.
func NewHandler(keyManager *KeyManager, principalStore store.PrincipalStore, baseURL string) *Handler {
	return &Handler{
		keyManager:     keyManager,
		principalStore: principalStore,
		baseURL:        baseURL,
	}
}

// DiscoveryHandler returns the OIDC discovery document at /.well-known/openid-configuration
// This endpoint allows API servers to discover the JWKS endpoint and supported features.
func (h *Handler) DiscoveryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Msg("OIDC discovery request")

		config := map[string]any{
			"issuer":                                h.baseURL,
			"jwks_uri":                              h.baseURL + "/.well-known/jwks.json",
			"token_endpoint":                        h.baseURL + "/auth/token",
			"response_types_supported":              []string{"token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 24 hours
		if err := json.NewEncoder(w).Encode(config); err != nil {
			log.Error().Err(err).Msg("Failed to encode OIDC discovery response")
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

// JWKSHandler returns the website's public key in JWKS format at /.well-known/jwks.json
// API servers use this endpoint to fetch the public key for verifying user JWTs.
func (h *Handler) JWKSHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Str("kid", h.keyManager.Kid()).Msg("JWKS request")

		jwks := map[string]any{
			"keys": []any{h.keyManager.JWK()},
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			log.Error().Err(err).Msg("Failed to encode JWKS response")
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

// SessionManager is an interface for session management.
// This allows the handler to retrieve the current user from the session.
type SessionManager interface {
	GetSession(r *http.Request) *Session
}

// Session represents an authenticated user session.
type Session struct {
	PrincipalID uuid.UUID
}

// TokenHandler issues a JWT for the currently logged-in user at POST /auth/token
// The frontend calls this endpoint after logging in via GitHub OAuth to get a JWT for API calls.
func (h *Handler) TokenHandler(sessionManager SessionManager, apiBaseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Msg("Token request")

		// Get user from session
		session := sessionManager.GetSession(r)
		if session == nil {
			log.Warn().Msg("Token request without valid session")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Look up user principal
		ctx := r.Context()
		principal, err := h.principalStore.Get(ctx, session.PrincipalID)
		if err != nil {
			log.Error().Err(err).Str("principal_id", session.PrincipalID.String()).Msg("Failed to get principal")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Create JWT claims
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":          h.baseURL,
			"sub":          principal.PrincipalID.String(),
			"aud":          apiBaseURL,
			"org":          principal.OrgID.String(),
			"roles":        principal.Roles,
			"principal_id": principal.PrincipalID.String(),
			"iat":          now.Unix(),
			"exp":          now.Add(1 * time.Hour).Unix(),
		}

		// Sign with website's private key
		tokenString, err := h.keyManager.SignJWT(claims)
		if err != nil {
			log.Error().Err(err).Msg("Failed to sign JWT")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		log.Info().
			Str("principal_id", principal.PrincipalID.String()).
			Str("org_id", principal.OrgID.String()).
			Msg("Issued user JWT")

		// Return JWT to frontend
		response := map[string]string{
			"access_token": tokenString,
			"token_type":   "Bearer",
			"expires_in":   fmt.Sprintf("%d", 3600),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error().Err(err).Msg("Failed to encode token response")
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
