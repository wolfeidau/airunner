package auth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ErrUnauthenticated is returned when authentication fails.
var ErrUnauthenticated = errors.New("unauthenticated")

// SessionData represents session information from a session store.
// This matches the fields needed from login.SessionData.
type SessionData struct {
	SessionID   uuid.UUID
	PrincipalID uuid.UUID
	OrgID       uuid.UUID
	Roles       []string
}

// SessionProvider provides access to session data from HTTP requests.
// This interface allows the session middleware to be decoupled from the login package.
type SessionProvider interface {
	// GetSessionData extracts and validates the session from a request.
	// Returns session data including principal info, or an error if not authenticated.
	GetSessionData(r *http.Request) (*SessionData, error)
}

// SessionAuthMiddleware creates an HTTP middleware that authenticates requests
// using session cookies. It extracts the session and adds the principal to the
// request context using the same key as the JWT middleware.
//
// If authentication fails, it returns 401 Unauthorized.
func SessionAuthMiddleware(provider SessionProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get session from provider
			session, err := provider.GetSessionData(r)
			if err != nil {
				log.Debug().Err(err).Msg("Session auth: failed to get session")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Convert session to principal (same structure used by JWT middleware)
			principal := &Principal{
				PrincipalID: session.PrincipalID,
				OrgID:       session.OrgID,
				Roles:       session.Roles,
				Type:        "user", // Session auth is always for users
			}

			log.Debug().
				Str("principal_id", principal.PrincipalID.String()).
				Str("org_id", principal.OrgID.String()).
				Msg("Session auth: authenticated")

			// Add principal to context
			ctx := WithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
