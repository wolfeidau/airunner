package auth

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// DualAuthMiddleware creates an HTTP middleware that supports both JWT and session authentication.
// It tries JWT first (from Authorization header), then falls back to session (from cookie).
// This allows both programmatic access (CLI/workers with JWT) and browser access (session cookies).
func DualAuthMiddleware(
	jwtVerifier *JWTVerifier,
	sessionProvider SessionProvider,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check for Authorization header first (JWT auth)
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				// Try JWT authentication
				principal, err := jwtVerifier.VerifyRequest(r)
				if err != nil {
					log.Debug().Err(err).Msg("Dual auth: JWT verification failed")
					// Don't fall back to session if JWT was provided but invalid
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}

				log.Debug().
					Str("principal_id", principal.PrincipalID.String()).
					Str("type", principal.Type).
					Msg("Dual auth: JWT authenticated")

				ctx = WithPrincipal(ctx, principal)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No JWT provided, try session authentication
			session, err := sessionProvider.GetSessionData(r)
			if err != nil {
				log.Debug().Err(err).Msg("Dual auth: session authentication failed")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Convert session to principal
			principal := &Principal{
				PrincipalID: session.PrincipalID,
				OrgID:       session.OrgID,
				Roles:       session.Roles,
				Type:        "user",
			}

			log.Debug().
				Str("principal_id", principal.PrincipalID.String()).
				Msg("Dual auth: session authenticated")

			ctx = WithPrincipal(ctx, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
