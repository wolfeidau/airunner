package oidc

import (
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/login"
)

// SessionAdapter adapts the login.Github session management to the OIDC SessionManager interface.
// With server-side sessions, the session already contains the principal ID, so no additional lookup is needed.
type SessionAdapter struct {
	gh *login.Github
}

// NewSessionAdapter creates a new session adapter.
func NewSessionAdapter(gh *login.Github) *SessionAdapter {
	return &SessionAdapter{
		gh: gh,
	}
}

// GetSession retrieves the current user's session from the request.
// Returns nil if the session is invalid or expired.
func (s *SessionAdapter) GetSession(r *http.Request) *Session {
	sessionData, err := s.gh.GetSession(r)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get session")
		return nil
	}

	return &Session{
		PrincipalID: sessionData.PrincipalID,
	}
}
