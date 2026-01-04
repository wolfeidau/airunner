package models

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a user's authenticated session.
// The session ID is stored in an opaque cookie, while all session data lives server-side.
type Session struct {
	SessionID   uuid.UUID // UUIDv7 - this is the only value stored in the cookie
	PrincipalID uuid.UUID // Who is logged in
	OrgID       uuid.UUID // Denormalized for fast JWT claims

	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time

	// Optional audit metadata
	UserAgent string
	IPAddress string
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
