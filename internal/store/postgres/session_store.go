package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// SessionStore implements store.SessionStore using PostgreSQL.
type SessionStore struct {
	pool *pgxpool.Pool
}

// NewSessionStore creates a new PostgreSQL-backed session store.
func NewSessionStore(pool *pgxpool.Pool) *SessionStore {
	return &SessionStore{
		pool: pool,
	}
}

// Create creates a new session in the database.
func (s *SessionStore) Create(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (
			session_id, principal_id, org_id,
			created_at, expires_at, last_used_at,
			user_agent, ip_address
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8::inet
		)
	`

	// Convert empty IP address to nil for proper INET handling
	var ipAddress any
	if session.IPAddress == "" {
		ipAddress = nil
	} else {
		ipAddress = session.IPAddress
	}

	_, err := s.pool.Exec(ctx, query,
		session.SessionID,
		session.PrincipalID,
		session.OrgID,
		session.CreatedAt,
		session.ExpiresAt,
		session.LastUsedAt,
		session.UserAgent,
		ipAddress,
	)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	log.Debug().
		Str("session_id", session.SessionID.String()).
		Str("principal_id", session.PrincipalID.String()).
		Msg("Created session")

	return nil
}

// Get retrieves a session by ID.
func (s *SessionStore) Get(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	query := `
		SELECT
			session_id, principal_id, org_id,
			created_at, expires_at, last_used_at,
			user_agent, ip_address
		FROM sessions
		WHERE session_id = $1
	`

	var session models.Session
	var ipAddress any
	err := s.pool.QueryRow(ctx, query, sessionID).Scan(
		&session.SessionID,
		&session.PrincipalID,
		&session.OrgID,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.LastUsedAt,
		&session.UserAgent,
		&ipAddress,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Convert INET to string
	if ipAddress != nil {
		session.IPAddress = fmt.Sprintf("%v", ipAddress)
	}

	// Check if session has expired
	if session.IsExpired() {
		return nil, store.ErrSessionExpired
	}

	return &session, nil
}

// UpdateLastUsed updates the last_used_at timestamp for a session.
func (s *SessionStore) UpdateLastUsed(ctx context.Context, sessionID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET last_used_at = $2
		WHERE session_id = $1
	`

	result, err := s.pool.Exec(ctx, query, sessionID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update session last_used_at: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrSessionNotFound
	}

	return nil
}

// Delete deletes a session by ID (logout).
func (s *SessionStore) Delete(ctx context.Context, sessionID uuid.UUID) error {
	query := `DELETE FROM sessions WHERE session_id = $1`

	result, err := s.pool.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	if result.RowsAffected() == 0 {
		return store.ErrSessionNotFound
	}

	log.Debug().
		Str("session_id", sessionID.String()).
		Msg("Deleted session")

	return nil
}

// DeleteByPrincipal deletes all sessions for a principal (logout everywhere).
func (s *SessionStore) DeleteByPrincipal(ctx context.Context, principalID uuid.UUID) (int, error) {
	query := `DELETE FROM sessions WHERE principal_id = $1`

	result, err := s.pool.Exec(ctx, query, principalID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete sessions by principal: %w", err)
	}

	count := int(result.RowsAffected())

	log.Info().
		Str("principal_id", principalID.String()).
		Int("count", count).
		Msg("Deleted all sessions for principal")

	return count, nil
}

// DeleteExpired deletes all expired sessions (cleanup job).
func (s *SessionStore) DeleteExpired(ctx context.Context) (int, error) {
	query := `DELETE FROM sessions WHERE expires_at < $1`

	result, err := s.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	count := int(result.RowsAffected())

	if count > 0 {
		log.Info().
			Int("count", count).
			Msg("Deleted expired sessions")
	}

	return count, nil
}
