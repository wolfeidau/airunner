package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// SessionStore implements store.SessionStore using in-memory storage.
// This implementation is for testing only - data is lost on restart.
type SessionStore struct {
	mu sync.RWMutex

	sessions            map[uuid.UUID]*models.Session // session_id -> Session
	sessionsByPrincipal map[uuid.UUID][]uuid.UUID     // principal_id -> []session_id
}

// NewSessionStore creates a new in-memory session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:            make(map[uuid.UUID]*models.Session),
		sessionsByPrincipal: make(map[uuid.UUID][]uuid.UUID),
	}
}

// Create creates a new session in memory.
func (s *SessionStore) Create(ctx context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clone to avoid external modifications
	clone := *session
	s.sessions[session.SessionID] = &clone

	// Update principal index
	s.sessionsByPrincipal[session.PrincipalID] = append(
		s.sessionsByPrincipal[session.PrincipalID],
		session.SessionID,
	)

	return nil
}

// Get retrieves a session by ID.
func (s *SessionStore) Get(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, store.ErrSessionNotFound
	}

	// Check if session has expired
	if session.IsExpired() {
		return nil, store.ErrSessionExpired
	}

	// Clone to avoid external modifications
	clone := *session
	return &clone, nil
}

// UpdateLastUsed updates the last_used_at timestamp for a session.
func (s *SessionStore) UpdateLastUsed(ctx context.Context, sessionID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return store.ErrSessionNotFound
	}

	session.LastUsedAt = time.Now()
	return nil
}

// Delete deletes a session by ID (logout).
func (s *SessionStore) Delete(ctx context.Context, sessionID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return store.ErrSessionNotFound
	}

	// Remove from principal index
	s.removeFromPrincipalIndex(session.PrincipalID, sessionID)

	// Remove from main map
	delete(s.sessions, sessionID)

	return nil
}

// DeleteByPrincipal deletes all sessions for a principal (logout everywhere).
func (s *SessionStore) DeleteByPrincipal(ctx context.Context, principalID uuid.UUID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionIDs, exists := s.sessionsByPrincipal[principalID]
	if !exists {
		return 0, nil
	}

	count := len(sessionIDs)

	// Delete all sessions
	for _, sessionID := range sessionIDs {
		delete(s.sessions, sessionID)
	}

	// Clear index
	delete(s.sessionsByPrincipal, principalID)

	return count, nil
}

// DeleteExpired deletes all expired sessions (cleanup job).
func (s *SessionStore) DeleteExpired(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toDelete []uuid.UUID
	now := time.Now()

	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			toDelete = append(toDelete, id)
		}
	}

	for _, sessionID := range toDelete {
		session := s.sessions[sessionID]
		s.removeFromPrincipalIndex(session.PrincipalID, sessionID)
		delete(s.sessions, sessionID)
	}

	return len(toDelete), nil
}

// removeFromPrincipalIndex removes a session ID from the principal's session list.
func (s *SessionStore) removeFromPrincipalIndex(principalID, sessionID uuid.UUID) {
	sessionIDs := s.sessionsByPrincipal[principalID]
	for i, id := range sessionIDs {
		if id == sessionID {
			s.sessionsByPrincipal[principalID] = append(sessionIDs[:i], sessionIDs[i+1:]...)
			break
		}
	}
	// Clean up empty entries
	if len(s.sessionsByPrincipal[principalID]) == 0 {
		delete(s.sessionsByPrincipal, principalID)
	}
}
