package memory

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/models"
)

func TestSessionStore_DeleteExpired_Limit(t *testing.T) {
	ctx := context.Background()
	s := NewSessionStore()
	principal := uuid.New()

	add := func(exp time.Time) {
		require.NoError(t, s.Create(ctx, &models.Session{
			SessionID:   uuid.New(),
			PrincipalID: principal,
			OrgID:       uuid.New(),
			CreatedAt:   time.Now(),
			ExpiresAt:   exp,
			LastUsedAt:  time.Now(),
		}))
	}
	for i := 0; i < 5; i++ {
		add(time.Now().Add(-time.Hour))
	}
	add(time.Now().Add(time.Hour))

	_, err := s.DeleteExpired(ctx, 0)
	require.Error(t, err)

	for _, want := range []int{2, 2, 1, 0} {
		n, err := s.DeleteExpired(ctx, 2)
		require.NoError(t, err)
		require.Equal(t, want, n)
	}
	require.Len(t, s.sessions, 1)
	require.Len(t, s.sessionsByPrincipal[principal], 1)
}
