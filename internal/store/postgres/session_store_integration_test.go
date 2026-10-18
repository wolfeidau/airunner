//go:build integration

package postgres_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
)

func seedSessions(t *testing.T, s *postgrestest.Stores, fx postgrestest.Fixture, expired, live int) {
	t.Helper()
	ctx := context.Background()
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO sessions (session_id, principal_id, org_id, created_at, expires_at, last_used_at)
		SELECT gen_random_uuid(), $1, $2, now() - interval '2 days', now() - interval '1 hour' - (g || ' seconds')::interval, now()
		FROM generate_series(1, $3) g`, fx.User.PrincipalID, fx.User.OrgID, expired)
	require.NoError(t, err)
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO sessions (session_id, principal_id, org_id, created_at, expires_at, last_used_at)
		SELECT gen_random_uuid(), $1, $2, now(), now() + interval '1 hour', now()
		FROM generate_series(1, $3)`, fx.User.PrincipalID, fx.User.OrgID, live)
	require.NoError(t, err)
}

func countSessions(t *testing.T, s *postgrestest.Stores) int {
	t.Helper()
	var n int
	require.NoError(t, s.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions`).Scan(&n))
	return n
}

func TestSessionStore_DeleteExpired_Batches(t *testing.T) {
	ctx := context.Background()
	s := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, s)
	sessions := postgres.NewSessionStore(s.Pool)
	seedSessions(t, s, fx, 2500, 3)

	_, err := sessions.DeleteExpired(ctx, 0)
	require.Error(t, err)

	for _, want := range []int{1000, 1000, 500, 0} {
		n, err := sessions.DeleteExpired(ctx, 1000)
		require.NoError(t, err)
		require.Equal(t, want, n)
	}
	require.Equal(t, 3, countSessions(t, s))
}

func TestRunSessionSweeper(t *testing.T) {
	s := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, s)
	sessions := postgres.NewSessionStore(s.Pool)
	seedSessions(t, s, fx, 2500, 3)

	var deleted atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		postgres.RunSessionSweeper(ctx, sessions, 50*time.Millisecond, 1000, 10, func(n int) { deleted.Add(int64(n)) })
	}()

	require.Eventually(t, func() bool { return countSessions(t, s) == 3 }, 5*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool { return deleted.Load() == 2500 }, time.Second, 10*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sweeper did not return after cancel")
	}
}
