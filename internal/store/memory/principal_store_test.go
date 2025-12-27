package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/store"
)

func TestNewPrincipalStore(t *testing.T) {
	st := NewPrincipalStore()
	require.NotNil(t, st)
}

func TestMemoryPrincipalStore_Create(t *testing.T) {
	t.Run("create new principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		err := st.Create(ctx, principal)
		require.NoError(t, err)
	})

	t.Run("create duplicate principal returns error", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		err := st.Create(ctx, principal)
		require.NoError(t, err)

		err = st.Create(ctx, principal)
		require.Error(t, err)
		require.Equal(t, store.ErrPrincipalAlreadyExists, err)
	})

	t.Run("create principal with metadata", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID:     "user-123",
			Type:            store.PrincipalTypeUser,
			Status:          store.PrincipalStatusActive,
			CreatedAt:       time.Now(),
			CreatedBy:       "admin",
			Email:           "user@example.com",
			Description:     "Test user",
			MaxCertificates: 5,
			Metadata: map[string]string{
				"team": "backend",
			},
		}

		err := st.Create(ctx, principal)
		require.NoError(t, err)

		retrieved, err := st.Get(ctx, "user-123")
		require.NoError(t, err)
		require.Equal(t, principal.Email, retrieved.Email)
		require.Equal(t, principal.Metadata["team"], retrieved.Metadata["team"])
	})
}

func TestMemoryPrincipalStore_Get(t *testing.T) {
	t.Run("get existing principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, st.Create(ctx, principal))

		retrieved, err := st.Get(ctx, "user-123")
		require.NoError(t, err)
		require.Equal(t, principal.PrincipalID, retrieved.PrincipalID)
		require.Equal(t, principal.Type, retrieved.Type)
	})

	t.Run("get nonexistent principal returns error", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		_, err := st.Get(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, store.ErrPrincipalNotFound, err)
	})

	t.Run("get returns copy of principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
			Metadata: map[string]string{
				"key": "value",
			},
		}

		require.NoError(t, st.Create(ctx, principal))

		retrieved1, _ := st.Get(ctx, "user-123")
		retrieved1.Metadata["key"] = "modified"

		retrieved2, _ := st.Get(ctx, "user-123")
		require.Equal(t, "value", retrieved2.Metadata["key"])
	})
}

func TestMemoryPrincipalStore_Update(t *testing.T) {
	t.Run("update existing principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
			Email:       "old@example.com",
		}

		require.NoError(t, st.Create(ctx, principal))

		principal.Email = "new@example.com"
		err := st.Update(ctx, principal)
		require.NoError(t, err)

		retrieved, _ := st.Get(ctx, "user-123")
		require.Equal(t, "new@example.com", retrieved.Email)
	})

	t.Run("update nonexistent principal returns error", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "nonexistent",
			Type:        store.PrincipalTypeUser,
		}

		err := st.Update(ctx, principal)
		require.Error(t, err)
		require.Equal(t, store.ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_Suspend(t *testing.T) {
	t.Run("suspend active principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, st.Create(ctx, principal))

		err := st.Suspend(ctx, "user-123", "Policy violation")
		require.NoError(t, err)

		retrieved, _ := st.Get(ctx, "user-123")
		require.Equal(t, store.PrincipalStatusSuspended, retrieved.Status)
		require.Equal(t, "Policy violation", retrieved.SuspendedReason)
		require.NotNil(t, retrieved.SuspendedAt)
	})

	t.Run("suspend nonexistent principal returns error", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		err := st.Suspend(ctx, "nonexistent", "Test")
		require.Error(t, err)
		require.Equal(t, store.ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_Activate(t *testing.T) {
	t.Run("activate suspended principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, st.Create(ctx, principal))

		// Suspend then activate
		require.NoError(t, st.Suspend(ctx, "user-123", "Test"))

		err := st.Activate(ctx, "user-123")
		require.NoError(t, err)

		retrieved, _ := st.Get(ctx, "user-123")
		require.Equal(t, store.PrincipalStatusActive, retrieved.Status)
		require.Nil(t, retrieved.SuspendedAt)
		require.Empty(t, retrieved.SuspendedReason)
	})

	t.Run("activate nonexistent principal returns error", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		err := st.Activate(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, store.ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_Delete(t *testing.T) {
	t.Run("soft delete principal", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, st.Create(ctx, principal))

		err := st.Delete(ctx, "user-123")
		require.NoError(t, err)

		retrieved, _ := st.Get(ctx, "user-123")
		require.Equal(t, store.PrincipalStatusDeleted, retrieved.Status)
	})

	t.Run("delete nonexistent principal returns error", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		err := st.Delete(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, store.ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_List(t *testing.T) {
	t.Run("list all principals", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principals := []*store.PrincipalMetadata{
			{PrincipalID: "user-1", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "user-2", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-1", Type: store.PrincipalTypeWorker, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
		}

		for _, p := range principals {
			require.NoError(t, st.Create(ctx, p))
		}

		result, err := st.List(ctx, store.ListPrincipalsOptions{})
		require.NoError(t, err)
		require.Len(t, result, 3)
	})

	t.Run("list by type", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principals := []*store.PrincipalMetadata{
			{PrincipalID: "user-1", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "user-2", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-1", Type: store.PrincipalTypeWorker, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
		}

		for _, p := range principals {
			require.NoError(t, st.Create(ctx, p))
		}

		result, err := st.List(ctx, store.ListPrincipalsOptions{Type: store.PrincipalTypeUser})
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, p := range result {
			require.Equal(t, store.PrincipalTypeUser, p.Type)
		}
	})

	t.Run("list by status", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		p1 := &store.PrincipalMetadata{PrincipalID: "user-1", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"}
		p2 := &store.PrincipalMetadata{PrincipalID: "user-2", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"}
		p3 := &store.PrincipalMetadata{PrincipalID: "user-3", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"}

		require.NoError(t, st.Create(ctx, p1))
		require.NoError(t, st.Create(ctx, p2))
		require.NoError(t, st.Create(ctx, p3))

		// Suspend one
		require.NoError(t, st.Suspend(ctx, "user-2", "Test"))

		result, err := st.List(ctx, store.ListPrincipalsOptions{Status: store.PrincipalStatusSuspended})
		require.NoError(t, err)
		require.Len(t, result, 1)
		require.Equal(t, "user-2", result[0].PrincipalID)
	})

	t.Run("list with limit", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		for i := 1; i <= 5; i++ {
			p := &store.PrincipalMetadata{
				PrincipalID: string(rune(64 + i)), // A, B, C, D, E
				Type:        store.PrincipalTypeUser,
				Status:      store.PrincipalStatusActive,
				CreatedAt:   time.Now(),
				CreatedBy:   "admin",
			}
			require.NoError(t, st.Create(ctx, p))
		}

		result, err := st.List(ctx, store.ListPrincipalsOptions{Limit: 3})
		require.NoError(t, err)
		require.Len(t, result, 3)
	})

	t.Run("list combined filters", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		principals := []*store.PrincipalMetadata{
			{PrincipalID: "user-1", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "user-2", Type: store.PrincipalTypeUser, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-1", Type: store.PrincipalTypeWorker, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-2", Type: store.PrincipalTypeWorker, Status: store.PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
		}

		for _, p := range principals {
			require.NoError(t, st.Create(ctx, p))
		}

		result, err := st.List(ctx, store.ListPrincipalsOptions{
			Type:   store.PrincipalTypeWorker,
			Status: store.PrincipalStatusActive,
		})
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, p := range result {
			require.Equal(t, store.PrincipalTypeWorker, p.Type)
			require.Equal(t, store.PrincipalStatusActive, p.Status)
		}
	})

	t.Run("list empty result", func(t *testing.T) {
		st := NewPrincipalStore()
		ctx := context.Background()

		result, err := st.List(ctx, store.ListPrincipalsOptions{})
		require.NoError(t, err)
		require.Empty(t, result)
	})
}

func TestMemoryPrincipalStoreImplementsInterface(t *testing.T) {
	var _ store.PrincipalStore = (*PrincipalStore)(nil)
}
