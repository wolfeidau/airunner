package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMemoryPrincipalStore(t *testing.T) {
	store := NewMemoryPrincipalStore()
	require.NotNil(t, store)
}

func TestMemoryPrincipalStore_Create(t *testing.T) {
	t.Run("create new principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		err := store.Create(ctx, principal)
		require.NoError(t, err)
	})

	t.Run("create duplicate principal returns error", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		err := store.Create(ctx, principal)
		require.NoError(t, err)

		err = store.Create(ctx, principal)
		require.Error(t, err)
		require.Equal(t, ErrPrincipalAlreadyExists, err)
	})

	t.Run("create principal with metadata", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID:     "user-123",
			Type:            PrincipalTypeUser,
			Status:          PrincipalStatusActive,
			CreatedAt:       time.Now(),
			CreatedBy:       "admin",
			Email:           "user@example.com",
			Description:     "Test user",
			MaxCertificates: 5,
			Metadata: map[string]string{
				"team": "backend",
			},
		}

		err := store.Create(ctx, principal)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, "user-123")
		require.NoError(t, err)
		require.Equal(t, principal.Email, retrieved.Email)
		require.Equal(t, principal.Metadata["team"], retrieved.Metadata["team"])
	})
}

func TestMemoryPrincipalStore_Get(t *testing.T) {
	t.Run("get existing principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, store.Create(ctx, principal))

		retrieved, err := store.Get(ctx, "user-123")
		require.NoError(t, err)
		require.Equal(t, principal.PrincipalID, retrieved.PrincipalID)
		require.Equal(t, principal.Type, retrieved.Type)
	})

	t.Run("get nonexistent principal returns error", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		_, err := store.Get(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, ErrPrincipalNotFound, err)
	})

	t.Run("get returns copy of principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
			Metadata: map[string]string{
				"key": "value",
			},
		}

		require.NoError(t, store.Create(ctx, principal))

		retrieved1, _ := store.Get(ctx, "user-123")
		retrieved1.Metadata["key"] = "modified"

		retrieved2, _ := store.Get(ctx, "user-123")
		require.Equal(t, "value", retrieved2.Metadata["key"])
	})
}

func TestMemoryPrincipalStore_Update(t *testing.T) {
	t.Run("update existing principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
			Email:       "old@example.com",
		}

		require.NoError(t, store.Create(ctx, principal))

		principal.Email = "new@example.com"
		err := store.Update(ctx, principal)
		require.NoError(t, err)

		retrieved, _ := store.Get(ctx, "user-123")
		require.Equal(t, "new@example.com", retrieved.Email)
	})

	t.Run("update nonexistent principal returns error", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "nonexistent",
			Type:        PrincipalTypeUser,
		}

		err := store.Update(ctx, principal)
		require.Error(t, err)
		require.Equal(t, ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_Suspend(t *testing.T) {
	t.Run("suspend active principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, store.Create(ctx, principal))

		err := store.Suspend(ctx, "user-123", "Policy violation")
		require.NoError(t, err)

		retrieved, _ := store.Get(ctx, "user-123")
		require.Equal(t, PrincipalStatusSuspended, retrieved.Status)
		require.Equal(t, "Policy violation", retrieved.SuspendedReason)
		require.NotNil(t, retrieved.SuspendedAt)
	})

	t.Run("suspend nonexistent principal returns error", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		err := store.Suspend(ctx, "nonexistent", "Test")
		require.Error(t, err)
		require.Equal(t, ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_Activate(t *testing.T) {
	t.Run("activate suspended principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, store.Create(ctx, principal))

		// Suspend then activate
		require.NoError(t, store.Suspend(ctx, "user-123", "Test"))

		err := store.Activate(ctx, "user-123")
		require.NoError(t, err)

		retrieved, _ := store.Get(ctx, "user-123")
		require.Equal(t, PrincipalStatusActive, retrieved.Status)
		require.Nil(t, retrieved.SuspendedAt)
		require.Empty(t, retrieved.SuspendedReason)
	})

	t.Run("activate nonexistent principal returns error", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		err := store.Activate(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_Delete(t *testing.T) {
	t.Run("soft delete principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principal := &PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        PrincipalTypeUser,
			Status:      PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}

		require.NoError(t, store.Create(ctx, principal))

		err := store.Delete(ctx, "user-123")
		require.NoError(t, err)

		retrieved, _ := store.Get(ctx, "user-123")
		require.Equal(t, PrincipalStatusDeleted, retrieved.Status)
	})

	t.Run("delete nonexistent principal returns error", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		err := store.Delete(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, ErrPrincipalNotFound, err)
	})
}

func TestMemoryPrincipalStore_List(t *testing.T) {
	t.Run("list all principals", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principals := []*PrincipalMetadata{
			{PrincipalID: "user-1", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "user-2", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-1", Type: PrincipalTypeWorker, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
		}

		for _, p := range principals {
			require.NoError(t, store.Create(ctx, p))
		}

		result, err := store.List(ctx, ListPrincipalsOptions{})
		require.NoError(t, err)
		require.Len(t, result, 3)
	})

	t.Run("list by type", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principals := []*PrincipalMetadata{
			{PrincipalID: "user-1", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "user-2", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-1", Type: PrincipalTypeWorker, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
		}

		for _, p := range principals {
			require.NoError(t, store.Create(ctx, p))
		}

		result, err := store.List(ctx, ListPrincipalsOptions{Type: PrincipalTypeUser})
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, p := range result {
			require.Equal(t, PrincipalTypeUser, p.Type)
		}
	})

	t.Run("list by status", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		p1 := &PrincipalMetadata{PrincipalID: "user-1", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"}
		p2 := &PrincipalMetadata{PrincipalID: "user-2", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"}
		p3 := &PrincipalMetadata{PrincipalID: "user-3", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"}

		require.NoError(t, store.Create(ctx, p1))
		require.NoError(t, store.Create(ctx, p2))
		require.NoError(t, store.Create(ctx, p3))

		// Suspend one
		require.NoError(t, store.Suspend(ctx, "user-2", "Test"))

		result, err := store.List(ctx, ListPrincipalsOptions{Status: PrincipalStatusSuspended})
		require.NoError(t, err)
		require.Len(t, result, 1)
		require.Equal(t, "user-2", result[0].PrincipalID)
	})

	t.Run("list with limit", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		for i := 1; i <= 5; i++ {
			p := &PrincipalMetadata{
				PrincipalID: string(rune(64 + i)), // A, B, C, D, E
				Type:        PrincipalTypeUser,
				Status:      PrincipalStatusActive,
				CreatedAt:   time.Now(),
				CreatedBy:   "admin",
			}
			require.NoError(t, store.Create(ctx, p))
		}

		result, err := store.List(ctx, ListPrincipalsOptions{Limit: 3})
		require.NoError(t, err)
		require.Len(t, result, 3)
	})

	t.Run("list combined filters", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		principals := []*PrincipalMetadata{
			{PrincipalID: "user-1", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "user-2", Type: PrincipalTypeUser, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-1", Type: PrincipalTypeWorker, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
			{PrincipalID: "worker-2", Type: PrincipalTypeWorker, Status: PrincipalStatusActive, CreatedAt: time.Now(), CreatedBy: "admin"},
		}

		for _, p := range principals {
			require.NoError(t, store.Create(ctx, p))
		}

		result, err := store.List(ctx, ListPrincipalsOptions{
			Type:   PrincipalTypeWorker,
			Status: PrincipalStatusActive,
		})
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, p := range result {
			require.Equal(t, PrincipalTypeWorker, p.Type)
			require.Equal(t, PrincipalStatusActive, p.Status)
		}
	})

	t.Run("list empty result", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		ctx := context.Background()

		result, err := store.List(ctx, ListPrincipalsOptions{})
		require.NoError(t, err)
		require.Empty(t, result)
	})
}

func TestMemoryPrincipalStoreImplementsInterface(t *testing.T) {
	var _ PrincipalStore = (*MemoryPrincipalStore)(nil)
}
