package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMemoryCertificateStore(t *testing.T) {
	store := NewMemoryCertificateStore()
	require.NotNil(t, store)
}

func TestMemoryCertificateStore_Register(t *testing.T) {
	t.Run("register new certificate", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			SubjectDN:     "CN=user-123",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		err := store.Register(ctx, cert)
		require.NoError(t, err)
	})

	t.Run("register duplicate certificate returns error", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, store.Register(ctx, cert))

		err := store.Register(ctx, cert)
		require.Error(t, err)
		require.Equal(t, ErrCertAlreadyExists, err)
	})

	t.Run("register certificate with description", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			SubjectDN:     "CN=user-123",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Description:   "Production certificate",
		}

		require.NoError(t, store.Register(ctx, cert))

		retrieved, _ := store.Get(ctx, "1234567890abcdef")
		require.Equal(t, "Production certificate", retrieved.Description)
	})
}

func TestMemoryCertificateStore_Get(t *testing.T) {
	t.Run("get existing certificate by serial number", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, store.Register(ctx, cert))

		retrieved, err := store.Get(ctx, "1234567890abcdef")
		require.NoError(t, err)
		require.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
		require.Equal(t, cert.PrincipalID, retrieved.PrincipalID)
	})

	t.Run("get nonexistent certificate returns error", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		_, err := store.Get(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, ErrCertNotFound, err)
	})

	t.Run("get returns copy of certificate", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, store.Register(ctx, cert))

		retrieved1, _ := store.Get(ctx, "1234567890abcdef")
		now := time.Now()
		retrieved1.RevokedAt = &now

		retrieved2, _ := store.Get(ctx, "1234567890abcdef")
		require.Nil(t, retrieved2.RevokedAt)
	})
}

func TestMemoryCertificateStore_GetByPrincipal(t *testing.T) {
	t.Run("get certificates by principal ID", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		certs := []*CertMetadata{
			{
				SerialNumber:  "1111111111111111",
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   "aaaaaaaaaa",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
			{
				SerialNumber:  "2222222222222222",
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   "bbbbbbbbbb",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
			{
				SerialNumber:  "3333333333333333",
				PrincipalID:   "user-456",
				PrincipalType: "user",
				Fingerprint:   "cccccccccc",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
		}

		for _, cert := range certs {
			require.NoError(t, store.Register(ctx, cert))
		}

		result, err := store.GetByPrincipal(ctx, "user-123")
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, cert := range result {
			require.Equal(t, "user-123", cert.PrincipalID)
		}
	})

	t.Run("get by nonexistent principal returns empty slice", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		result, err := store.GetByPrincipal(ctx, "nonexistent")
		require.NoError(t, err)
		require.Empty(t, result)
	})
}

func TestMemoryCertificateStore_GetByFingerprint(t *testing.T) {
	t.Run("get certificate by fingerprint", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456xyz",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, store.Register(ctx, cert))

		retrieved, err := store.GetByFingerprint(ctx, "abc123def456xyz")
		require.NoError(t, err)
		require.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
	})

	t.Run("get by nonexistent fingerprint returns error", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		_, err := store.GetByFingerprint(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, ErrCertNotFound, err)
	})
}

func TestMemoryCertificateStore_Revoke(t *testing.T) {
	t.Run("revoke active certificate", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert := &CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		require.NoError(t, store.Register(ctx, cert))

		err := store.Revoke(ctx, "1234567890abcdef", "Key compromise")
		require.NoError(t, err)

		retrieved, _ := store.Get(ctx, "1234567890abcdef")
		require.True(t, retrieved.Revoked)
		require.Equal(t, "Key compromise", retrieved.RevocationReason)
		require.NotNil(t, retrieved.RevokedAt)
	})

	t.Run("revoke nonexistent certificate returns error", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		err := store.Revoke(ctx, "nonexistent", "Test")
		require.Error(t, err)
		require.Equal(t, ErrCertNotFound, err)
	})
}

func TestMemoryCertificateStore_List(t *testing.T) {
	t.Run("list all certificates", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		certs := []*CertMetadata{
			{
				SerialNumber:  "1111111111111111",
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   "aaaaaaaaaa",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
			{
				SerialNumber:  "2222222222222222",
				PrincipalID:   "user-456",
				PrincipalType: "user",
				Fingerprint:   "bbbbbbbbbb",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
		}

		for _, cert := range certs {
			require.NoError(t, store.Register(ctx, cert))
		}

		result, err := store.List(ctx, ListCertificatesOptions{})
		require.NoError(t, err)
		require.Len(t, result, 2)
	})

	t.Run("list by principal ID", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		certs := []*CertMetadata{
			{
				SerialNumber:  "1111111111111111",
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   "aaaaaaaaaa",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
			{
				SerialNumber:  "2222222222222222",
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   "bbbbbbbbbb",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
			{
				SerialNumber:  "3333333333333333",
				PrincipalID:   "user-456",
				PrincipalType: "user",
				Fingerprint:   "cccccccccc",
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			},
		}

		for _, cert := range certs {
			require.NoError(t, store.Register(ctx, cert))
		}

		result, err := store.List(ctx, ListCertificatesOptions{PrincipalID: "user-123"})
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, cert := range result {
			require.Equal(t, "user-123", cert.PrincipalID)
		}
	})

	t.Run("list excludes revoked by default", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert1 := &CertMetadata{
			SerialNumber:  "1111111111111111",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "aaaaaaaaaa",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		cert2 := &CertMetadata{
			SerialNumber:  "2222222222222222",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "bbbbbbbbbb",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		require.NoError(t, store.Register(ctx, cert1))
		require.NoError(t, store.Register(ctx, cert2))

		// Revoke one
		require.NoError(t, store.Revoke(ctx, "2222222222222222", "Test"))

		result, err := store.List(ctx, ListCertificatesOptions{})
		require.NoError(t, err)
		require.Len(t, result, 1)
		require.Equal(t, "1111111111111111", result[0].SerialNumber)
	})

	t.Run("list includes revoked when requested", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert1 := &CertMetadata{
			SerialNumber:  "1111111111111111",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "aaaaaaaaaa",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		cert2 := &CertMetadata{
			SerialNumber:  "2222222222222222",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "bbbbbbbbbb",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		require.NoError(t, store.Register(ctx, cert1))
		require.NoError(t, store.Register(ctx, cert2))

		// Revoke one
		require.NoError(t, store.Revoke(ctx, "2222222222222222", "Test"))

		result, err := store.List(ctx, ListCertificatesOptions{IncludeRevoked: true})
		require.NoError(t, err)
		require.Len(t, result, 2)
	})

	t.Run("list with limit", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		for i := 1; i <= 5; i++ {
			cert := &CertMetadata{
				SerialNumber:  string(rune(48 + i)), // 1, 2, 3, 4, 5
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   string(rune(97 + i)), // a, b, c, d, e
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			}
			require.NoError(t, store.Register(ctx, cert))
		}

		result, err := store.List(ctx, ListCertificatesOptions{Limit: 3})
		require.NoError(t, err)
		require.Len(t, result, 3)
	})

	t.Run("list by principal with revoked exclusion", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		cert1 := &CertMetadata{
			SerialNumber:  "1111111111111111",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "aaaaaaaaaa",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		cert2 := &CertMetadata{
			SerialNumber:  "2222222222222222",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "bbbbbbbbbb",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, store.Register(ctx, cert1))
		require.NoError(t, store.Register(ctx, cert2))
		require.NoError(t, store.Revoke(ctx, "2222222222222222", "Test"))

		result, err := store.List(ctx, ListCertificatesOptions{
			PrincipalID:    "user-123",
			IncludeRevoked: false,
		})
		require.NoError(t, err)
		require.Len(t, result, 1)
	})

	t.Run("list empty result", func(t *testing.T) {
		store := NewMemoryCertificateStore()
		ctx := context.Background()

		result, err := store.List(ctx, ListCertificatesOptions{})
		require.NoError(t, err)
		require.Empty(t, result)
	})
}

func TestMemoryCertificateStoreImplementsInterface(t *testing.T) {
	var _ CertificateStore = (*MemoryCertificateStore)(nil)
}
