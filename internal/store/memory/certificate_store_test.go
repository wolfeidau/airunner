package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/store"
)

func TestNewCertificateStore(t *testing.T) {
	store := NewCertificateStore()
	require.NotNil(t, store)
}

func TestCertificateStore_Register(t *testing.T) {
	t.Run("register new certificate", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			SubjectDN:     "CN=user-123",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		err := st.Register(ctx, cert)
		require.NoError(t, err)
	})

	t.Run("register duplicate certificate returns error", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, st.Register(ctx, cert))

		err := st.Register(ctx, cert)
		require.Error(t, err)
		require.Equal(t, store.ErrCertAlreadyExists, err)
	})

	t.Run("register certificate with description", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			SubjectDN:     "CN=user-123",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Description:   "Production certificate",
		}

		require.NoError(t, st.Register(ctx, cert))

		retrieved, _ := st.Get(ctx, "1234567890abcdef")
		require.Equal(t, "Production certificate", retrieved.Description)
	})
}

func TestCertificateStore_Get(t *testing.T) {
	t.Run("get existing certificate by serial number", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, st.Register(ctx, cert))

		retrieved, err := st.Get(ctx, "1234567890abcdef")
		require.NoError(t, err)
		require.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
		require.Equal(t, cert.PrincipalID, retrieved.PrincipalID)
	})

	t.Run("get nonexistent certificate returns error", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		_, err := st.Get(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, store.ErrCertNotFound, err)
	})

	t.Run("get returns copy of certificate", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, st.Register(ctx, cert))

		retrieved1, _ := st.Get(ctx, "1234567890abcdef")
		now := time.Now()
		retrieved1.RevokedAt = &now

		retrieved2, _ := st.Get(ctx, "1234567890abcdef")
		require.Nil(t, retrieved2.RevokedAt)
	})
}

func TestCertificateStore_GetByPrincipal(t *testing.T) {
	t.Run("get certificates by principal ID", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		certs := []*store.CertMetadata{
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
			require.NoError(t, st.Register(ctx, cert))
		}

		result, err := st.GetByPrincipal(ctx, "user-123")
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, cert := range result {
			require.Equal(t, "user-123", cert.PrincipalID)
		}
	})

	t.Run("get by nonexistent principal returns empty slice", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		result, err := st.GetByPrincipal(ctx, "nonexistent")
		require.NoError(t, err)
		require.Empty(t, result)
	})
}

func TestCertificateStore_GetByFingerprint(t *testing.T) {
	t.Run("get certificate by fingerprint", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456xyz",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, st.Register(ctx, cert))

		retrieved, err := st.GetByFingerprint(ctx, "abc123def456xyz")
		require.NoError(t, err)
		require.Equal(t, cert.SerialNumber, retrieved.SerialNumber)
	})

	t.Run("get by nonexistent fingerprint returns error", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		_, err := st.GetByFingerprint(ctx, "nonexistent")
		require.Error(t, err)
		require.Equal(t, store.ErrCertNotFound, err)
	})
}

func TestCertificateStore_Revoke(t *testing.T) {
	t.Run("revoke active certificate", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert := &store.CertMetadata{
			SerialNumber:  "1234567890abcdef",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "abc123def456",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		require.NoError(t, st.Register(ctx, cert))

		err := st.Revoke(ctx, "1234567890abcdef", "Key compromise")
		require.NoError(t, err)

		retrieved, _ := st.Get(ctx, "1234567890abcdef")
		require.True(t, retrieved.Revoked)
		require.Equal(t, "Key compromise", retrieved.RevocationReason)
		require.NotNil(t, retrieved.RevokedAt)
	})

	t.Run("revoke nonexistent certificate returns error", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		err := st.Revoke(ctx, "nonexistent", "Test")
		require.Error(t, err)
		require.Equal(t, store.ErrCertNotFound, err)
	})
}

func TestCertificateStore_List(t *testing.T) {
	t.Run("list all certificates", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		certs := []*store.CertMetadata{
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
			require.NoError(t, st.Register(ctx, cert))
		}

		result, err := st.List(ctx, store.ListCertificatesOptions{})
		require.NoError(t, err)
		require.Len(t, result, 2)
	})

	t.Run("list by principal ID", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		certs := []*store.CertMetadata{
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
			require.NoError(t, st.Register(ctx, cert))
		}

		result, err := st.List(ctx, store.ListCertificatesOptions{PrincipalID: "user-123"})
		require.NoError(t, err)
		require.Len(t, result, 2)

		for _, cert := range result {
			require.Equal(t, "user-123", cert.PrincipalID)
		}
	})

	t.Run("list excludes revoked by default", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert1 := &store.CertMetadata{
			SerialNumber:  "1111111111111111",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "aaaaaaaaaa",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		cert2 := &store.CertMetadata{
			SerialNumber:  "2222222222222222",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "bbbbbbbbbb",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		require.NoError(t, st.Register(ctx, cert1))
		require.NoError(t, st.Register(ctx, cert2))

		// Revoke one
		require.NoError(t, st.Revoke(ctx, "2222222222222222", "Test"))

		result, err := st.List(ctx, store.ListCertificatesOptions{})
		require.NoError(t, err)
		require.Len(t, result, 1)
		require.Equal(t, "1111111111111111", result[0].SerialNumber)
	})

	t.Run("list includes revoked when requested", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert1 := &store.CertMetadata{
			SerialNumber:  "1111111111111111",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "aaaaaaaaaa",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		cert2 := &store.CertMetadata{
			SerialNumber:  "2222222222222222",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "bbbbbbbbbb",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			Revoked:       false,
		}

		require.NoError(t, st.Register(ctx, cert1))
		require.NoError(t, st.Register(ctx, cert2))

		// Revoke one
		require.NoError(t, st.Revoke(ctx, "2222222222222222", "Test"))

		result, err := st.List(ctx, store.ListCertificatesOptions{IncludeRevoked: true})
		require.NoError(t, err)
		require.Len(t, result, 2)
	})

	t.Run("list with limit", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		for i := 1; i <= 5; i++ {
			cert := &store.CertMetadata{
				SerialNumber:  string(rune(48 + i)), // 1, 2, 3, 4, 5
				PrincipalID:   "user-123",
				PrincipalType: "user",
				Fingerprint:   string(rune(97 + i)), // a, b, c, d, e
				IssuedAt:      time.Now(),
				ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
			}
			require.NoError(t, st.Register(ctx, cert))
		}

		result, err := st.List(ctx, store.ListCertificatesOptions{Limit: 3})
		require.NoError(t, err)
		require.Len(t, result, 3)
	})

	t.Run("list by principal with revoked exclusion", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		cert1 := &store.CertMetadata{
			SerialNumber:  "1111111111111111",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "aaaaaaaaaa",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		cert2 := &store.CertMetadata{
			SerialNumber:  "2222222222222222",
			PrincipalID:   "user-123",
			PrincipalType: "user",
			Fingerprint:   "bbbbbbbbbb",
			IssuedAt:      time.Now(),
			ExpiresAt:     time.Now().Add(365 * 24 * time.Hour),
		}

		require.NoError(t, st.Register(ctx, cert1))
		require.NoError(t, st.Register(ctx, cert2))
		require.NoError(t, st.Revoke(ctx, "2222222222222222", "Test"))

		result, err := st.List(ctx, store.ListCertificatesOptions{
			PrincipalID:    "user-123",
			IncludeRevoked: false,
		})
		require.NoError(t, err)
		require.Len(t, result, 1)
	})

	t.Run("list empty result", func(t *testing.T) {
		st := NewCertificateStore()
		ctx := context.Background()

		result, err := st.List(ctx, store.ListCertificatesOptions{})
		require.NoError(t, err)
		require.Empty(t, result)
	})
}

func TestMemoryCertificateStoreImplementsInterface(t *testing.T) {
	var _ store.CertificateStore = (*CertificateStore)(nil)
}
