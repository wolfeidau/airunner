package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/authn"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/pki"
	"github.com/wolfeidau/airunner/internal/store"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
)

// createTestCert creates a test certificate with OID extensions
func createTestCert(principalType, principalID string) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: principalID,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	if principalType != "" {
		typeBytes, _ := asn1.Marshal(principalType)
		ext := pkix.Extension{Id: pki.OIDPrincipalType, Value: typeBytes}
		cert.Extensions = append(cert.Extensions, ext)
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}

	if principalID != "" {
		idBytes, _ := asn1.Marshal(principalID)
		ext := pkix.Extension{Id: pki.OIDPrincipalID, Value: idBytes}
		cert.Extensions = append(cert.Extensions, ext)
		cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	}

	return cert
}

func TestNewMTLSAuthenticator(t *testing.T) {
	ps := memorystore.NewPrincipalStore()
	cs := memorystore.NewCertificateStore()

	auth := NewMTLSAuthenticator(ps, cs)

	require.NotNil(t, auth)
	require.NotNil(t, auth.principalStore)
	require.NotNil(t, auth.certStore)
	require.NotNil(t, auth.cache)
}

func TestMTLSAuthenticator_AuthFunc(t *testing.T) {
	t.Run("no TLS connection returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		req := &http.Request{TLS: nil}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("no verified chains returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: nil,
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("empty verified chains returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("successful authentication with valid principal", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		// Create principal in store
		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}
		require.NoError(t, ps.Create(context.Background(), principal))

		// Create test certificate
		cert := createTestCert("user", "user-123")

		// Register the certificate
		certMeta := store.NewCertMetadataFromX509(cert)
		require.NoError(t, cs.Register(context.Background(), certMeta))

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		info, err := authFunc(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, info)

		pi, ok := info.(*PrincipalInfo)
		require.True(t, ok)
		require.Equal(t, "user-123", pi.PrincipalID)
		require.Equal(t, store.PrincipalTypeUser, pi.Type)
	})

	t.Run("principal not found returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		cert := createTestCert("user", "nonexistent-user")

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("suspended principal returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		principal := &store.PrincipalMetadata{
			PrincipalID:     "user-suspended",
			Type:            store.PrincipalTypeUser,
			Status:          store.PrincipalStatusSuspended,
			CreatedAt:       time.Now(),
			CreatedBy:       "admin",
			SuspendedReason: "Policy violation",
		}
		require.NoError(t, ps.Create(context.Background(), principal))

		cert := createTestCert("user", "user-suspended")

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("deleted principal returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-deleted",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusDeleted,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}
		require.NoError(t, ps.Create(context.Background(), principal))

		cert := createTestCert("user", "user-deleted")

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("principal type mismatch returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		// Store principal as admin
		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeAdmin,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}
		require.NoError(t, ps.Create(context.Background(), principal))

		// But certificate says user
		cert := createTestCert("user", "user-123")

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("revoked certificate returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}
		require.NoError(t, ps.Create(context.Background(), principal))

		cert := createTestCert("user", "user-123")

		// Register and revoke certificate
		certMeta := &store.CertMetadata{
			SerialNumber:     cert.SerialNumber.Text(16),
			PrincipalID:      "user-123",
			Fingerprint:      "abc123",
			Revoked:          true,
			RevocationReason: "Key compromise",
		}
		require.NoError(t, cs.Register(context.Background(), certMeta))

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("cache returns cached result on second call", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		principal := &store.PrincipalMetadata{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
			Status:      store.PrincipalStatusActive,
			CreatedAt:   time.Now(),
			CreatedBy:   "admin",
		}
		require.NoError(t, ps.Create(context.Background(), principal))

		cert := createTestCert("user", "user-123")

		// Register the certificate
		certMeta := store.NewCertMetadataFromX509(cert)
		require.NoError(t, cs.Register(context.Background(), certMeta))

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		// First call
		info1, err1 := authFunc(context.Background(), req)
		require.NoError(t, err1)

		// Delete the principal to ensure we're using cache
		require.NoError(t, ps.Delete(context.Background(), "user-123"))

		// Second call should still succeed via cache
		info2, err2 := authFunc(context.Background(), req)
		require.NoError(t, err2)

		pi1 := info1.(*PrincipalInfo)
		pi2 := info2.(*PrincipalInfo)
		require.Equal(t, pi1.PrincipalID, pi2.PrincipalID)
	})

	t.Run("invalid principal type returns error", func(t *testing.T) {
		ps := memorystore.NewPrincipalStore()
		cs := memorystore.NewCertificateStore()
		auth := NewMTLSAuthenticator(ps, cs)

		// Create cert with invalid principal type
		cert := createTestCert("invalid_type", "user-123")

		req := &http.Request{
			TLS: &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		}
		authFunc := auth.AuthFunc()

		_, err := authFunc(context.Background(), req)
		require.Error(t, err)
	})
}

func TestGetPrincipalInfo(t *testing.T) {
	t.Run("retrieve principal info from context", func(t *testing.T) {
		expectedInfo := &PrincipalInfo{
			PrincipalID:  "user-123",
			Type:         store.PrincipalTypeUser,
			SerialNumber: "abc123",
		}

		ctx := authn.SetInfo(context.Background(), expectedInfo)

		info, ok := GetPrincipalInfo(ctx)
		require.True(t, ok)
		require.Equal(t, expectedInfo, info)
	})

	t.Run("context without principal info returns false", func(t *testing.T) {
		ctx := context.Background()

		info, ok := GetPrincipalInfo(ctx)
		require.False(t, ok)
		require.Nil(t, info)
	})

	t.Run("context with wrong type returns false", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), "not a PrincipalInfo")

		info, ok := GetPrincipalInfo(ctx)
		require.False(t, ok)
		require.Nil(t, info)
	})
}
