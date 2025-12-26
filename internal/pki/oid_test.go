package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Simplified test - create certs with extension manually
func createCertWithExtension(oid asn1.ObjectIdentifier, value string) *x509.Certificate {
	valueBytes, _ := asn1.Marshal(value)
	ext := pkix.Extension{
		Id:    oid,
		Value: valueBytes,
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-principal",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(24 * time.Hour),
		Extensions:      []pkix.Extension{ext},
		ExtraExtensions: []pkix.Extension{ext},
	}

	return cert
}

func TestExtractPrincipalType(t *testing.T) {
	t.Run("extract valid principal type", func(t *testing.T) {
		cert := createCertWithExtension(OIDPrincipalType, "admin")

		pt, err := ExtractPrincipalType(cert)
		require.NoError(t, err)
		require.Equal(t, "admin", pt)
	})

	t.Run("extract worker type", func(t *testing.T) {
		cert := createCertWithExtension(OIDPrincipalType, "worker")

		pt, err := ExtractPrincipalType(cert)
		require.NoError(t, err)
		require.Equal(t, "worker", pt)
	})

	t.Run("missing extension returns error", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "test"},
		}

		_, err := ExtractPrincipalType(cert)
		require.Error(t, err)
		require.Equal(t, ErrExtensionNotFound, err)
	})

	t.Run("empty extensions returns error", func(t *testing.T) {
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{},
		}

		_, err := ExtractPrincipalType(cert)
		require.Error(t, err)
		require.Equal(t, ErrExtensionNotFound, err)
	})
}

func TestExtractPrincipalID(t *testing.T) {
	t.Run("extract valid principal ID", func(t *testing.T) {
		cert := createCertWithExtension(OIDPrincipalID, "user-12345")

		id, err := ExtractPrincipalID(cert)
		require.NoError(t, err)
		require.Equal(t, "user-12345", id)
	})

	t.Run("extract UUID principal ID", func(t *testing.T) {
		cert := createCertWithExtension(OIDPrincipalID, "550e8400-e29b-41d4-a716-446655440000")

		id, err := ExtractPrincipalID(cert)
		require.NoError(t, err)
		require.Equal(t, "550e8400-e29b-41d4-a716-446655440000", id)
	})

	t.Run("missing extension returns error", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "test"},
		}

		_, err := ExtractPrincipalID(cert)
		require.Error(t, err)
		require.Equal(t, ErrExtensionNotFound, err)
	})

	t.Run("empty extensions returns error", func(t *testing.T) {
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{},
		}

		_, err := ExtractPrincipalID(cert)
		require.Error(t, err)
		require.Equal(t, ErrExtensionNotFound, err)
	})
}

func TestMustExtractPrincipal(t *testing.T) {
	t.Run("extract both type and ID successfully", func(t *testing.T) {
		typeBytes, _ := asn1.Marshal("user")
		idBytes, _ := asn1.Marshal("user-123")

		cert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "fallback-cn"},
			Extensions: []pkix.Extension{
				{Id: OIDPrincipalType, Value: typeBytes},
				{Id: OIDPrincipalID, Value: idBytes},
			},
			ExtraExtensions: []pkix.Extension{
				{Id: OIDPrincipalType, Value: typeBytes},
				{Id: OIDPrincipalID, Value: idBytes},
			},
		}

		pt, id, err := MustExtractPrincipal(cert)
		require.NoError(t, err)
		require.Equal(t, "user", pt)
		require.Equal(t, "user-123", id)
	})

	t.Run("fallback to CN when ID extension missing", func(t *testing.T) {
		typeBytes, _ := asn1.Marshal("worker")

		cert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "worker-from-cn"},
			Extensions: []pkix.Extension{
				{Id: OIDPrincipalType, Value: typeBytes},
			},
			ExtraExtensions: []pkix.Extension{
				{Id: OIDPrincipalType, Value: typeBytes},
			},
		}

		pt, id, err := MustExtractPrincipal(cert)
		require.NoError(t, err)
		require.Equal(t, "worker", pt)
		require.Equal(t, "worker-from-cn", id) // Falls back to CN
	})

	t.Run("error when principal type extension missing", func(t *testing.T) {
		idBytes, _ := asn1.Marshal("test-id")

		cert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "test-cn"},
			Extensions: []pkix.Extension{
				{Id: OIDPrincipalID, Value: idBytes},
			},
			ExtraExtensions: []pkix.Extension{
				{Id: OIDPrincipalID, Value: idBytes},
			},
		}

		_, _, err := MustExtractPrincipal(cert)
		require.Error(t, err)
	})

	t.Run("error when no ID extension and no CN", func(t *testing.T) {
		typeBytes, _ := asn1.Marshal("admin")

		cert := &x509.Certificate{
			Subject: pkix.Name{}, // Empty CommonName
			Extensions: []pkix.Extension{
				{Id: OIDPrincipalType, Value: typeBytes},
			},
			ExtraExtensions: []pkix.Extension{
				{Id: OIDPrincipalType, Value: typeBytes},
			},
		}

		_, _, err := MustExtractPrincipal(cert)
		require.Error(t, err)
	})
}

func TestValidPrincipalTypes(t *testing.T) {
	t.Run("all valid principal types", func(t *testing.T) {
		validTypes := []string{"admin", "worker", "user", "service"}

		for _, pt := range validTypes {
			cert := createCertWithExtension(OIDPrincipalType, pt)

			extracted, err := ExtractPrincipalType(cert)
			require.NoError(t, err)
			require.Equal(t, pt, extracted)
		}
	})
}
