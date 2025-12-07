package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func generateECKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createSignedToken(t *testing.T, privateKey *ecdsa.PrivateKey, claims *jwt.RegisteredClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenStr, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenStr
}

func generatePublicKeyPEM(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})
	require.NotNil(t, publicKeyPEM)
	return string(publicKeyPEM)
}

func TestNewJWTVerifierFromPEM(t *testing.T) {
	t.Run("empty public key", func(t *testing.T) {
		v, err := newJWTVerifierFromPEM("")
		require.Error(t, err)
		require.Nil(t, v)
		require.Equal(t, "JWT public key not provided", err.Error())
	})

	t.Run("invalid PEM", func(t *testing.T) {
		v, err := newJWTVerifierFromPEM("invalid pem")
		require.Error(t, err)
		require.Nil(t, v)
	})

	t.Run("valid public key PEM", func(t *testing.T) {
		_, publicKey, err := generateECKeyPair()
		require.NoError(t, err)

		publicKeyPEM := generatePublicKeyPEM(t, publicKey)
		v, err := newJWTVerifierFromPEM(publicKeyPEM)
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestNewJWTAuthFunc(t *testing.T) {
	t.Run("invalid public key", func(t *testing.T) {
		authFunc, err := NewJWTAuthFunc("invalid")
		require.Error(t, err)
		require.Nil(t, authFunc)
	})

	t.Run("valid public key", func(t *testing.T) {
		_, publicKey, err := generateECKeyPair()
		require.NoError(t, err)

		publicKeyPEM := generatePublicKeyPEM(t, publicKey)
		authFunc, err := NewJWTAuthFunc(publicKeyPEM)
		require.NoError(t, err)
		require.NotNil(t, authFunc)
	})
}

func TestJWTAuthFunc(t *testing.T) {
	privateKey, publicKey, err := generateECKeyPair()
	require.NoError(t, err)

	publicKeyPEM := generatePublicKeyPEM(t, publicKey)

	authFunc, err := NewJWTAuthFunc(publicKeyPEM)
	require.NoError(t, err)

	t.Run("health check endpoint", func(t *testing.T) {
		req := &http.Request{URL: &url.URL{Path: "/health"}}
		subject, err := authFunc(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, subject)
	})

	t.Run("missing bearer token", func(t *testing.T) {
		req := &http.Request{
			URL:    &url.URL{Path: "/api/test"},
			Header: http.Header{},
		}
		subject, err := authFunc(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, subject)
	})

	t.Run("valid token", func(t *testing.T) {
		now := time.Now()
		claims := &jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		}
		tokenStr := createSignedToken(t, privateKey, claims)

		req := &http.Request{
			URL: &url.URL{Path: "/api/test"},
			Header: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", tokenStr)},
			},
		}
		subject, err := authFunc(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, "user123", subject)
	})

	t.Run("expired token", func(t *testing.T) {
		now := time.Now()
		claims := &jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
		}
		tokenStr := createSignedToken(t, privateKey, claims)

		req := &http.Request{
			URL: &url.URL{Path: "/api/test"},
			Header: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", tokenStr)},
			},
		}
		subject, err := authFunc(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, subject)
	})

	t.Run("token without expiry", func(t *testing.T) {
		claims := &jwt.RegisteredClaims{
			Subject:   "user456",
			ExpiresAt: nil,
		}
		tokenStr := createSignedToken(t, privateKey, claims)

		req := &http.Request{
			URL: &url.URL{Path: "/api/test"},
			Header: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", tokenStr)},
			},
		}
		subject, err := authFunc(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, subject)
	})

	t.Run("token signed with wrong algorithm", func(t *testing.T) {
		now := time.Now()
		claims := &jwt.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		}
		// Sign with HS256 instead of ES256
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		req := &http.Request{
			URL: &url.URL{Path: "/api/test"},
			Header: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", tokenStr)},
			},
		}
		subject, err := authFunc(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, subject)
	})

	t.Run("malformed token", func(t *testing.T) {
		req := &http.Request{
			URL: &url.URL{Path: "/api/test"},
			Header: http.Header{
				"Authorization": []string{"Bearer invalid.token.string"},
			},
		}
		subject, err := authFunc(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, subject)
	})
}
