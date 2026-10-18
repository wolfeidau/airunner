package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// jwkFor encodes the coordinates of an uncompressed P-256 point as a JWK map.
func jwkFor(x, y []byte) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
}

func generateKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	point, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	return key, point
}

func TestParseJWK(t *testing.T) {
	t.Run("round trips a valid key", func(t *testing.T) {
		key, point := generateKey(t)

		got, err := parseJWK(jwkFor(point[1:33], point[33:]))
		require.NoError(t, err)
		require.True(t, key.PublicKey.Equal(got))
	})

	t.Run("accepts coordinates with leading zeros trimmed", func(t *testing.T) {
		var key *ecdsa.PrivateKey
		var point []byte
		for {
			key, point = generateKey(t)
			if point[1] == 0 {
				break
			}
		}

		got, err := parseJWK(jwkFor(point[2:33], point[33:]))
		require.NoError(t, err)
		require.True(t, key.PublicKey.Equal(got))
	})

	t.Run("rejects a point not on the curve", func(t *testing.T) {
		_, point := generateKey(t)
		y := append([]byte(nil), point[33:]...)
		y[31] ^= 0x01

		_, err := parseJWK(jwkFor(point[1:33], y))
		require.Error(t, err)
	})

	t.Run("rejects oversized coordinates", func(t *testing.T) {
		_, point := generateKey(t)
		x := append([]byte{0x01}, point[1:33]...)

		_, err := parseJWK(jwkFor(x, point[33:]))
		require.Error(t, err)
	})
}
