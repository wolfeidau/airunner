package auth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/authn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

type jwtVerifier struct {
	publicKey *ecdsa.PublicKey
}

func newJWTVerifierFromPEM(publicKeyPEM string) (*jwtVerifier, error) {
	if publicKeyPEM == "" {
		return nil, errors.New("JWT public key not provided")
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil {
		return nil, err
	}

	return &jwtVerifier{publicKey: publicKey}, nil
}

// NewJWTAuthFunc returns an authn.AuthFunc that validates Bearer JWTs.
// The returned function extracts and validates JWT tokens from the Authorization header.
// On success, it returns the subject claim which can be retrieved via authn.GetInfo(ctx).
func NewJWTAuthFunc(publicKeyPEM string) (authn.AuthFunc, error) {
	v, err := newJWTVerifierFromPEM(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, req *http.Request) (any, error) {
		if req.URL.Path == "/health" {
			return nil, nil
		}

		tokenStr, ok := authn.BearerToken(req)
		if !ok {
			return nil, authn.Errorf("missing bearer token")
		}

		parsed, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodES256 {
				return nil, errors.New("invalid signing method")
			}
			return v.publicKey, nil
		})
		if err != nil {
			log.Debug().Err(err).Msg("JWT parse error")
			return nil, authn.Errorf("invalid token")
		}

		if !parsed.Valid {
			return nil, authn.Errorf("token invalid")
		}

		claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
		if !ok {
			return nil, authn.Errorf("invalid claims")
		}

		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			return nil, authn.Errorf("token expired")
		}

		return claims.Subject, nil
	}, nil
}
