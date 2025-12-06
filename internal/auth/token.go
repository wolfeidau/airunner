package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueToken creates a signed JWT token for the given subject.
// signingKeyPEM is the PEM-encoded ECDSA private key.
func IssueToken(signingKeyPEM string, subject string, ttl time.Duration) (string, error) {
	signingKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(signingKeyPEM))
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := &jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Issuer:    "airunner",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(signingKey)
}
