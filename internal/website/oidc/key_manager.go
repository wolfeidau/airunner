package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mr-tron/base58"
)

// KeyManager manages the website's ECDSA keypair for signing user JWTs.
// The website acts as an OIDC provider and signs JWTs on behalf of logged-in users.
type KeyManager struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	kid        string // Key ID (fingerprint)
}

// NewKeyManager creates a new KeyManager with a fresh ECDSA P-256 keypair.
// The key ID (kid) is computed as the base58-encoded SHA256 hash of the public key DER bytes.
func NewKeyManager() (*KeyManager, error) {
	// Generate ECDSA P-256 keypair for signing user JWTs
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Compute fingerprint as kid
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(pubKeyDER)
	kid := base58.Encode(hash[:])

	return &KeyManager{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        kid,
	}, nil
}

// Kid returns the key ID (fingerprint) for this keypair.
func (km *KeyManager) Kid() string {
	return km.kid
}

// SignJWT signs a JWT with the website's private key.
// The token header will include the kid for key identification.
func (km *KeyManager) SignJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = km.kid

	tokenString, err := token.SignedString(km.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// JWK returns the public key in JWK (JSON Web Key) format.
// This is used by the JWKS endpoint for API servers to fetch the public key.
func (km *KeyManager) JWK() map[string]any {
	return map[string]any{
		"kty": "EC",    // Key Type: Elliptic Curve
		"use": "sig",   // Public Key Use: Signature
		"crv": "P-256", // Curve: P-256
		"kid": km.kid,
		"x":   base64.RawURLEncoding.EncodeToString(km.publicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(km.publicKey.Y.Bytes()),
		"alg": "ES256",
	}
}
