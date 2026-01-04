package credentials

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

const (
	// TokenExpiry is the duration after which a token expires.
	TokenExpiry = 1 * time.Hour

	// Issuer identifies tokens as CLI-generated.
	Issuer = "airunner-cli"
)

// JWTSigner creates and signs JWTs for API authentication.
type JWTSigner struct {
	store *Store
}

// NewJWTSigner creates a new JWT signer.
func NewJWTSigner(store *Store) *JWTSigner {
	return &JWTSigner{store: store}
}

// Claims represents the JWT claims for worker authentication.
type Claims struct {
	jwt.RegisteredClaims
	Org         string   `json:"org"`
	Roles       []string `json:"roles"`
	PrincipalID string   `json:"principal_id"`
}

// SignToken creates a signed JWT for the specified credential.
// Returns an error if the credential is not imported.
func (s *JWTSigner) SignToken(credName string, audience string) (string, error) {
	// Load credential metadata
	cred, err := s.store.Get(credName)
	if err != nil {
		return "", err
	}

	// Verify credential is imported
	if !cred.IsImported() {
		return "", fmt.Errorf("%w: credential %q has not been imported to the server\n\n"+
			"To import:\n"+
			"  1. Copy the public key: airunner-cli credentials show %s\n"+
			"  2. Import via web UI\n"+
			"  3. Update: airunner-cli credentials update %s --org-id <ORG_ID> --principal-id <PRINCIPAL_ID>",
			ErrCredentialNotImported, credName, credName, credName)
	}

	// Load private key
	privateKey, err := s.store.LoadPrivateKey(credName)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}

	// Create token
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   cred.Fingerprint, // Subject is the key fingerprint
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiry)),
		},
		Org:         cred.OrgID,
		Roles:       []string{"worker"},
		PrincipalID: cred.PrincipalID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Set kid header to fingerprint (server uses this to look up public key)
	token.Header["kid"] = cred.Fingerprint

	// Sign with private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	log.Debug().
		Str("credName", credName).
		Str("fingerprint", cred.Fingerprint).
		Str("audience", audience).
		Msg("signed JWT token")

	return tokenString, nil
}

// SignTokenWithKey creates a signed JWT using a provided private key.
// Used primarily for testing.
func SignTokenWithKey(
	privateKey *ecdsa.PrivateKey,
	fingerprint string,
	orgID string,
	principalID string,
	audience string,
) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   fingerprint,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiry)),
		},
		Org:         orgID,
		Roles:       []string{"worker"},
		PrincipalID: principalID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = fingerprint

	return token.SignedString(privateKey)
}
