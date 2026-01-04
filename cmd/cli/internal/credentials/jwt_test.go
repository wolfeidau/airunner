package credentials

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTSigner_SignToken(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	// Create and import credential
	cred, err := store.Create("test-workers")
	require.NoError(t, err)

	err = store.Update("test-workers", "org-123", "principal-456")
	require.NoError(t, err)

	// Sign token
	signer := NewJWTSigner(store)
	token, err := signer.SignToken("test-workers", "https://api.example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse and verify claims
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(token, &Claims{})
	require.NoError(t, err)

	claims := parsed.Claims.(*Claims)
	assert.Equal(t, "airunner-cli", claims.Issuer)
	assert.Equal(t, cred.Fingerprint, claims.Subject)
	assert.Equal(t, "org-123", claims.Org)
	assert.Equal(t, "principal-456", claims.PrincipalID)
	assert.Equal(t, []string{"worker"}, claims.Roles)

	// Verify audience
	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Contains(t, aud, "https://api.example.com")

	// Verify kid header
	assert.Equal(t, cred.Fingerprint, parsed.Header["kid"])
}

func TestJWTSigner_NotImported(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	// Create but don't import
	_, err = store.Create("test-workers")
	require.NoError(t, err)

	signer := NewJWTSigner(store)
	_, err = signer.SignToken("test-workers", "https://api.example.com")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCredentialNotImported)
	assert.Contains(t, err.Error(), "has not been imported to the server")
}

func TestJWTSigner_CredentialNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	signer := NewJWTSigner(store)
	_, err = signer.SignToken("nonexistent", "https://api.example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestJWTSigner_TokenExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)

	err = store.Update("test-workers", "org-123", "principal-456")
	require.NoError(t, err)

	signer := NewJWTSigner(store)
	token, err := signer.SignToken("test-workers", "https://api.example.com")
	require.NoError(t, err)

	// Parse token
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(token, &Claims{})
	require.NoError(t, err)

	claims := parsed.Claims.(*Claims)

	// Verify expiry is set and approximately 1 hour from now
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, exp)

	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	require.NotNil(t, iat)

	// Check that expiry is approximately 1 hour after issued
	diff := exp.Sub(iat.Time)
	assert.InDelta(t, TokenExpiry.Seconds(), diff.Seconds(), 1.0)
}

func TestSignTokenWithKey(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	// Create credential to get a private key
	cred, err := store.Create("test-workers")
	require.NoError(t, err)

	privateKey, err := store.LoadPrivateKey("test-workers")
	require.NoError(t, err)

	// Sign token directly with key
	token, err := SignTokenWithKey(
		privateKey,
		cred.Fingerprint,
		"org-123",
		"principal-456",
		"https://api.example.com",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse and verify
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(token, &Claims{})
	require.NoError(t, err)

	claims := parsed.Claims.(*Claims)
	assert.Equal(t, "airunner-cli", claims.Issuer)
	assert.Equal(t, cred.Fingerprint, claims.Subject)
	assert.Equal(t, "org-123", claims.Org)
	assert.Equal(t, "principal-456", claims.PrincipalID)
	assert.Equal(t, []string{"worker"}, claims.Roles)
}
