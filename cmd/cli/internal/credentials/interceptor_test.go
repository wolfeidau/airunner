package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthInterceptor_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)
	err = store.Update("test-workers", "org-123", "principal-456")
	require.NoError(t, err)

	interceptor, err := NewAuthInterceptor(store, "test-workers", "https://api.example.com")
	require.NoError(t, err)
	assert.NotNil(t, interceptor)
	assert.Equal(t, "test-workers", interceptor.credName)
	assert.Equal(t, "https://api.example.com", interceptor.audience)
}

func TestNewAuthInterceptor_UsesDefault(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	// Create credential (will be set as default automatically)
	_, err = store.Create("default-cred")
	require.NoError(t, err)
	err = store.Update("default-cred", "org-123", "principal-456")
	require.NoError(t, err)

	// Create interceptor with empty credName - should use default
	interceptor, err := NewAuthInterceptor(store, "", "https://api.example.com")
	require.NoError(t, err)
	assert.NotNil(t, interceptor)
	assert.Equal(t, "default-cred", interceptor.credName)
}

func TestNewAuthInterceptor_NoDefault(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	// No credentials created, no default set
	_, err = NewAuthInterceptor(store, "", "https://api.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential specified")
}

func TestNewAuthInterceptor_CredentialNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	_, err = NewAuthInterceptor(store, "nonexistent", "https://api.example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestAuthInterceptor_GetAuthorizationHeader(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)
	err = store.Update("test-workers", "org-123", "principal-456")
	require.NoError(t, err)

	interceptor, err := NewAuthInterceptor(store, "test-workers", "https://api.example.com")
	require.NoError(t, err)

	// Get authorization header
	header, err := interceptor.GetAuthorizationHeader()
	require.NoError(t, err)
	assert.NotEmpty(t, header)
	assert.Contains(t, header, "Bearer ")
}

func TestAuthInterceptor_TokenCaching(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)
	err = store.Update("test-workers", "org-123", "principal-456")
	require.NoError(t, err)

	interceptor, err := NewAuthInterceptor(store, "test-workers", "https://api.example.com")
	require.NoError(t, err)

	// Get token twice - should return same cached token
	header1, err := interceptor.GetAuthorizationHeader()
	require.NoError(t, err)

	header2, err := interceptor.GetAuthorizationHeader()
	require.NoError(t, err)

	assert.Equal(t, header1, header2)
}

func TestAuthInterceptor_CredentialNotImported(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(tmpDir)
	require.NoError(t, err)

	// Create but don't import
	_, err = store.Create("test-workers")
	require.NoError(t, err)

	interceptor, err := NewAuthInterceptor(store, "test-workers", "https://api.example.com")
	require.NoError(t, err)

	// Try to get authorization header - should fail because not imported
	_, err = interceptor.GetAuthorizationHeader()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialNotImported)
}
