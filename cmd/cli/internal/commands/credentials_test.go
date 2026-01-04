package commands

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
)

func TestCredentialsListCmd_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CredentialsListCmd{OutputDir: tmpDir}
	err := cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)
}

func TestCredentialsListCmd_WithCredentials(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some credentials
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers-1")
	require.NoError(t, err)
	_, err = store.Create("test-workers-2")
	require.NoError(t, err)

	// Run list command
	cmd := &CredentialsListCmd{OutputDir: tmpDir}
	err = cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)
}

func TestCredentialsShowCmd_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a credential
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)

	// Run show command
	cmd := &CredentialsShowCmd{
		Name:      "test-workers",
		OutputDir: tmpDir,
	}
	err = cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)
}

func TestCredentialsShowCmd_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CredentialsShowCmd{
		Name:      "nonexistent",
		OutputDir: tmpDir,
	}

	err := cmd.Run(context.Background(), &Globals{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCredentialsUpdateCmd_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a credential
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)

	// Run update command
	cmd := &CredentialsUpdateCmd{
		Name:        "test-workers",
		OrgID:       "org-123",
		PrincipalID: "principal-456",
		OutputDir:   tmpDir,
	}
	err = cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Verify it was updated
	cred, err := store.Get("test-workers")
	require.NoError(t, err)
	assert.Equal(t, "org-123", cred.OrgID)
	assert.Equal(t, "principal-456", cred.PrincipalID)
	assert.True(t, cred.IsImported())
}

func TestCredentialsUpdateCmd_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CredentialsUpdateCmd{
		Name:        "nonexistent",
		OrgID:       "org-123",
		PrincipalID: "principal-456",
		OutputDir:   tmpDir,
	}

	err := cmd.Run(context.Background(), &Globals{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCredentialsDeleteCmd_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a credential
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers")
	require.NoError(t, err)

	// Run delete command with force flag
	cmd := &CredentialsDeleteCmd{
		Name:      "test-workers",
		Force:     true,
		OutputDir: tmpDir,
	}
	err = cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Verify it was deleted
	_, err = store.Get("test-workers")
	require.Error(t, err)
	assert.ErrorIs(t, err, credentials.ErrCredentialNotFound)
}

func TestCredentialsDeleteCmd_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CredentialsDeleteCmd{
		Name:      "nonexistent",
		Force:     true,
		OutputDir: tmpDir,
	}

	err := cmd.Run(context.Background(), &Globals{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCredentialsSetDefaultCmd_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create credentials
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	_, err = store.Create("test-workers-1")
	require.NoError(t, err)
	_, err = store.Create("test-workers-2")
	require.NoError(t, err)

	// Run set-default command
	cmd := &CredentialsSetDefaultCmd{
		Name:      "test-workers-2",
		OutputDir: tmpDir,
	}
	err = cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Verify it was set as default
	defaultCred, err := store.GetDefault()
	require.NoError(t, err)
	assert.Equal(t, "test-workers-2", defaultCred.Name)
}

func TestCredentialsSetDefaultCmd_NotFound(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CredentialsSetDefaultCmd{
		Name:      "nonexistent",
		OutputDir: tmpDir,
	}

	err := cmd.Run(context.Background(), &Globals{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
