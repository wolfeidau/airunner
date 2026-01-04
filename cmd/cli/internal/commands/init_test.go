package commands

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
)

func TestInitCmd_Run(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &InitCmd{
		Name:      "test-workers",
		OutputDir: tmpDir,
	}

	err := cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Verify files created
	_, err = os.Stat(filepath.Join(tmpDir, "test-workers.key"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, "test-workers.pub"))
	require.NoError(t, err)

	// Verify credential was added to config
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	cred, err := store.Get("test-workers")
	require.NoError(t, err)
	assert.Equal(t, "test-workers", cred.Name)
	assert.NotEmpty(t, cred.Fingerprint)
	assert.False(t, cred.IsImported())
}

func TestInitCmd_Duplicate(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &InitCmd{
		Name:      "test-workers",
		OutputDir: tmpDir,
	}

	// First creation should succeed
	err := cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Try to create duplicate - should fail
	err = cmd.Run(context.Background(), &Globals{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestInitCmd_SetDefault(t *testing.T) {
	tmpDir := t.TempDir()

	// Create first credential without set-default
	cmd1 := &InitCmd{
		Name:       "test-workers-1",
		SetDefault: false,
		OutputDir:  tmpDir,
	}
	err := cmd1.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Create second credential with set-default
	cmd2 := &InitCmd{
		Name:       "test-workers-2",
		SetDefault: true,
		OutputDir:  tmpDir,
	}
	err = cmd2.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Verify second credential is now default
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	defaultCred, err := store.GetDefault()
	require.NoError(t, err)
	assert.Equal(t, "test-workers-2", defaultCred.Name)
}

func TestInitCmd_AutoDefaultForFirstCredential(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &InitCmd{
		Name:       "test-workers",
		SetDefault: false, // Not explicitly setting as default
		OutputDir:  tmpDir,
	}

	err := cmd.Run(context.Background(), &Globals{})
	require.NoError(t, err)

	// Verify it's automatically set as default since it's the first credential
	store, err := credentials.NewStore(tmpDir)
	require.NoError(t, err)

	defaultCred, err := store.GetDefault()
	require.NoError(t, err)
	assert.Equal(t, "test-workers", defaultCred.Name)
}
