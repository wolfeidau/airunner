package credentials

import (
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	t.Run("creates directory with correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		credDir := filepath.Join(tmpDir, "creds")

		store, err := NewStore(credDir)
		require.NoError(t, err)
		assert.NotNil(t, store)

		// Verify directory exists
		info, err := os.Stat(credDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
	})

	t.Run("creates config.json on initialization", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		configPath := filepath.Join(tmpDir, "config.json")
		_, err = os.Stat(configPath)
		require.NoError(t, err)

		// Load and verify config
		cfg, err := store.loadConfig()
		require.NoError(t, err)
		assert.Equal(t, 1, cfg.Version)
		assert.Empty(t, cfg.DefaultCredential)
		assert.Empty(t, cfg.Credentials)
	})

	t.Run("uses default directory when baseDir is empty", func(t *testing.T) {
		// This test would use ~/.airunner/credentials/ which we don't want to pollute
		// So we'll just verify the logic by checking the error path
		store, err := NewStore("")
		// If home dir is available, this should succeed
		// If not, it should fail with a specific error
		if err != nil {
			assert.Contains(t, err.Error(), "home directory")
		} else {
			assert.NotNil(t, store)
		}
	})
}

func TestStore_Create(t *testing.T) {
	t.Run("generates valid keypair", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		cred, err := store.Create("test-workers")
		require.NoError(t, err)
		assert.Equal(t, "test-workers", cred.Name)
		assert.NotEmpty(t, cred.Fingerprint)
		assert.False(t, cred.Imported)
		assert.Empty(t, cred.OrgID)
		assert.Empty(t, cred.PrincipalID)
		assert.False(t, cred.CreatedAt.IsZero())
		assert.False(t, cred.UpdatedAt.IsZero())
	})

	t.Run("creates key files with correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		// Verify private key exists with 0600 permissions
		privateKeyPath := filepath.Join(tmpDir, "test-workers.key")
		info, err := os.Stat(privateKeyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

		// Verify public key exists with 0644 permissions
		publicKeyPath := filepath.Join(tmpDir, "test-workers.pub")
		info, err = os.Stat(publicKeyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
	})

	t.Run("updates config with credential metadata", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		cred, err := store.Create("test-workers")
		require.NoError(t, err)

		// Verify config was updated
		cfg, err := store.loadConfig()
		require.NoError(t, err)
		assert.Len(t, cfg.Credentials, 1)
		assert.Equal(t, cred.Name, cfg.Credentials["test-workers"].Name)
		assert.Equal(t, cred.Fingerprint, cfg.Credentials["test-workers"].Fingerprint)
	})

	t.Run("sets as default when first credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		cfg, err := store.loadConfig()
		require.NoError(t, err)
		assert.Equal(t, "test-workers", cfg.DefaultCredential)
	})

	t.Run("returns error for duplicate name", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		assert.ErrorIs(t, err, ErrCredentialExists)
	})

	t.Run("cleans up on failure", func(t *testing.T) {
		// This is harder to test without mocking, but we can verify the cleanup logic
		// by checking that key files don't exist after an error
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		// Create a credential successfully first
		_, err = store.Create("test1")
		require.NoError(t, err)

		// Try to create a duplicate - should not leave orphaned files
		_, err = store.Create("test1")
		require.ErrorIs(t, err, ErrCredentialExists)

		// Verify no extra files were created
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		// Should have: config.json, test1.key, test1.pub
		assert.Len(t, entries, 3)
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("retrieves existing credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		created, err := store.Create("test-workers")
		require.NoError(t, err)

		retrieved, err := store.Get("test-workers")
		require.NoError(t, err)
		assert.Equal(t, created.Name, retrieved.Name)
		assert.Equal(t, created.Fingerprint, retrieved.Fingerprint)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Get("non-existent")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})
}

func TestStore_GetDefault(t *testing.T) {
	t.Run("returns default credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		defaultCred, err := store.GetDefault()
		require.NoError(t, err)
		assert.Equal(t, "test-workers", defaultCred.Name)
	})

	t.Run("returns error when no default set", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.GetDefault()
		assert.ErrorIs(t, err, ErrNoDefaultCredential)
	})
}

func TestStore_List(t *testing.T) {
	t.Run("returns empty list initially", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		creds, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, creds)
	})

	t.Run("returns all credentials", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers-1")
		require.NoError(t, err)
		_, err = store.Create("test-workers-2")
		require.NoError(t, err)

		creds, err := store.List()
		require.NoError(t, err)
		assert.Len(t, creds, 2)

		names := make(map[string]bool)
		for _, cred := range creds {
			names[cred.Name] = true
		}
		assert.True(t, names["test-workers-1"])
		assert.True(t, names["test-workers-2"])
	})
}

func TestStore_Update(t *testing.T) {
	t.Run("updates credential metadata", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		err = store.Update("test-workers", "org-123", "principal-456")
		require.NoError(t, err)

		cred, err := store.Get("test-workers")
		require.NoError(t, err)
		assert.Equal(t, "org-123", cred.OrgID)
		assert.Equal(t, "principal-456", cred.PrincipalID)
		assert.True(t, cred.Imported)
	})

	t.Run("updates UpdatedAt timestamp", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		cred, err := store.Create("test-workers")
		require.NoError(t, err)
		originalUpdated := cred.UpdatedAt

		err = store.Update("test-workers", "org-123", "principal-456")
		require.NoError(t, err)

		updated, err := store.Get("test-workers")
		require.NoError(t, err)
		assert.True(t, updated.UpdatedAt.After(originalUpdated))
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		err = store.Update("non-existent", "org-123", "principal-456")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("removes credential and key files", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		err = store.Delete("test-workers")
		require.NoError(t, err)

		// Verify credential removed from config
		_, err = store.Get("test-workers")
		require.ErrorIs(t, err, ErrCredentialNotFound)

		// Verify key files removed
		_, err = os.Stat(filepath.Join(tmpDir, "test-workers.key"))
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(filepath.Join(tmpDir, "test-workers.pub"))
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("clears default if deleting default credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		err = store.Delete("test-workers")
		require.NoError(t, err)

		cfg, err := store.loadConfig()
		require.NoError(t, err)
		assert.Empty(t, cfg.DefaultCredential)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		err = store.Delete("non-existent")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})
}

func TestStore_SetDefault(t *testing.T) {
	t.Run("sets default credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers-1")
		require.NoError(t, err)
		_, err = store.Create("test-workers-2")
		require.NoError(t, err)

		err = store.SetDefault("test-workers-2")
		require.NoError(t, err)

		defaultCred, err := store.GetDefault()
		require.NoError(t, err)
		assert.Equal(t, "test-workers-2", defaultCred.Name)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		err = store.SetDefault("non-existent")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})
}

func TestStore_LoadPrivateKey(t *testing.T) {
	t.Run("loads valid private key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		cred, err := store.Create("test-workers")
		require.NoError(t, err)

		privateKey, err := store.LoadPrivateKey("test-workers")
		require.NoError(t, err)
		assert.NotNil(t, privateKey)

		// Verify fingerprint matches
		publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		hash := sha256.Sum256(publicKeyDER)
		fingerprint := base58.Encode(hash[:])
		assert.Equal(t, cred.Fingerprint, fingerprint)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.LoadPrivateKey("non-existent")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})

	t.Run("returns error for missing key file", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		// Remove the key file
		os.Remove(filepath.Join(tmpDir, "test-workers.key"))

		_, err = store.LoadPrivateKey("test-workers")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})

	t.Run("returns error for invalid key file", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		// Corrupt the key file
		keyPath := filepath.Join(tmpDir, "test-workers.key")
		err = os.WriteFile(keyPath, []byte("invalid key data"), 0600)
		require.NoError(t, err)

		_, err = store.LoadPrivateKey("test-workers")
		assert.ErrorIs(t, err, ErrInvalidPrivateKey)
	})
}

func TestStore_LoadPublicKeyPEM(t *testing.T) {
	t.Run("loads public key PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		pem, err := store.LoadPublicKeyPEM("test-workers")
		require.NoError(t, err)
		assert.Contains(t, pem, "BEGIN PUBLIC KEY")
		assert.Contains(t, pem, "END PUBLIC KEY")
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.LoadPublicKeyPEM("non-existent")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})

	t.Run("returns error for missing public key file", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		_, err = store.Create("test-workers")
		require.NoError(t, err)

		// Remove the public key file
		os.Remove(filepath.Join(tmpDir, "test-workers.pub"))

		_, err = store.LoadPublicKeyPEM("test-workers")
		assert.ErrorIs(t, err, ErrCredentialNotFound)
	})
}

func TestCredential_IsImported(t *testing.T) {
	tests := []struct {
		name     string
		cred     Credential
		expected bool
	}{
		{
			name:     "not imported",
			cred:     Credential{Imported: false},
			expected: false,
		},
		{
			name:     "imported flag only",
			cred:     Credential{Imported: true},
			expected: false,
		},
		{
			name:     "imported with org_id only",
			cred:     Credential{Imported: true, OrgID: "org-123"},
			expected: false,
		},
		{
			name:     "imported with principal_id only",
			cred:     Credential{Imported: true, PrincipalID: "p-456"},
			expected: false,
		},
		{
			name:     "fully imported",
			cred:     Credential{Imported: true, OrgID: "org-123", PrincipalID: "p-456"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cred.IsImported())
		})
	}
}

func TestStore_AtomicConfigUpdate(t *testing.T) {
	t.Run("config updates are atomic", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := NewStore(tmpDir)
		require.NoError(t, err)

		// Create multiple credentials
		_, err = store.Create("cred1")
		require.NoError(t, err)
		_, err = store.Create("cred2")
		require.NoError(t, err)

		// Verify config.json.tmp doesn't exist after successful operation
		tmpPath := filepath.Join(tmpDir, "config.json.tmp")
		_, err = os.Stat(tmpPath)
		assert.True(t, os.IsNotExist(err))
	})
}
