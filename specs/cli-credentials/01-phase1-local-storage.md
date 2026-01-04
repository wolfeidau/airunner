# Phase 1: Local Credential Storage

[← README](README.md) | [← Architecture](00-architecture.md) | [Phase 2: CLI Commands →](02-phase2-cli-commands.md)

## Goal

Implement the credential storage package that manages keypairs and configuration in `~/.airunner/credentials/`.

## Prerequisites

- Read [Architecture](00-architecture.md) for config schema and directory structure
- Go 1.21+ with crypto/ecdsa support

## Success Criteria

- [ ] `CredentialStore` can create new ECDSA P-256 keypairs
- [ ] Private keys saved with 0600 permissions
- [ ] Public keys saved with 0644 permissions
- [ ] Config.json updated atomically on changes
- [ ] Fingerprint calculation matches server implementation
- [ ] All credentials can be listed with metadata
- [ ] Individual credentials can be loaded, updated, and deleted

## File to Create

`cmd/cli/internal/credentials/store.go`

## Interfaces

```go
package credentials

import (
    "crypto/ecdsa"
    "time"
)

// Credential represents a stored credential with its metadata.
type Credential struct {
    Name        string    `json:"name"`
    Fingerprint string    `json:"fingerprint"`
    OrgID       string    `json:"org_id,omitempty"`
    PrincipalID string    `json:"principal_id,omitempty"`
    Imported    bool      `json:"imported"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// IsImported returns true if the credential has been imported to the server.
func (c *Credential) IsImported() bool {
    return c.Imported && c.OrgID != "" && c.PrincipalID != ""
}

// Config represents the credentials configuration file.
type Config struct {
    Version           int                   `json:"version"`
    DefaultCredential string                `json:"default_credential,omitempty"`
    Credentials       map[string]Credential `json:"credentials"`
}

// Store manages credential storage on the local filesystem.
type Store struct {
    baseDir string
}

// NewStore creates a new credential store.
// If baseDir is empty, uses ~/.airunner/credentials/
func NewStore(baseDir string) (*Store, error)

// Create generates a new ECDSA P-256 keypair and stores it.
// Returns the credential metadata including fingerprint.
func (s *Store) Create(name string) (*Credential, error)

// Get retrieves credential metadata by name.
func (s *Store) Get(name string) (*Credential, error)

// GetDefault retrieves the default credential.
// Returns ErrNoDefaultCredential if none is set.
func (s *Store) GetDefault() (*Credential, error)

// List returns all stored credentials.
func (s *Store) List() ([]Credential, error)

// Update updates credential metadata (org_id, principal_id, imported status).
func (s *Store) Update(name string, orgID, principalID string) error

// Delete removes a credential and its key files.
func (s *Store) Delete(name string) error

// SetDefault sets the default credential.
func (s *Store) SetDefault(name string) error

// LoadPrivateKey loads the private key for signing JWTs.
func (s *Store) LoadPrivateKey(name string) (*ecdsa.PrivateKey, error)

// LoadPublicKeyPEM returns the public key in PEM format (for display/import).
func (s *Store) LoadPublicKeyPEM(name string) (string, error)
```

## Errors

```go
var (
    // ErrCredentialNotFound is returned when a credential doesn't exist.
    ErrCredentialNotFound = errors.New("credential not found")

    // ErrCredentialExists is returned when trying to create a duplicate.
    ErrCredentialExists = errors.New("credential already exists")

    // ErrCredentialNotImported is returned when using an unimported credential.
    ErrCredentialNotImported = errors.New("credential not imported")

    // ErrNoDefaultCredential is returned when no default is set.
    ErrNoDefaultCredential = errors.New("no default credential set")

    // ErrInvalidPrivateKey is returned when the private key file is invalid.
    ErrInvalidPrivateKey = errors.New("invalid private key")
)
```

## Implementation Details

### Directory Initialization

```go
func NewStore(baseDir string) (*Store, error) {
    if baseDir == "" {
        home, err := os.UserHomeDir()
        if err != nil {
            return nil, fmt.Errorf("failed to get home directory: %w", err)
        }
        baseDir = filepath.Join(home, ".airunner", "credentials")
    }

    // Create directory with 0700 permissions
    if err := os.MkdirAll(baseDir, 0700); err != nil {
        return nil, fmt.Errorf("failed to create credentials directory: %w", err)
    }

    store := &Store{baseDir: baseDir}

    // Initialize config if it doesn't exist
    if err := store.ensureConfig(); err != nil {
        return nil, err
    }

    return store, nil
}
```

### Key Generation

```go
func (s *Store) Create(name string) (*Credential, error) {
    // Check if credential already exists
    if _, err := s.Get(name); err == nil {
        return nil, ErrCredentialExists
    }

    // Generate ECDSA P-256 keypair
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate key: %w", err)
    }

    // Encode private key to PEM
    privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal private key: %w", err)
    }
    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: privateKeyDER,
    })

    // Encode public key to PEM
    publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }
    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyDER,
    })

    // Calculate fingerprint (Base58-encoded SHA256 of public key DER)
    hash := sha256.Sum256(publicKeyDER)
    fingerprint := base58.Encode(hash[:])

    // Write private key (0600 permissions)
    privateKeyPath := filepath.Join(s.baseDir, name+".key")
    if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
        return nil, fmt.Errorf("failed to write private key: %w", err)
    }

    // Write public key (0644 permissions)
    publicKeyPath := filepath.Join(s.baseDir, name+".pub")
    if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
        // Clean up private key on failure
        os.Remove(privateKeyPath)
        return nil, fmt.Errorf("failed to write public key: %w", err)
    }

    // Update config
    now := time.Now().UTC()
    cred := Credential{
        Name:        name,
        Fingerprint: fingerprint,
        Imported:    false,
        CreatedAt:   now,
        UpdatedAt:   now,
    }

    if err := s.addCredential(cred); err != nil {
        // Clean up key files on failure
        os.Remove(privateKeyPath)
        os.Remove(publicKeyPath)
        return nil, err
    }

    return &cred, nil
}
```

### Atomic Config Updates

```go
func (s *Store) saveConfig(cfg *Config) error {
    data, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal config: %w", err)
    }

    // Write to temp file first
    configPath := filepath.Join(s.baseDir, "config.json")
    tempPath := configPath + ".tmp"

    if err := os.WriteFile(tempPath, data, 0600); err != nil {
        return fmt.Errorf("failed to write config: %w", err)
    }

    // Atomic rename
    if err := os.Rename(tempPath, configPath); err != nil {
        os.Remove(tempPath)
        return fmt.Errorf("failed to save config: %w", err)
    }

    return nil
}
```

### Loading Private Key

```go
func (s *Store) LoadPrivateKey(name string) (*ecdsa.PrivateKey, error) {
    // Verify credential exists in config
    if _, err := s.Get(name); err != nil {
        return nil, err
    }

    privateKeyPath := filepath.Join(s.baseDir, name+".key")
    pemData, err := os.ReadFile(privateKeyPath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, ErrCredentialNotFound
        }
        return nil, fmt.Errorf("failed to read private key: %w", err)
    }

    block, _ := pem.Decode(pemData)
    if block == nil {
        return nil, ErrInvalidPrivateKey
    }

    privateKey, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
    }

    return privateKey, nil
}
```

## Testing

Create `cmd/cli/internal/credentials/store_test.go`:

```go
func TestStore_Create(t *testing.T) {
    // Use temp directory
    tmpDir := t.TempDir()
    store, err := NewStore(tmpDir)
    require.NoError(t, err)

    // Create credential
    cred, err := store.Create("test-workers")
    require.NoError(t, err)
    assert.Equal(t, "test-workers", cred.Name)
    assert.NotEmpty(t, cred.Fingerprint)
    assert.False(t, cred.Imported)

    // Verify files exist
    _, err = os.Stat(filepath.Join(tmpDir, "test-workers.key"))
    assert.NoError(t, err)
    _, err = os.Stat(filepath.Join(tmpDir, "test-workers.pub"))
    assert.NoError(t, err)

    // Verify private key permissions
    info, _ := os.Stat(filepath.Join(tmpDir, "test-workers.key"))
    assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestStore_CreateDuplicate(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := NewStore(tmpDir)

    _, err := store.Create("test-workers")
    require.NoError(t, err)

    _, err = store.Create("test-workers")
    assert.ErrorIs(t, err, ErrCredentialExists)
}

func TestStore_Update(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := NewStore(tmpDir)

    _, err := store.Create("test-workers")
    require.NoError(t, err)

    err = store.Update("test-workers", "org-123", "principal-456")
    require.NoError(t, err)

    cred, err := store.Get("test-workers")
    require.NoError(t, err)
    assert.Equal(t, "org-123", cred.OrgID)
    assert.Equal(t, "principal-456", cred.PrincipalID)
    assert.True(t, cred.Imported)
}

func TestStore_LoadPrivateKey(t *testing.T) {
    tmpDir := t.TempDir()
    store, _ := NewStore(tmpDir)

    cred, err := store.Create("test-workers")
    require.NoError(t, err)

    privateKey, err := store.LoadPrivateKey("test-workers")
    require.NoError(t, err)
    assert.NotNil(t, privateKey)

    // Verify fingerprint matches
    publicKeyDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
    hash := sha256.Sum256(publicKeyDER)
    fingerprint := base58.Encode(hash[:])
    assert.Equal(t, cred.Fingerprint, fingerprint)
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
```

## Verification

After implementing, verify:

```bash
# Run tests
go test ./cmd/cli/internal/credentials/...

# Manual verification
go run ./cmd/cli init test-cred
ls -la ~/.airunner/credentials/
cat ~/.airunner/credentials/config.json
```

---

[← README](README.md) | [← Architecture](00-architecture.md) | [Phase 2: CLI Commands →](02-phase2-cli-commands.md)
