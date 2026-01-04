package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mr-tron/base58"
	"github.com/rs/zerolog/log"
)

// Sentinel errors
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

	log.Debug().Str("baseDir", baseDir).Msg("credential store initialized")

	return store, nil
}

// Create generates a new ECDSA P-256 keypair and stores it.
// Returns the credential metadata including fingerprint.
func (s *Store) Create(name string) (*Credential, error) {
	// Check if credential already exists
	if _, err := s.Get(name); err == nil {
		return nil, ErrCredentialExists
	}

	log.Info().Str("name", name).Msg("generating new credential")

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

	log.Debug().
		Str("name", name).
		Str("fingerprint", fingerprint).
		Msg("generated key fingerprint")

	// Write private key (0600 permissions)
	privateKeyPath := filepath.Join(s.baseDir, name+".key")
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key (0644 permissions)
	publicKeyPath := filepath.Join(s.baseDir, name+".pub")
	// #nosec G306 - Public key files are intentionally world-readable per spec
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

	log.Info().
		Str("name", name).
		Str("fingerprint", fingerprint).
		Str("privateKeyPath", privateKeyPath).
		Str("publicKeyPath", publicKeyPath).
		Msg("credential created successfully")

	return &cred, nil
}

// Get retrieves credential metadata by name.
func (s *Store) Get(name string) (*Credential, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}

	cred, ok := cfg.Credentials[name]
	if !ok {
		return nil, ErrCredentialNotFound
	}

	return &cred, nil
}

// GetDefault retrieves the default credential.
// Returns ErrNoDefaultCredential if none is set.
func (s *Store) GetDefault() (*Credential, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}

	if cfg.DefaultCredential == "" {
		return nil, ErrNoDefaultCredential
	}

	return s.Get(cfg.DefaultCredential)
}

// List returns all stored credentials.
func (s *Store) List() ([]Credential, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}

	credentials := make([]Credential, 0, len(cfg.Credentials))
	for _, cred := range cfg.Credentials {
		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// Update updates credential metadata (org_id, principal_id, imported status).
func (s *Store) Update(name string, orgID, principalID string) error {
	cfg, err := s.loadConfig()
	if err != nil {
		return err
	}

	cred, ok := cfg.Credentials[name]
	if !ok {
		return ErrCredentialNotFound
	}

	cred.OrgID = orgID
	cred.PrincipalID = principalID
	cred.Imported = true
	cred.UpdatedAt = time.Now().UTC()

	cfg.Credentials[name] = cred

	if err := s.saveConfig(cfg); err != nil {
		return err
	}

	log.Info().
		Str("name", name).
		Str("orgID", orgID).
		Str("principalID", principalID).
		Msg("credential updated")

	return nil
}

// Delete removes a credential and its key files.
func (s *Store) Delete(name string) error {
	cfg, err := s.loadConfig()
	if err != nil {
		return err
	}

	if _, ok := cfg.Credentials[name]; !ok {
		return ErrCredentialNotFound
	}

	// Remove key files
	privateKeyPath := filepath.Join(s.baseDir, name+".key")
	publicKeyPath := filepath.Join(s.baseDir, name+".pub")

	if err := os.Remove(privateKeyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove private key: %w", err)
	}

	if err := os.Remove(publicKeyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove public key: %w", err)
	}

	// Remove from config
	delete(cfg.Credentials, name)

	// Clear default if this was the default credential
	if cfg.DefaultCredential == name {
		cfg.DefaultCredential = ""
	}

	if err := s.saveConfig(cfg); err != nil {
		return err
	}

	log.Info().Str("name", name).Msg("credential deleted")

	return nil
}

// SetDefault sets the default credential.
func (s *Store) SetDefault(name string) error {
	cfg, err := s.loadConfig()
	if err != nil {
		return err
	}

	if _, ok := cfg.Credentials[name]; !ok {
		return ErrCredentialNotFound
	}

	cfg.DefaultCredential = name

	if err := s.saveConfig(cfg); err != nil {
		return err
	}

	log.Info().Str("name", name).Msg("default credential set")

	return nil
}

// LoadPrivateKey loads the private key for signing JWTs.
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

	log.Debug().Str("name", name).Msg("private key loaded")

	return privateKey, nil
}

// LoadPublicKeyPEM returns the public key in PEM format (for display/import).
func (s *Store) LoadPublicKeyPEM(name string) (string, error) {
	// Verify credential exists in config
	if _, err := s.Get(name); err != nil {
		return "", err
	}

	publicKeyPath := filepath.Join(s.baseDir, name+".pub")
	pemData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrCredentialNotFound
		}
		return "", fmt.Errorf("failed to read public key: %w", err)
	}

	return string(pemData), nil
}

// ensureConfig creates an empty config if it doesn't exist.
func (s *Store) ensureConfig() error {
	configPath := filepath.Join(s.baseDir, "config.json")

	// Check if config exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // Config exists
	}

	// Create empty config
	cfg := &Config{
		Version:     1,
		Credentials: make(map[string]Credential),
	}

	return s.saveConfig(cfg)
}

// loadConfig reads the config file.
func (s *Store) loadConfig() (*Config, error) {
	configPath := filepath.Join(s.baseDir, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Ensure credentials map is initialized
	if cfg.Credentials == nil {
		cfg.Credentials = make(map[string]Credential)
	}

	return &cfg, nil
}

// saveConfig writes the config file atomically.
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

// addCredential adds a new credential to the config.
func (s *Store) addCredential(cred Credential) error {
	cfg, err := s.loadConfig()
	if err != nil {
		return err
	}

	cfg.Credentials[cred.Name] = cred

	// Set as default if this is the first credential
	if len(cfg.Credentials) == 1 {
		cfg.DefaultCredential = cred.Name
	}

	return s.saveConfig(cfg)
}
