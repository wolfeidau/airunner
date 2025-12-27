# Phase 1: Create internal/tlscerts Package

[← README](README.md) | [← Architecture](00-architecture.md) | [Phase 2 →](02-phase2-integration.md)

## Goal

Create a reusable, well-tested `internal/tlscerts` package for loading TLS certificates from either bundles or individual files.

**Duration:** ~45 minutes

## Prerequisites

- Completed reading [00-architecture.md](00-architecture.md)
- Go development environment set up
- Understanding of PEM certificate format

## Success Criteria

- [ ] `internal/tlscerts/loader.go` created with complete API
- [ ] `internal/tlscerts/loader_test.go` created with comprehensive tests
- [ ] All unit tests pass
- [ ] Test coverage > 80%
- [ ] Package can load from bundles and individual files
- [ ] Error handling is robust

## Implementation Steps

### Step 1: Create Package Structure

Create the package directory and main file:

```bash
mkdir -p internal/tlscerts
touch internal/tlscerts/loader.go
touch internal/tlscerts/loader_test.go
```

### Step 2: Implement loader.go

Create `internal/tlscerts/loader.go` with the following structure:

#### 2.1 Package Declaration and Imports

```go
package tlscerts

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)
```

#### 2.2 Config Struct

```go
// Config specifies how to load TLS certificates
type Config struct {
	// Bundle approach (client cert + CA cert in one file)
	CertBundle string // Path to certificate bundle
	ClientKey  string // Path to private key

	// Individual files approach (backward compatibility)
	CACert     string // Path to CA certificate
	ClientCert string // Path to client certificate
}
```

**Design notes:**
- `CertBundle` takes precedence if both bundle and individual files are provided
- `ClientKey` is required for both approaches
- Individual files require both `CACert` and `ClientCert`

#### 2.3 Certificates Struct

```go
// Certificates holds certificate data in memory
type Certificates struct {
	ClientCert []byte // Client certificate PEM
	ClientKey  []byte // Client private key PEM
	CACerts    []byte // CA certificate(s) PEM
}
```

**Design notes:**
- Stores PEM-encoded data in memory (not parsed certificates)
- Keeps data as byte slices for maximum flexibility
- CA certs can contain multiple certificates (chain)

#### 2.4 Load Function

```go
// Load loads certificates from either a bundle or individual files
func Load(config Config) (*Certificates, error) {
	certs := &Certificates{}

	// Load client private key (required for both approaches)
	if config.ClientKey == "" {
		return nil, fmt.Errorf("client key is required")
	}
	keyData, err := os.ReadFile(config.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}
	certs.ClientKey = keyData

	// Load certificates from bundle or individual files
	if config.CertBundle != "" {
		// Load from bundle
		bundleData, err := os.ReadFile(config.CertBundle)
		if err != nil {
			return nil, fmt.Errorf("failed to read cert bundle: %w", err)
		}

		clientCert, caCerts, err := parseBundle(bundleData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cert bundle: %w", err)
		}

		certs.ClientCert = clientCert
		certs.CACerts = caCerts
	} else {
		// Load from individual files
		if config.ClientCert == "" || config.CACert == "" {
			return nil, fmt.Errorf("client cert and CA cert are required")
		}

		clientCert, err := os.ReadFile(config.ClientCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read client cert: %w", err)
		}
		certs.ClientCert = clientCert

		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		certs.CACerts = caCert
	}

	return certs, nil
}
```

**Key logic:**
1. Private key is always required first
2. If `CertBundle` is provided, load from bundle
3. Otherwise, load from individual files
4. All file reads wrapped with helpful error messages

#### 2.5 parseBundle Function

```go
// parseBundle parses a PEM bundle containing client cert + CA cert(s)
// Returns: (clientCertPEM, caCertsPEM, error)
func parseBundle(bundleData []byte) ([]byte, []byte, error) {
	var certBlocks []*pem.Block

	// Parse all PEM blocks from bundle
	rest := bundleData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certBlocks = append(certBlocks, block)
		}
	}

	if len(certBlocks) < 2 {
		return nil, nil, fmt.Errorf("cert bundle must contain at least 2 certificates (client cert + CA cert)")
	}

	// First certificate is the client cert
	clientCertPEM := pem.EncodeToMemory(certBlocks[0])

	// Remaining certificates are CA certs
	var caCertsPEM []byte
	for _, block := range certBlocks[1:] {
		caCertsPEM = append(caCertsPEM, pem.EncodeToMemory(block)...)
	}

	return clientCertPEM, caCertsPEM, nil
}
```

**Key logic:**
1. Iterate through all PEM blocks in bundle
2. Filter for CERTIFICATE type blocks only
3. Require at least 2 certificates (client + CA)
4. First cert is client cert, rest are CA chain
5. Re-encode as PEM for consistency

#### 2.6 TLSConfig Method

```go
// TLSConfig creates a tls.Config from the certificates
func (c *Certificates) TLSConfig() (*tls.Config, error) {
	// Create X509KeyPair from client cert and key
	clientCert, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	// Parse CA certificates
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(c.CACerts) {
		return nil, fmt.Errorf("failed to parse CA certificates")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
```

**Key logic:**
1. Use Go's `tls.X509KeyPair()` to parse client cert + key
2. Use `x509.NewCertPool()` + `AppendCertsFromPEM()` for CA certs
3. Configure TLS 1.2 minimum version
4. Return ready-to-use tls.Config

#### 2.7 Validate Method

```go
// Validate validates that certificate data is valid PEM
func (c *Certificates) Validate() error {
	// Validate CA certs
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(c.CACerts) {
		return fmt.Errorf("invalid CA certificate PEM")
	}

	// Validate client cert/key pair
	_, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		return fmt.Errorf("invalid client certificate/key: %w", err)
	}

	return nil
}
```

**Key logic:**
1. Validates CA certs can be parsed as PEM
2. Validates client cert and key match
3. Does NOT check certificate validity/expiration (happens during handshake)

### Step 3: Implement loader_test.go

Create `internal/tlscerts/loader_test.go` with comprehensive tests:

#### 3.1 Test Fixtures Setup

```go
package tlscerts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// setupTestCerts creates temporary test certificate files
func setupTestCerts(t *testing.T) (string, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "tlscerts-test-*")
	require.NoError(t, err)

	// Client certificate (valid PEM)
	clientCertPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6nqMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBUxEzARBgNVBAMM
CnRlc3RjbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATXUvXBkHVPZjGD
qYB4vQgBj3vE4Rp6fGPPfhNb0mGjgQHPqVz8UoFQF8nE3YjHXzC9ZnT8m2QJKB8P
5kQvLzNWMA0GCSqGSIb3DQEBCwUAA0EAGPkFjQkjFZGZ8MfJ0WCNqGc8qF0WJNXP
KlF7QGZGFkWJKLXPjGZXPKLFQGZPFKLWJNXPKLFQGZ=
-----END CERTIFICATE-----`

	// CA certificate (valid PEM)
	caCertPEM := `-----BEGIN CERTIFICATE-----
MIIBeDCCAR6gAwIBAgIJAKHHCgVZU6npMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMMBnRlc3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzAN
BgNVBAMMBnRlc3RjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNdS9cGQdU9m
MYOpgHi9CAGPe8ThGnp8Y89+E1vSYaOBAc+pXPxSgVAXycTdiMdfML1mdPybZAko
Hw/mRC8vM1ajUDBOMB0GA1UdDgQWBBQX8fPQKBGGF7Z8jHGXPFKL=
-----END CERTIFICATE-----`

	// Client private key (valid PEM)
	clientKeyPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKrH4vkK7nJFKLXPjGZXPKLFQGZPFKLWJNXPKLFQGZoAoGCCqGSM49
AwEHoUQDQgAE11L1wZB1T2Yxg6mAeL0IAY97xOEaenxjz34TW9Jho4EBz6lc/FKB
UBfJxN2Ix18wvWZ0/JtkCSgfD+ZELy8zVg==
-----END EC PRIVATE KEY-----`

	// Write test files
	clientCertPath := filepath.Join(tmpDir, "client-cert.pem")
	caCertPath := filepath.Join(tmpDir, "ca-cert.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")
	bundlePath := filepath.Join(tmpDir, "bundle.pem")

	require.NoError(t, os.WriteFile(clientCertPath, []byte(clientCertPEM), 0644))
	require.NoError(t, os.WriteFile(caCertPath, []byte(caCertPEM), 0644))
	require.NoError(t, os.WriteFile(clientKeyPath, []byte(clientKeyPEM), 0600))
	require.NoError(t, os.WriteFile(bundlePath, []byte(clientCertPEM+caCertPEM), 0644))

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}
```

**Note:** These are placeholder test certificates. In real tests, you should generate proper test certificates using `crypto/x509` or pre-generate them with `openssl`.

#### 3.2 Test Load from Bundle

```go
func TestLoadFromBundle(t *testing.T) {
	tmpDir, cleanup := setupTestCerts(t)
	defer cleanup()

	config := Config{
		CertBundle: filepath.Join(tmpDir, "bundle.pem"),
		ClientKey:  filepath.Join(tmpDir, "client-key.pem"),
	}

	certs, err := Load(config)
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.NotEmpty(t, certs.ClientCert)
	require.NotEmpty(t, certs.ClientKey)
	require.NotEmpty(t, certs.CACerts)
}
```

#### 3.3 Test Load from Individual Files

```go
func TestLoadFromIndividualFiles(t *testing.T) {
	tmpDir, cleanup := setupTestCerts(t)
	defer cleanup()

	config := Config{
		CACert:     filepath.Join(tmpDir, "ca-cert.pem"),
		ClientCert: filepath.Join(tmpDir, "client-cert.pem"),
		ClientKey:  filepath.Join(tmpDir, "client-key.pem"),
	}

	certs, err := Load(config)
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.NotEmpty(t, certs.ClientCert)
	require.NotEmpty(t, certs.ClientKey)
	require.NotEmpty(t, certs.CACerts)
}
```

#### 3.4 Test Error Cases

```go
func TestLoadMissingClientKey(t *testing.T) {
	config := Config{
		CertBundle: "/path/to/bundle.pem",
		// ClientKey missing
	}

	_, err := Load(config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "client key is required")
}

func TestLoadBundleFileNotFound(t *testing.T) {
	tmpDir, cleanup := setupTestCerts(t)
	defer cleanup()

	config := Config{
		CertBundle: "/nonexistent/bundle.pem",
		ClientKey:  filepath.Join(tmpDir, "client-key.pem"),
	}

	_, err := Load(config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read cert bundle")
}

func TestLoadIndividualFilesMissingCACert(t *testing.T) {
	tmpDir, cleanup := setupTestCerts(t)
	defer cleanup()

	config := Config{
		ClientCert: filepath.Join(tmpDir, "client-cert.pem"),
		ClientKey:  filepath.Join(tmpDir, "client-key.pem"),
		// CACert missing
	}

	_, err := Load(config)
	require.Error(t, err)
	require.Contains(t, err.Error(), "client cert and CA cert are required")
}
```

#### 3.5 Test parseBundle

```go
func TestParseBundleValid(t *testing.T) {
	bundleData := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6nqMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBUxEzARBgNVBAMM
CnRlc3RjbGllbnQ=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBeDCCAR6gAwIBAgIJAKHHCgVZU6npMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMMBnRlc3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzAN
BgNVBAMMBnRlc3RjYQ==
-----END CERTIFICATE-----`)

	clientCert, caCerts, err := parseBundle(bundleData)
	require.NoError(t, err)
	require.NotEmpty(t, clientCert)
	require.NotEmpty(t, caCerts)
	require.Contains(t, string(clientCert), "BEGIN CERTIFICATE")
	require.Contains(t, string(caCerts), "BEGIN CERTIFICATE")
}

func TestParseBundleInsufficientCerts(t *testing.T) {
	bundleData := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU6nqMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYQ==
-----END CERTIFICATE-----`)

	_, _, err := parseBundle(bundleData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must contain at least 2 certificates")
}
```

#### 3.6 Test TLSConfig

```go
func TestTLSConfig(t *testing.T) {
	tmpDir, cleanup := setupTestCerts(t)
	defer cleanup()

	config := Config{
		CertBundle: filepath.Join(tmpDir, "bundle.pem"),
		ClientKey:  filepath.Join(tmpDir, "client-key.pem"),
	}

	certs, err := Load(config)
	require.NoError(t, err)

	tlsConfig, err := certs.TLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	require.Len(t, tlsConfig.Certificates, 1)
	require.NotNil(t, tlsConfig.RootCAs)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
}
```

#### 3.7 Test Validate

```go
func TestValidate(t *testing.T) {
	tmpDir, cleanup := setupTestCerts(t)
	defer cleanup()

	config := Config{
		CertBundle: filepath.Join(tmpDir, "bundle.pem"),
		ClientKey:  filepath.Join(tmpDir, "client-key.pem"),
	}

	certs, err := Load(config)
	require.NoError(t, err)

	err = certs.Validate()
	require.NoError(t, err)
}
```

### Step 4: Run Tests

```bash
# Run tests with coverage
go test ./internal/tlscerts/... -v -cover

# Check coverage report
go test ./internal/tlscerts/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Expected output:**
```
=== RUN   TestLoadFromBundle
--- PASS: TestLoadFromBundle (0.00s)
=== RUN   TestLoadFromIndividualFiles
--- PASS: TestLoadFromIndividualFiles (0.00s)
=== RUN   TestLoadMissingClientKey
--- PASS: TestLoadMissingClientKey (0.00s)
...
PASS
coverage: 85.7% of statements
```

## Verification

### Checklist

- [ ] Package compiles without errors
- [ ] All tests pass
- [ ] Test coverage > 80%
- [ ] Can load from bundle
- [ ] Can load from individual files
- [ ] Error cases are handled
- [ ] TLSConfig() creates valid config
- [ ] Validate() works correctly

### Manual Testing

Test the package manually:

```go
package main

import (
	"fmt"
	"github.com/wolfeidau/airunner/internal/tlscerts"
)

func main() {
	// Test bundle loading
	config := tlscerts.Config{
		CertBundle: "./certs/admin-bundle.pem",
		ClientKey:  "./certs/admin-key.pem",
	}

	certs, err := tlscerts.Load(config)
	if err != nil {
		panic(err)
	}

	tlsConfig, err := certs.TLSConfig()
	if err != nil {
		panic(err)
	}

	fmt.Printf("✓ Loaded certificates successfully\n")
	fmt.Printf("  Client cert size: %d bytes\n", len(certs.ClientCert))
	fmt.Printf("  CA certs size: %d bytes\n", len(certs.CACerts))
	fmt.Printf("  TLS config min version: TLS 1.%d\n", tlsConfig.MinVersion-0x0300)
}
```

## Troubleshooting

### Issue: Tests fail with "invalid test certificates"

**Solution:** The placeholder certificates in `setupTestCerts()` are not real. Generate proper test certificates:

```bash
# Generate test CA
openssl ecparam -genkey -name prime256v1 -out testdata/ca-key.pem
openssl req -new -x509 -key testdata/ca-key.pem -out testdata/ca-cert.pem -days 365 -subj "/CN=testca"

# Generate test client cert
openssl ecparam -genkey -name prime256v1 -out testdata/client-key.pem
openssl req -new -key testdata/client-key.pem -out testdata/client.csr -subj "/CN=testclient"
openssl x509 -req -in testdata/client.csr -CA testdata/ca-cert.pem -CAkey testdata/ca-key.pem -CAcreateserial -out testdata/client-cert.pem -days 365

# Create bundle
cat testdata/client-cert.pem testdata/ca-cert.pem > testdata/bundle.pem
```

### Issue: Coverage is low

**Solution:** Add more test cases:
- Test with multiple CA certificates in bundle
- Test with intermediate CA certificates
- Test various invalid PEM formats
- Test concurrent loads

## Next Steps

✅ Phase 1 complete! The `internal/tlscerts` package is now ready.

Proceed to [Phase 2: CLI Integration](02-phase2-integration.md) to add `--cert-bundle` support to CLI commands.

---

[← README](README.md) | [← Architecture](00-architecture.md) | [Phase 2 →](02-phase2-integration.md)
