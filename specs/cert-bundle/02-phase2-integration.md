# Phase 2: CLI Integration

[← README](README.md) | [← Phase 1](01-phase1-package.md) | [Architecture](00-architecture.md) | [Phase 3 →](03-phase3-bootstrap.md)

## Goal

Integrate the `internal/tlscerts` package into the CLI commands to support the `--cert-bundle` flag while maintaining backward compatibility with the existing three-flag approach.

**Duration:** ~30 minutes

## Prerequisites

- ✅ Phase 1 completed (`internal/tlscerts` package created and tested)
- ✅ All Phase 1 tests passing

## Success Criteria

- [ ] `internal/client/client.go` updated to use tlscerts package
- [ ] `buildTLSConfig()` simplified from ~80 lines to ~30 lines
- [ ] All CLI commands have `CertBundle` field
- [ ] Environment variable `AIRUNNER_CERT_BUNDLE` supported
- [ ] Backward compatibility maintained (old three-flag approach still works)
- [ ] CLI builds successfully
- [ ] Help text shows new `--cert-bundle` flag

## Step 1: Update internal/client/client.go

### 1.1 Add tlscerts Import

**File:** `internal/client/client.go`

Add the import at the top of the file:

```go
import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/wolfeidau/airunner/internal/tlscerts"  // NEW
)
```

### 1.2 Add CertBundle Field to Config

**File:** `internal/client/client.go` (around line 12)

Update the `Config` struct to include the new `CertBundle` field:

```go
type Config struct {
	ServerURL  string
	Timeout    time.Duration
	Debug      bool

	// Certificate bundle (new approach)
	CertBundle string  // NEW

	// Individual certificates (backward compatibility)
	CACert     string
	ClientCert string
	ClientKey  string
}
```

### 1.3 Simplify buildTLSConfig Function

**File:** `internal/client/client.go` (lines 65-96)

Replace the existing `buildTLSConfig()` function with this simplified version:

**Before (lines 65-96, ~32 lines):**
```go
func buildTLSConfig(config Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate if provided
	if config.CACert != "" {
		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if provided
	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
```

**After (~15 lines):**
```go
func buildTLSConfig(config Config) (*tls.Config, error) {
	// If no certificates specified, return basic TLS config
	if config.CertBundle == "" && config.CACert == "" {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
		}, nil
	}

	// Use tlscerts package to load certificates
	certConfig := tlscerts.Config{
		CertBundle: config.CertBundle,
		CACert:     config.CACert,
		ClientCert: config.ClientCert,
		ClientKey:  config.ClientKey,
	}

	certs, err := tlscerts.Load(certConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	// Create TLS config from certificates
	tlsConfig, err := certs.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	return tlsConfig, nil
}
```

**Benefits of the new implementation:**
- ✅ Reduced from ~32 lines to ~15 lines
- ✅ No manual PEM parsing
- ✅ Clearer separation of concerns
- ✅ Easier to test (can mock tlscerts)
- ✅ Supports both bundle and individual file approaches

## Step 2: Update CLI Commands

All commands that connect to the server need the `CertBundle` field added.

### 2.1 Update cmd/cli/internal/commands/submit.go

**File:** `cmd/cli/internal/commands/submit.go`

**Current struct (around line 50):**
```go
type SubmitCmd struct {
	Server     string `help:"Server URL" default:"https://localhost:443"`
	Queue      string `help:"Queue name" default:"default"`
	CACert     string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey  string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Updated struct:**
```go
type SubmitCmd struct {
	Server     string `help:"Server URL" default:"https://localhost:443"`
	Queue      string `help:"Queue name" default:"default"`

	// Certificate bundle (new approach)
	CertBundle string `help:"Path to certificate bundle (client cert + CA cert)" env:"AIRUNNER_CERT_BUNDLE"`

	// Individual certificates (backward compatibility)
	CACert     string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey  string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Update the Run() method (around line 90):**

Find where `client.Config` is created and add the `CertBundle` field:

```go
config := client.Config{
	ServerURL:  s.Server,
	CertBundle: s.CertBundle,  // NEW
	CACert:     s.CACert,
	ClientCert: s.ClientCert,
	ClientKey:  s.ClientKey,
	Timeout:    30 * time.Second,
	Debug:      globals.Debug,
}
```

### 2.2 Update cmd/cli/internal/commands/worker.go

**File:** `cmd/cli/internal/commands/worker.go`

**Current struct (around line 26):**
```go
type WorkerCmd struct {
	Server     string        `help:"Server URL" default:"https://localhost:443"`
	Queue      string        `help:"Queue name" default:"default"`
	CACert     string        `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert string        `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey  string        `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Updated struct:**
```go
type WorkerCmd struct {
	Server     string        `help:"Server URL" default:"https://localhost:443"`
	Queue      string        `help:"Queue name" default:"default"`

	// Certificate bundle (new approach)
	CertBundle string `help:"Path to certificate bundle (client cert + CA cert)" env:"AIRUNNER_CERT_BUNDLE"`

	// Individual certificates (backward compatibility)
	CACert     string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey  string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Update client.Config creation:**
```go
config := client.Config{
	ServerURL:  w.Server,
	CertBundle: w.CertBundle,  // NEW
	CACert:     w.CACert,
	ClientCert: w.ClientCert,
	ClientKey:  w.ClientKey,
	Timeout:    30 * time.Second,
	Debug:      globals.Debug,
}
```

### 2.3 Update cmd/cli/internal/commands/monitor.go

**File:** `cmd/cli/internal/commands/monitor.go`

**Current struct (around line 27):**
```go
type MonitorCmd struct {
	Server       string `help:"Server URL" default:"https://localhost:443"`
	CACert       string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert   string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey    string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Updated struct:**
```go
type MonitorCmd struct {
	Server       string `help:"Server URL" default:"https://localhost:443"`

	// Certificate bundle (new approach)
	CertBundle string `help:"Path to certificate bundle (client cert + CA cert)" env:"AIRUNNER_CERT_BUNDLE"`

	// Individual certificates (backward compatibility)
	CACert       string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert   string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey    string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Update client.Config creation:**
```go
config := client.Config{
	ServerURL:  m.Server,
	CertBundle: m.CertBundle,  // NEW
	CACert:     m.CACert,
	ClientCert: m.ClientCert,
	ClientKey:  m.ClientKey,
	Timeout:    30 * time.Second,
	Debug:      globals.Debug,
}
```

### 2.4 Update cmd/cli/internal/commands/list.go

**File:** `cmd/cli/internal/commands/list.go`

**Current struct (around line 22):**
```go
type ListCmd struct {
	Server     string `help:"Server URL" default:"https://localhost:443"`
	CACert     string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey  string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Updated struct:**
```go
type ListCmd struct {
	Server     string `help:"Server URL" default:"https://localhost:443"`

	// Certificate bundle (new approach)
	CertBundle string `help:"Path to certificate bundle (client cert + CA cert)" env:"AIRUNNER_CERT_BUNDLE"`

	// Individual certificates (backward compatibility)
	CACert     string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT"`
	ClientCert string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
	ClientKey  string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`
	// ... other fields
}
```

**Update client.Config creation:**
```go
config := client.Config{
	ServerURL:  l.Server,
	CertBundle: l.CertBundle,  // NEW
	CACert:     l.CACert,
	ClientCert: l.ClientCert,
	ClientKey:  l.ClientKey,
	Timeout:    30 * time.Second,
	Debug:      globals.Debug,
}
```

## Step 3: Build and Verify

### 3.1 Build the CLI

```bash
make build-cli
```

**Expected output:**
```
go build -o ./bin/airunner-cli ./cmd/cli
```

**Verify binary exists:**
```bash
ls -lh ./bin/airunner-cli
```

### 3.2 Verify Help Text

Check that the new `--cert-bundle` flag appears in help:

```bash
./bin/airunner-cli submit --help
```

**Expected output should include:**
```
Flags:
  --cert-bundle=STRING         Path to certificate bundle (client cert + CA cert) ($AIRUNNER_CERT_BUNDLE)
  --ca-cert=STRING             Path to CA certificate ($AIRUNNER_CA_CERT)
  --client-cert=STRING         Path to client certificate ($AIRUNNER_CLIENT_CERT)
  --client-key=STRING          Path to client private key ($AIRUNNER_CLIENT_KEY)
```

**Verify for all commands:**
```bash
./bin/airunner-cli submit --help | grep cert-bundle
./bin/airunner-cli worker --help | grep cert-bundle
./bin/airunner-cli monitor --help | grep cert-bundle
./bin/airunner-cli list --help | grep cert-bundle
```

Each should show the `--cert-bundle` flag.

## Step 4: Integration Testing

### 4.1 Test with Existing Certificates (Three-Flag Approach)

Verify backward compatibility by testing with the existing three-flag approach:

```bash
./bin/airunner-cli list \
  --server="https://localhost:443" \
  --ca-cert=./certs/ca-cert.pem \
  --client-cert=./certs/admin-cert.pem \
  --client-key=./certs/admin-key.pem
```

**Expected:** Should work exactly as before (backward compatibility maintained).

### 4.2 Test with Environment Variables (Three-Flag Approach)

```bash
export AIRUNNER_SERVER="https://localhost:443"
export AIRUNNER_CA_CERT="./certs/ca-cert.pem"
export AIRUNNER_CLIENT_CERT="./certs/admin-cert.pem"
export AIRUNNER_CLIENT_KEY="./certs/admin-key.pem"

./bin/airunner-cli list
```

**Expected:** Should work with environment variables.

### 4.3 Create a Test Bundle

Manually create a test bundle to verify the new functionality will work:

```bash
# Combine admin cert + CA cert
cat ./certs/admin-cert.pem ./certs/ca-cert.pem > ./certs/admin-bundle.pem

# Verify the bundle has 2 certificates
openssl storeutl -noout -text -certs ./certs/admin-bundle.pem | grep "Certificate:"
```

**Expected output:**
```
Certificate:
Certificate:
```

Should see two "Certificate:" lines.

### 4.4 Test with Bundle (New Approach)

```bash
./bin/airunner-cli list \
  --server="https://localhost:443" \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem
```

**Expected:** Should successfully connect and list jobs.

### 4.5 Test with Bundle via Environment Variables

```bash
unset AIRUNNER_CA_CERT
unset AIRUNNER_CLIENT_CERT

export AIRUNNER_CERT_BUNDLE="./certs/admin-bundle.pem"
export AIRUNNER_CLIENT_KEY="./certs/admin-key.pem"

./bin/airunner-cli list
```

**Expected:** Should work with bundle environment variables.

## Step 5: Error Handling Tests

### 5.1 Test Missing Client Key

```bash
./bin/airunner-cli list \
  --server="https://localhost:443" \
  --cert-bundle=./certs/admin-bundle.pem
```

**Expected error:**
```
Error: failed to load certificates: client key is required
```

### 5.2 Test Bundle with Only One Certificate

Create a test bundle with only one certificate:

```bash
cp ./certs/admin-cert.pem ./certs/invalid-bundle.pem

./bin/airunner-cli list \
  --server="https://localhost:443" \
  --cert-bundle=./certs/invalid-bundle.pem \
  --client-key=./certs/admin-key.pem
```

**Expected error:**
```
Error: failed to load certificates: failed to parse cert bundle: cert bundle must contain at least 2 certificates (client cert + CA cert)
```

### 5.3 Test Non-Existent Bundle File

```bash
./bin/airunner-cli list \
  --server="https://localhost:443" \
  --cert-bundle=./certs/nonexistent.pem \
  --client-key=./certs/admin-key.pem
```

**Expected error:**
```
Error: failed to load certificates: failed to read cert bundle: open ./certs/nonexistent.pem: no such file or directory
```

## Verification Checklist

- [ ] CLI builds successfully (`make build-cli`)
- [ ] `--cert-bundle` flag appears in `--help` for all commands
- [ ] Backward compatibility: Three-flag approach still works
- [ ] Environment variables work for both approaches
- [ ] Bundle approach works with manually created bundle
- [ ] Error handling works (missing key, invalid bundle, missing files)
- [ ] `internal/client/client.go` is simplified (~50% reduction in buildTLSConfig)

## Troubleshooting

### Build Fails with Import Error

**Error:**
```
package github.com/wolfeidau/airunner/internal/tlscerts: no such file or directory
```

**Solution:**
Ensure Phase 1 is completed and `internal/tlscerts/loader.go` exists.

### Help Text Doesn't Show --cert-bundle

**Error:** `--cert-bundle` flag not visible in help output.

**Solution:**
- Verify the `CertBundle` field was added to the command struct
- Verify the `help:` tag is present
- Rebuild the CLI: `make build-cli`

### Backward Compatibility Broken

**Error:** Three-flag approach no longer works.

**Solution:**
- Verify `buildTLSConfig()` still checks for `config.CACert` and `config.ClientCert`
- Verify the `tlscerts.Load()` function supports individual files
- Review `internal/tlscerts/loader.go` implementation

## Next Steps

After completing Phase 2:

1. ✅ Verify all integration tests pass
2. ✅ Clean up test files (`./certs/admin-bundle.pem`, `./certs/invalid-bundle.pem`)
3. → Proceed to [Phase 3: Bootstrap Support](03-phase3-bootstrap.md) to automatically generate bundles

## Files Modified Summary

### Created:
- None (uses existing package from Phase 1)

### Modified:
1. `internal/client/client.go` - Add `CertBundle` field, simplify `buildTLSConfig()`
2. `cmd/cli/internal/commands/submit.go` - Add `CertBundle` field and env var
3. `cmd/cli/internal/commands/worker.go` - Add `CertBundle` field and env var
4. `cmd/cli/internal/commands/monitor.go` - Add `CertBundle` field and env var
5. `cmd/cli/internal/commands/list.go` - Add `CertBundle` field and env var

**Total lines changed:** ~50 lines across 5 files

---

[← README](README.md) | [← Phase 1](01-phase1-package.md) | [Architecture](00-architecture.md) | [Phase 3 →](03-phase3-bootstrap.md)
