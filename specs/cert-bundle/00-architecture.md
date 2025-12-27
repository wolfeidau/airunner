# Architecture: Certificate Bundle Support

[← README](README.md) | [Phase 1 →](01-phase1-package.md)

## Summary and Goals

**What:** Add certificate bundle support to the Airunner CLI for mTLS authentication.

**Why:** Reduce complexity of certificate management by combining public certificates (client cert + CA cert) into a single bundle file, while keeping the private key separate. This follows cfssl security best practices and makes it easier to store certificates in password managers like 1Password.

**Goals:**
1. Reduce certificate files from 3 to 2 (bundle + key)
2. Follow security best practices (public certs bundled, private key separate)
3. Create reusable `internal/tlscerts` package
4. Maintain backward compatibility with existing three-flag approach
5. Comprehensive test coverage

## Design Decisions and Trade-offs

### Decision 1: Dedicated Package vs Inline Implementation

**Chosen:** Create dedicated `internal/tlscerts` package

**Alternatives considered:**
1. Implement directly in `internal/client/client.go`
2. Extend existing `internal/ssmcerts` package
3. Create new dedicated `internal/tlscerts` package ✅

**Rationale:**
- **Reusability:** Package can be extracted and used in other tools/CLIs
- **Testability:** Comprehensive unit tests in isolated package
- **Separation of concerns:** Client package focuses on HTTP/gRPC, not PEM parsing
- **Consistency:** Mirrors `internal/ssmcerts` pattern already established

**Trade-offs:**
- ➕ Clean separation, easy to test, reusable
- ➖ Slightly more code (new package), but manageable (~150 lines)

### Decision 2: Bundle Format - PEM Concatenation

**Chosen:** Simple PEM concatenation (client cert first, then CA cert(s))

**Alternatives considered:**
1. PKCS#12 binary format (.p12/.pfx)
2. Simple PEM concatenation ✅
3. Custom JSON/YAML wrapper format

**Rationale:**
- **Standard:** PEM bundles are widely used (HAProxy, NGINX, Kubernetes)
- **cfssl alignment:** Matches cfssl's certificate-only bundle approach
- **Simplicity:** No additional dependencies, uses Go's standard `encoding/pem`
- **Inspectable:** Text format, easy to view/debug with `openssl storeutl`
- **Private key separate:** Security best practice, only bundle public certs

**Trade-offs:**
- ➕ Simple, standard, no external dependencies
- ➕ Text format is easy to inspect and debug
- ➖ No password protection (but bundles only contain public data)
- ➖ Less formal standard than PKCS#12 (but widely accepted)

### Decision 3: Certificate Order in Bundle

**Chosen:** Client cert first, CA cert(s) second

**Rationale:**
- **Standard practice:** Most tools expect leaf cert first, then chain
- **cfssl pattern:** `cfssl bundle` outputs in this order
- **Clear semantics:** First cert is the identity, rest are the trust chain

### Decision 4: Backward Compatibility Approach

**Chosen:** Support both bundle and individual files simultaneously

**Rationale:**
- **No breaking changes:** Existing scripts/deployments continue to work
- **Gradual migration:** Teams can adopt bundles at their own pace
- **Flexibility:** Use bundles in production, individual files for debugging

**Implementation:**
```go
type Config struct {
    // Bundle approach (new)
    CertBundle string
    ClientKey  string

    // Individual files (backward compatibility)
    CACert     string
    ClientCert string
}
```

## Architecture Diagrams

### Current Architecture (3 Files)

```
┌─────────────────┐
│  User provides  │
│   3 files:      │
│                 │
│  ca-cert.pem    │
│  client-cert    │
│  client-key     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│   CLI Commands              │
│   (submit, worker, etc.)    │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  internal/client/client.go  │
│  buildTLSConfig()           │
│  - os.ReadFile() x3         │
│  - tls.LoadX509KeyPair()    │
│  - AppendCertsFromPEM()     │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│      tls.Config             │
└─────────────────────────────┘
```

### New Architecture (2 Files with Bundle)

```
┌─────────────────┐
│  User provides  │
│   2 files:      │
│                 │
│  admin-bundle   │  ← client cert + CA cert
│  client-key     │  ← private key (1Password)
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│   CLI Commands              │
│   --cert-bundle flag        │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  internal/client/client.go  │
│  Delegates to tlscerts pkg  │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  internal/tlscerts          │
│  Load() - auto-detect       │
│  parseBundle() - parse PEM  │
│  TLSConfig() - create cfg   │
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│      tls.Config             │
└─────────────────────────────┘
```

## Data Models

### tlscerts.Config

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

**Logic:**
- If `CertBundle != ""`: Load from bundle
- Else if `CACert != "" && ClientCert != ""`: Load from individual files
- Else: Error

### tlscerts.Certificates

```go
// Certificates holds certificate data in memory
type Certificates struct {
    ClientCert []byte // Client certificate PEM
    ClientKey  []byte // Client private key PEM
    CACerts    []byte // CA certificate(s) PEM
}
```

**Methods:**
- `TLSConfig() (*tls.Config, error)` - Creates TLS config from certificates
- `Validate() error` - Validates that PEM data is valid

### Bundle Format (PEM File)

```
-----BEGIN CERTIFICATE-----
MIIBkT... (client certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBjD... (CA certificate)
-----END CERTIFICATE-----
[optional: intermediate CA certificates]
```

**Parsing logic:**
1. Parse all PEM blocks from file
2. First block is client certificate
3. Remaining blocks are CA certificates (chain)
4. Validate: At least 2 certificates required

## Key Concepts and Terminology

### Certificate Bundle
A single PEM file containing multiple certificates (client cert + CA cert chain). Contains only public certificates, no private keys.

### cfssl Bundle Approach
CloudFlare's PKI toolkit creates certificate-only bundles (public certs) and stores private keys separately. This is considered a security best practice.

### PEM Format
Privacy-Enhanced Mail format - a Base64-encoded DER certificate wrapped in `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` markers.

### Certificate Chain
The sequence of certificates from the leaf (client) certificate to the root CA certificate. Required for TLS verification.

## API Design

### Package: internal/tlscerts

#### Load Function

```go
func Load(config Config) (*Certificates, error)
```

**Purpose:** Load certificates from either a bundle or individual files

**Behavior:**
- Auto-detects bundle vs individual files based on config
- Reads all files into memory
- Returns `Certificates` struct with PEM data
- Validates file existence and readability

**Error cases:**
- `ClientKey` missing: "client key is required"
- Bundle parsing fails: "cert bundle must contain at least 2 certificates"
- File read fails: "failed to read <file>: <error>"

#### parseBundle Function (internal)

```go
func parseBundle(bundleData []byte) ([]byte, []byte, error)
```

**Purpose:** Parse PEM bundle into client cert and CA certs

**Behavior:**
- Iterates through PEM blocks
- First certificate becomes client cert
- Remaining certificates become CA certs
- Re-encodes as PEM for consistency

**Error cases:**
- Less than 2 certs: "cert bundle must contain at least 2 certificates"
- Invalid PEM: Returns pem.Decode error

#### TLSConfig Method

```go
func (c *Certificates) TLSConfig() (*tls.Config, error)
```

**Purpose:** Create TLS config from in-memory certificates

**Behavior:**
- Creates X509KeyPair from client cert + key
- Parses CA certs into cert pool
- Returns tls.Config with:
  - `Certificates`: Client cert
  - `RootCAs`: CA cert pool
  - `MinVersion`: TLS 1.2

**Error cases:**
- Invalid client cert/key: "failed to parse client certificate: <error>"
- Invalid CA certs: "failed to parse CA certificates"

#### Validate Method

```go
func (c *Certificates) Validate() error
```

**Purpose:** Validate that certificate data is valid PEM

**Behavior:**
- Validates CA certs can be parsed
- Validates client cert/key pair match
- Does NOT verify certificate validity/expiration

**Error cases:**
- Invalid CA cert PEM: "invalid CA certificate PEM"
- Invalid client cert/key: "invalid client certificate/key: <error>"

## Integration with Existing Code

### internal/client/client.go

**Before:**
```go
func buildTLSConfig(config Config) (*tls.Config, error) {
    // 40+ lines of file reading, PEM parsing, etc.
}
```

**After:**
```go
func buildTLSConfig(config Config) (*tls.Config, error) {
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

    return certs.TLSConfig()
}
```

**Benefits:**
- Reduced from ~80 lines to ~15 lines
- Clearer separation of concerns
- Easier to test client.go (can mock tlscerts)

### CLI Commands

**Before:**
```go
type SubmitCmd struct {
    CACert     string
    ClientCert string
    ClientKey  string
}
```

**After:**
```go
type SubmitCmd struct {
    CertBundle string  // NEW
    CACert     string  // Backward compat
    ClientCert string  // Backward compat
    ClientKey  string
}
```

**Environment variables:**
- `AIRUNNER_CERT_BUNDLE` - Certificate bundle path
- `AIRUNNER_CA_CERT` - CA cert path (backward compat)
- `AIRUNNER_CLIENT_CERT` - Client cert path (backward compat)
- `AIRUNNER_CLIENT_KEY` - Client key path

## Security Considerations

### Bundle Contains Only Public Data
Certificate bundles contain only public certificates (client cert + CA cert). These are not sensitive and can be stored on disk or in version control.

### Private Key Remains Separate
The private key (`admin-key.pem`) is the only sensitive file and must be protected:
- Store in 1Password or other secure password manager
- Restrict file permissions (0600) if stored on disk
- Never commit to version control
- Rotate regularly

### Certificate Validation
The `Validate()` method only validates PEM format and cert/key pairing. It does NOT:
- Check certificate expiration
- Verify certificate chain
- Validate certificate against CA

These validations happen during TLS handshake.

### No Password Protection on Bundles
Unlike PKCS#12, PEM bundles are not password-protected. This is acceptable because bundles contain only public data.

## Testing Strategy

### Unit Tests (internal/tlscerts/loader_test.go)

**Test cases:**
1. `TestLoadFromBundle` - Load valid bundle + key
2. `TestLoadFromIndividualFiles` - Load from separate files
3. `TestLoadBundleInvalidFormat` - Bundle with <2 certs
4. `TestLoadBundleMissingKey` - Bundle without private key
5. `TestLoadMissingFiles` - File not found errors
6. `TestTLSConfig` - Verify TLS config creation
7. `TestValidate` - Validate good and bad PEM data
8. `TestParseBundleOrder` - Verify cert order (client first, CA second)

**Test fixtures:**
- `testdata/valid-bundle.pem` - Client cert + CA cert
- `testdata/client-cert.pem` - Individual client cert
- `testdata/ca-cert.pem` - Individual CA cert
- `testdata/client-key.pem` - Client private key
- `testdata/invalid-bundle.pem` - Bundle with only 1 cert

### Integration Tests

**Test bootstrap:**
```bash
./bin/airunner-cli bootstrap --environment local
test -f ./certs/admin-bundle.pem
```

**Test CLI with bundle:**
```bash
./bin/airunner-cli list \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem
```

**Test backward compatibility:**
```bash
./bin/airunner-cli list \
  --ca-cert=./certs/ca-cert.pem \
  --client-cert=./certs/admin-cert.pem \
  --client-key=./certs/admin-key.pem
```

## Performance Considerations

### File I/O
- Bundle approach: 2 file reads (bundle + key)
- Individual approach: 3 file reads (CA + cert + key)
- Difference: Negligible (small files, infrequent reads)

### Memory Usage
Both approaches load certificates into memory. Bundle approach uses same memory as individual files (just different parsing logic).

### Startup Time
No measurable difference - certificate loading is fast (<1ms for typical certs).

## References

### Internal Documentation
- [specs/mtls/](../mtls/) - mTLS implementation spec
- [internal/ssmcerts/](../../internal/ssmcerts/) - Similar package pattern
- [AGENT.md](../../AGENT.md) - Development guidelines

### External Resources
- [cfssl Documentation](https://github.com/cloudflare/cfssl) - PKI toolkit patterns
- [Go crypto/tls Package](https://pkg.go.dev/crypto/tls) - TLS implementation
- [PEM Format (RFC 7468)](https://tools.ietf.org/html/rfc7468) - PEM specification

---

[← README](README.md) | [Phase 1 →](01-phase1-package.md)
