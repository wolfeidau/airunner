# Phase 2: Local Integration Testing

[← Back to README](README.md) | [← Phase 1: Core Code](01-phase1-core-code.md) | [Phase 3: Infrastructure →](03-phase3-infrastructure.md)

## Overview

**Goal:** Validate mTLS flow with local DynamoDB (LocalStack) and implement the bootstrap command for certificate management.

**Duration:** 2-3 hours

**Prerequisites:**
- Phase 1 complete and all tests passing
- Docker and Docker Compose installed

**Success Criteria:**

**Local Mode:**
- [ ] Bootstrap command creates CA key in `./certs/ca-key.pem`
- [ ] FileSigner signs certificates locally
- [ ] Server starts with mTLS enabled using local certs
- [ ] Health check endpoint responds
- [ ] mTLS authentication works with local certificates

**AWS Mode (if testing with LocalStack KMS):**
- [ ] KMS key created (or stub in LocalStack)
- [ ] KMSSigner signs certificates via KMS API
- [ ] Bootstrap completes without creating local CA key
- [ ] Principal and certificate stores work with DynamoDB

## DynamoDB Store Implementations

**Location:** `internal/store/`

**What you'll create:**
- `dynamodb_principal_store.go` - Production PrincipalStore implementation
- `dynamodb_cert_store.go` - Production CertificateStore implementation

### Key Implementation Patterns

**GSI Usage:**
- GSI1 on `principals`: Query by status (list all active principals)
- GSI2 on `principals`: Query by type (list all workers)
- GSI1 on `certificates`: Query by principal_id (list all certs for a principal)
- GSI2 on `certificates`: Query by fingerprint

**Conditional Writes:**
```go
// Use ConditionExpression to prevent duplicates
input := &dynamodb.PutItemInput{
    TableName: aws.String(tableName),
    Item:      item,
    ConditionExpression: aws.String("attribute_not_exists(principal_id)"),
}
```

**TTL Handling:**
```go
// Set TTL for automatic cleanup (30 days after expiry)
certMeta.TTL = certMeta.ExpiresAt.Add(30 * 24 * time.Hour).Unix()
```

**Reference:** See original spec lines 1393-1485 for complete patterns.

## Server Configuration

**Location:** `cmd/server/internal/commands/rpc.go` (updates)

**Reference:** `examples/server/rpc.go` (structure and pattern)

### Dual Listener Pattern

The server runs two listeners:
- **Port 443:** mTLS API (all RPC endpoints)
- **Port 8080:** Health check (HTTP, no TLS)

### TLS Configuration

```go
// Load server certificate
serverCert, err := tls.LoadX509KeyPair(cmd.ServerCert, cmd.ServerKey)

// Load CA for client verification
caCert, err := os.ReadFile(cmd.CACert)
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

// Configure TLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caCertPool,
    MinVersion:   tls.VersionTLS12,
}
```

### Health Check Handler

```go
func (s *RPCCmd) healthHandler(store store.PrincipalStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Check DynamoDB connectivity
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()

        _, err := store.List(ctx, store.ListPrincipalsOptions{Limit: 1})
        if err != nil {
            http.Error(w, "unhealthy", http.StatusServiceUnavailable)
            return
        }

        w.WriteHeader(http.StatusOK)
        fmt.Fprintln(w, "ok")
    }
}
```

## CLI Bootstrap Command

**Location:** `cmd/cli/internal/commands/bootstrap.go`

**Reference:** `examples/cli/bootstrap.go` (structure and flow)

**Complete Implementation:** See original spec lines 2279-2783 (505 lines)

### Bootstrap Modes: Local vs AWS

The bootstrap command supports two modes based on the `--environment` flag:

#### Local Mode (`--environment=local`)

**Purpose:** Development and testing without AWS dependencies

**CA Key Handling:**
- Generates CA private key to local file (`./certs/ca-key.pem`)
- Uses `FileSigner` for signing operations
- No AWS resources accessed
- Simple, fast development workflow

**Command:**
```bash
./bin/airunner-cli bootstrap --environment=local --output-dir=./certs
```

**Output:**
- `./certs/ca-key.pem` - CA private key (local file only)
- `./certs/ca-cert.pem` - CA certificate
- `./certs/server-cert.pem`, `server-key.pem` - Server cert/key
- `./certs/admin-cert.pem`, `admin-key.pem` - Admin cert/key

#### AWS Mode (`--environment=dev|staging|prod`)

**Purpose:** Production deployment with KMS-backed security

**CA Key Handling:**
- Uses KMS key created by Terraform (Phase 3)
- CA private key created in KMS, never exported
- Uses `KMSSigner` for signing operations via KMS API
- Never creates or stores CA private key locally
- Production-grade security (FIPS 140-2 Level 2)

**Prerequisites:**
- Terraform applied (Phase 3) - KMS key must exist
- KMS key alias: `alias/airunner-{env}-ca`
- SSM parameter exists: `/airunner/{env}/ca-kms-key-id`

**Command:**
```bash
./bin/airunner-cli bootstrap --environment=prod --domain=airunner.example.com
```

**Output:**
- KMS signing operations (CA cert, server cert, admin cert)
- Certificates uploaded to SSM Parameter Store
- Principal and certificate records in DynamoDB
- **No local CA private key created**

### Bootstrap Flow

**Local Mode:** The bootstrap command performs 6 steps:

1. **Check/Create CA**
   - Check if `ca-cert.pem` exists locally
   - Generate new CA key pair to `./certs/ca-key.pem` if needed (ECDSA P-256, 10-year validity)
   - Create FileSigner with local CA key

2. **Check/Create Server Certificate**
   - Generate server key pair
   - Sign with FileSigner (local CA key)
   - Add SAN: domain, localhost, 127.0.0.1
   - Save to `./certs/`

3. **Check/Create Admin Certificate**
   - Generate admin key pair
   - Add OID extensions (type=admin, id=admin-bootstrap)
   - Sign with FileSigner
   - Save to `./certs/`

**AWS Mode:** The bootstrap command performs 7 steps:

1. **Load KMS Key**
   - Read KMS key ID from SSM: `/airunner/{env}/ca-kms-key-id`
   - Verify KMS key accessible
   - Create KMSSigner with KMS key

2. **Create CA Certificate**
   - Build self-signed CA certificate template
   - Sign via KMS API (never creates CA private key locally)
   - 10-year validity

3. **Create Server Certificate**
   - Generate server key pair
   - Sign via KMS API
   - Add SAN: domain, localhost, 127.0.0.1
   - 90-day validity

4. **Create Admin Principal**
   - Check if principal exists in DynamoDB
   - Create with status=active, type=admin

5. **Create Admin Certificate**
   - Generate admin key pair
   - Add OID extensions (type=admin, id=admin-bootstrap)
   - Sign via KMS API
   - Register in DynamoDB certificates table

6. **Upload to AWS**
   - Put `ca-cert.pem` to SSM Parameter Store
   - Put `server-cert.pem` to SSM
   - Put `server-key.pem` to SSM SecureString
   - **Note:** CA private key never uploaded (exists only in KMS)

7. **Verify and Report**
   - Verify all resources accessible
   - Print summary with next steps

**Implementation Pattern:**

```go
func (cmd *BootstrapCommand) Run(ctx context.Context) error {
    switch cmd.config.Environment {
    case "local":
        return cmd.runLocalBootstrap(ctx)
    case "dev", "staging", "prod":
        return cmd.runAWSBootstrap(ctx)
    default:
        return fmt.Errorf("unknown environment: %s", cmd.config.Environment)
    }
}

func (cmd *BootstrapCommand) runLocalBootstrap(ctx context.Context) error {
    // 1. Generate CA key pair to ./certs/ca-key.pem
    // 2. Create FileSigner
    // 3. Sign server certificate
    // 4. Sign admin certificate
    // 5. Save all to local files
}

func (cmd *BootstrapCommand) runAWSBootstrap(ctx context.Context) error {
    // 1. Read KMS key ID from SSM: /airunner/{env}/ca-kms-key-id
    // 2. Create KMSSigner with KMS key
    // 3. Sign CA certificate (self-signed via KMS)
    // 4. Sign server certificate via KMS
    // 5. Sign admin certificate via KMS
    // 6. Upload certificates to SSM (public certs only, no private keys!)
    // 7. Store principal and certificate records in DynamoDB
}
```

### Original Bootstrap Flow (for reference)

The original bootstrap command performs these steps (now split between local/AWS modes):

1. **Check/Create CA**
   - Check if `ca-cert.pem` exists locally
   - Check if `ca-key` exists in Secrets Manager
   - Generate new CA if needed (ECDSA P-256, 10-year validity)

2. **Check/Create Server Certificate**
   - Check if `server-cert.pem` exists locally
   - Generate server key pair
   - Sign with CA
   - Add SAN: domain, localhost, 127.0.0.1

3. **Check/Create Admin Principal**
   - Check if principal exists in DynamoDB
   - Create with status=active, type=admin

4. **Check/Create Admin Certificate**
   - Generate admin key pair
   - Add OID extensions (type=admin, id=admin-bootstrap)
   - Register in DynamoDB

5. **Upload to AWS**
   - Put `ca-cert.pem` to SSM
   - Put `server-cert.pem` to SSM
   - Put `server-key.pem` to SSM SecureString
   - Put `ca-key.pem` to Secrets Manager

6. **Verify and Report**
   - Verify all resources accessible
   - Print summary with next steps

### Key Functions

```go
type BootstrapCmd struct {
    Environment string
    Domain      string
    AWSRegion   string
    OutputDir   string
    Force       bool // Force regeneration of all certificates
}

func (cmd *BootstrapCmd) ensureCA() error
func (cmd *BootstrapCmd) ensureServerCert() error
func (cmd *BootstrapCmd) ensureAdminPrincipal(ctx context.Context) error
func (cmd *BootstrapCmd) ensureAdminCert(ctx context.Context) error
func (cmd *BootstrapCmd) uploadToAWS(ctx context.Context) error
func (cmd *BootstrapCmd) verify(ctx context.Context) error
func (cmd *BootstrapCmd) printSummary()
```

### Certificate Lifecycle Management

**Problem:** Certificates expire and need rotation. The bootstrap command must handle:
- Detecting expired certificates
- Warning about certificates approaching expiry
- Automatic or forced regeneration
- Different rotation thresholds per certificate type

**Solution:** Implement certificate validation and rotation logic.

#### Rotation Thresholds

Different certificate types have different rotation windows:

| Certificate Type | Validity Period | Rotation Threshold | Auto-Regenerate |
|-----------------|-----------------|-------------------|-----------------|
| CA Certificate | 10 years | 365 days | No (warn only) |
| Server Certificate | 90 days | 7 days | Yes |
| Admin Certificate | 90 days | 7 days | Yes |

**Rationale:**
- **CA**: Long-lived, rarely rotated, warning gives time to plan rotation
- **Server/Admin**: Short-lived (90 days), auto-rotate within 7 days of expiry
- **Force flag**: Override any checks and regenerate everything

#### Certificate Validation Logic

```go
type CertValidation struct {
    Path          string
    Exists        bool
    Expired       bool
    NotBefore     time.Time
    NotAfter      time.Time
    DaysRemaining int
    ShouldRotate  bool
}

// validateCertificate checks if a certificate exists and its validity status
func validateCertificate(path string, rotationThreshold time.Duration) (*CertValidation, error) {
    validation := &CertValidation{Path: path}

    // Check if file exists
    if _, err := os.Stat(path); err != nil {
        validation.Exists = false
        validation.ShouldRotate = true
        return validation, nil
    }

    validation.Exists = true

    // Load and parse certificate
    cert, err := loadCertificate(path)
    if err != nil {
        return nil, fmt.Errorf("failed to load certificate: %w", err)
    }

    now := time.Now()
    validation.NotBefore = cert.NotBefore
    validation.NotAfter = cert.NotAfter
    validation.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)

    // Check if expired
    if now.After(cert.NotAfter) {
        validation.Expired = true
        validation.ShouldRotate = true
        return validation, nil
    }

    // Check if within rotation threshold
    if time.Until(cert.NotAfter) < rotationThreshold {
        validation.ShouldRotate = true
    }

    return validation, nil
}
```

#### Bootstrap Command Flags

Add `--force` flag to override all validation:

```go
type BootstrapCmd struct {
    Environment string `help:"environment name (local, dev, prod)" default:"local"`
    Domain      string `help:"server domain name" default:"localhost"`
    AWSRegion   string `help:"AWS region" default:"us-east-1"`
    OutputDir   string `help:"output directory for certificates" default:"./certs"`
    AWSEndpoint string `help:"AWS endpoint (for LocalStack)" default:""`
    Force       bool   `help:"force regeneration of all certificates" default:"false"`
}
```

#### Updated Bootstrap Flow

Each certificate check now includes validation:

**1. Check/Create CA:**
```go
// Validate existing CA certificate
caValidation, err := validateCertificate(paths.caCert, 365*24*time.Hour)
if err != nil {
    return nil, nil, err
}

if cmd.Force {
    log.Info().Msg("Force flag set, regenerating CA certificate...")
    // Generate new CA
} else if caValidation.ShouldRotate {
    if caValidation.Expired {
        log.Error().Msg("CA certificate is expired, regenerating...")
    } else {
        log.Warn().
            Int("days_remaining", caValidation.DaysRemaining).
            Msg("CA certificate approaching expiry, regenerating...")
    }
    // Generate new CA
} else if caValidation.Exists {
    log.Info().
        Int("days_remaining", caValidation.DaysRemaining).
        Msg("CA certificate is valid, using existing...")
    // Load existing CA
}
```

**2. Check/Create Server Certificate:**
```go
// Validate existing server certificate (7-day rotation window)
serverValidation, err := validateCertificate(paths.serverCert, 7*24*time.Hour)
if err != nil {
    return err
}

if cmd.Force || serverValidation.ShouldRotate {
    if serverValidation.Expired {
        log.Error().Msg("Server certificate is expired, regenerating...")
    } else if serverValidation.ShouldRotate {
        log.Warn().
            Int("days_remaining", serverValidation.DaysRemaining).
            Msg("Server certificate within rotation window, regenerating...")
    }
    // Generate new server certificate
}
```

**3. Check/Create Admin Certificate:**
```go
// Validate existing admin certificate (7-day rotation window)
adminValidation, err := validateCertificate(paths.adminCert, 7*24*time.Hour)
if err != nil {
    return err
}

if cmd.Force || adminValidation.ShouldRotate {
    // Generate new admin certificate and register in store
}
```

#### Validation Output Examples

**All certificates valid:**
```
INFO CA certificate is valid (3562 days remaining)
INFO Server certificate is valid (82 days remaining)
INFO Admin certificate is valid (85 days remaining)
```

**Server certificate approaching expiry:**
```
INFO CA certificate is valid (3562 days remaining)
WARN Server certificate within rotation window (5 days remaining), regenerating...
INFO Generated new server certificate (90 days validity)
INFO Admin certificate is valid (85 days remaining)
```

**Expired certificate:**
```
INFO CA certificate is valid (3562 days remaining)
ERROR Server certificate is expired (-3 days), regenerating...
INFO Generated new server certificate (90 days validity)
INFO Admin certificate is valid (85 days remaining)
```

**Force regeneration:**
```
INFO Force flag set, regenerating all certificates...
INFO Regenerated CA certificate (10 years validity)
INFO Regenerated server certificate (90 days validity)
INFO Regenerated admin certificate (90 days validity)
```

#### Testing Certificate Rotation

```bash
# Test with certificates approaching expiry
# 1. Generate initial certificates
./bin/airunner-cli bootstrap --environment=local --domain=localhost

# 2. Modify certificate to simulate near-expiry (for testing)
# In production, certificates naturally approach expiry

# 3. Run bootstrap again - should detect and rotate
./bin/airunner-cli bootstrap --environment=local --domain=localhost
# Expected: "Server certificate within rotation window (X days remaining), regenerating..."

# 4. Force regeneration regardless of validity
./bin/airunner-cli bootstrap --environment=local --domain=localhost --force
# Expected: "Force flag set, regenerating all certificates..."
```

#### Implementation Checklist

- [ ] Add `validateCertificate` function with rotation threshold
- [ ] Add `--force` flag to BootstrapCmd
- [ ] Update `ensureCA` with validation logic
- [ ] Update `ensureServerCert` with validation logic
- [ ] Update `ensureAdminCert` with validation logic
- [ ] Add validation logging (INFO/WARN/ERROR based on status)
- [ ] Update summary output to show certificate validity status
- [ ] Add integration tests for rotation scenarios

## Docker Compose Setup

**Location:** `docker-compose.yml` (additions)

Add LocalStack for DynamoDB:

```yaml
services:
  localstack:
    image: localstack/localstack:latest
    ports:
      - "4566:4566"
    environment:
      - SERVICES=dynamodb
      - DEFAULT_REGION=us-east-1
```

## Integration Test Scenarios

### Scenario 1: Bootstrap and Certificate Creation

```bash
# Start LocalStack
docker-compose up -d

# Create DynamoDB tables
aws dynamodb create-table --table-name test_principals \
    --attribute-definitions AttributeName=principal_id,AttributeType=S \
    --key-schema AttributeName=principal_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --endpoint-url http://localhost:4566

aws dynamodb create-table --table-name test_certificates \
    --attribute-definitions AttributeName=serial_number,AttributeType=S \
    --key-schema AttributeName=serial_number,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --endpoint-url http://localhost:4566

# Run bootstrap
./bin/airunner-cli bootstrap \
    --environment=local \
    --domain=localhost \
    --aws-region=us-east-1 \
    --output-dir=./test-certs

# Verify files created
ls test-certs/
# Expected: ca-cert.pem, ca-key.pem, server-cert.pem, server-key.pem, admin-cert.pem, admin-key.pem
```

### Scenario 2: Server Startup with mTLS

```bash
# Start server with mTLS
./bin/airunner-server \
    --mtls-listen=0.0.0.0:443 \
    --health-listen=0.0.0.0:8080 \
    --ca-cert=./test-certs/ca-cert.pem \
    --server-cert=./test-certs/server-cert.pem \
    --server-key=./test-certs/server-key.pem \
    --store-type=memory

# Test health check
curl http://localhost:8080/health
# Expected: ok
```

### Scenario 3: mTLS Client Connection

```bash
# Test with admin cert
curl --cacert test-certs/ca-cert.pem \
     --cert test-certs/admin-cert.pem \
     --key test-certs/admin-key.pem \
     https://localhost:443/job.v1.PrincipalService/ListPrincipals

# Expected: Success (200 OK) with principal list
```

### Scenario 4: Certificate Verification

```bash
# Verify admin certificate has OID extensions
openssl x509 -in test-certs/admin-cert.pem -text -noout | grep -A2 "1.3.6.1.4.1.99999"

# Expected output showing OID extensions:
# 1.3.6.1.4.1.99999.1.1:
#     admin
# 1.3.6.1.4.1.99999.1.2:
#     admin-bootstrap
```

## Implementation Checklist

- [ ] Create `internal/store/dynamodb_principal_store.go`
- [ ] Create `internal/store/dynamodb_cert_store.go`
- [ ] Update `cmd/server/internal/commands/rpc.go` with mTLS config
- [ ] Create `cmd/cli/internal/commands/bootstrap.go`
- [ ] Add LocalStack to `docker-compose.yml`
- [ ] Write integration tests
- [ ] Test bootstrap command locally
- [ ] Test server startup with mTLS
- [ ] Test mTLS client connections
- [ ] Verify certificate OID extensions

## Verification

```bash
# Full integration test
docker-compose up -d
./bin/airunner-cli bootstrap --environment=local --domain=localhost
./bin/airunner-server # Starts with mTLS
curl http://localhost:8080/health  # Should return "ok"
```

## Next Steps

Once Phase 2 is complete and integration tests pass, proceed to **[Phase 3: Infrastructure](03-phase3-infrastructure.md)**.

---

[← Back to README](README.md) | [← Phase 1: Core Code](01-phase1-core-code.md) | [Phase 3: Infrastructure →](03-phase3-infrastructure.md)
