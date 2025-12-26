# Phase 2: Local Integration Testing

[← Back to README](README.md) | [← Phase 1: Core Code](01-phase1-core-code.md) | [Phase 3: Infrastructure →](03-phase3-infrastructure.md)

## Overview

**Goal:** Validate mTLS flow with local DynamoDB (LocalStack) and implement the bootstrap command for certificate management.

**Duration:** 2-3 hours

**Prerequisites:**
- Phase 1 complete and all tests passing
- Docker and Docker Compose installed

**Success Criteria:**
- [ ] Bootstrap command creates CA and certificates
- [ ] Server starts with mTLS enabled
- [ ] Health check endpoint responds
- [ ] mTLS authentication works locally
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

### Bootstrap Flow

The bootstrap command performs 6 steps:

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
}

func (cmd *BootstrapCmd) ensureCA() error
func (cmd *BootstrapCmd) ensureServerCert() error
func (cmd *BootstrapCmd) ensureAdminPrincipal(ctx context.Context) error
func (cmd *BootstrapCmd) ensureAdminCert(ctx context.Context) error
func (cmd *BootstrapCmd) uploadToAWS(ctx context.Context) error
func (cmd *BootstrapCmd) verify(ctx context.Context) error
func (cmd *BootstrapCmd) printSummary()
```

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
