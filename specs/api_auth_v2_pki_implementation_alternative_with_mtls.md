# Implementation Plan: Per-Principal PKI Authentication with Mutual TLS

## Summary

Replace the current single shared JWT public key authentication model with a per-principal PKI model using **mutual TLS (mTLS)** where each user/worker maintains their own ECDSA P-256 key pair and X.509 certificate. This enables distributed credential management, automatic certificate rotation, per-principal revocation capabilities, and provides message integrity and replay protection via TLS.

## Goals

1. **Eliminate shared credentials**: Each principal (user, worker, service) has unique credentials
2. **Enable certificate rotation**: Workers automatically rotate certificates every 60-90 days
3. **Support revocation**: Individual principals can be revoked without affecting others
4. **Maintain security**: ECDSA ES256 certificates with per-principal verification
5. **Message integrity**: TLS provides cryptographic integrity for all requests
6. **Replay protection**: TLS sequence numbers and nonces prevent replay attacks
7. **Zero application code**: Authentication handled at TLS layer, not application layer

## Why mTLS Over JWT or HTTP Message Signatures?

### Security Benefits

| Feature | JWT Bearer | HTTP Signatures (RFC 9421) | mTLS |
|---------|-----------|---------------------------|------|
| **Message Integrity** | ❌ Only authenticates token | ✅ Signs request body | ✅ TLS record MACs |
| **Replay Protection** | ❌ Token valid for 1 hour | ✅ 60-second window | ✅ TLS sequence numbers |
| **Application Code** | Middleware needed | Middleware needed | ❌ None (TLS layer) |
| **Performance Overhead** | Sign once/hour | Sign every request | None (TLS handshake only) |
| **Industry Adoption** | Ubiquitous | Bleeding edge (2024) | Battle-tested |
| **Works after TLS termination** | ❌ No | ✅ Yes | N/A (is TLS) |
| **Certificate Management** | Simple key files | Simple key files | Standard PKI tools |

### Architectural Benefits

**TLS provides everything you need:**
```
┌──────────────────────────────────────────────────────────────┐
│                     TLS 1.3 Handshake                         │
│                                                               │
│  Client                                  Server               │
│    │                                        │                 │
│    ├─── ClientHello ───────────────────────>│                 │
│    │    (includes client cert)              │                 │
│    │                                        │                 │
│    │<──── ServerHello ──────────────────────┤                 │
│    │    (requests client cert verification) │                 │
│    │                                        │                 │
│    ├─── Certificate ─────────────────────>  │                 │
│    │    (client cert + chain)               │                 │
│    │                                        │                 │
│    ├─── CertificateVerify ─────────────────>│                 │
│    │    (signs handshake with private key)  │                 │
│    │                                        │                 │
│    │                        Server validates:                 │
│    │                        ✅ Cert signed by trusted CA      │
│    │                        ✅ Cert not expired               │
│    │                        ✅ Cert not revoked (CRL/OCSP)    │
│    │                        ✅ CN matches principal_id        │
│    │                                        │                 │
│    │<──── Finished ──────────────────────── │                 │
│    │                                        │                 │
│    │  🔒 Encrypted + authenticated channel │                 │
│    │                                        │                 │
│    ├─── Application Data (RPC request) ───>│                 │
│    │    ✅ Message integrity (TLS MAC)      │                 │
│    │    ✅ Replay protection (TLS seq #)    │                 │
│    │    ✅ Confidentiality (encryption)     │                 │
│    │                                        │                 │
└──────────────────────────────────────────────────────────────┘
```

**Result:** No application-layer signing needed. TLS handles everything.

## Current State vs Desired State

### Current Authentication Model

**Architecture:**
- Single ECDSA P256 key pair managed in AWS SSM Parameter Store
- Private key used externally to generate tokens (`airunner-cli token`)
- Server loads public key from `JWT_PUBLIC_KEY` environment variable
- All tokens verified against same public key via `auth.NewJWTAuthFunc(publicKeyPEM)`

**Limitations:**
- Shared public key means all tokens look identical to server
- No per-user revocation (must rotate shared key, invalidating all tokens)
- No message integrity (request body can be modified after TLS termination)
- No replay protection (stolen token valid until expiry)

### Desired Authentication Model (mTLS)

**Architecture:**
1. Each principal generates ECDSA P-256 key pair locally (`~/.airunner/keys/<principal_id>`)
2. Principal creates Certificate Signing Request (CSR) from public key
3. Admin/CA signs CSR → produces X.509 certificate (90-day validity)
4. Certificate metadata registered in DynamoDB (for revocation tracking)
5. Client presents certificate during TLS handshake
6. Server validates certificate against CA bundle + checks revocation list
7. TLS provides message integrity, replay protection, and encryption

**Benefits:**
- Message integrity: TLS record MACs prevent request tampering
- Replay protection: TLS sequence numbers prevent replay attacks
- Zero application code: Authentication at TLS layer, not application layer
- Per-principal revocation without affecting others
- Industry-standard PKI infrastructure
- Automatic rotation via certificate renewal

## Architecture Design

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Client/Worker                            │
│  ┌──────────────────┐  ┌──────────────────────────────┐    │
│  │ ~/.airunner/     │  │ Certificate Manager           │    │
│  │ - private.pem    │  │ - Monitors cert expiry        │    │
│  │ - cert.pem       │─>│ - Requests renewal (60d left) │    │
│  │ - ca-bundle.pem  │  │ - Updates TLS config          │    │
│  └──────────────────┘  └────────────┬─────────────────┘    │
│                                      │                       │
└───────────────────────────────┬──────┘
                                │ mTLS Handshake
                                ↓
┌─────────────────────────────────────────────────────────────┐
│                       Server                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ TLS Layer (crypto/tls)                                │  │
│  │ 1. Verify cert signed by trusted CA                  │  │
│  │ 2. Verify cert not expired (NotAfter)                │  │
│  │ 3. Extract CN (principal_id)                         │  │
│  │ 4. Check principal status (active/suspended)         │  │
│  │ 5. Check cert revocation (query DynamoDB)            │  │
│  │ 6. Store principal_id in context                     │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     ↓                                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ PrincipalStore (interface)                            │  │
│  │ - Get(principal_id) → principal metadata             │  │
│  │ - Create(principal)                                  │  │
│  │ - Suspend(principal_id)                              │  │
│  │ - Activate(principal_id)                             │  │
│  │ - List() → []PrincipalMetadata                       │  │
│  └──────────────────┬───────────────┬───────────────────┘  │
│                     ↓               ↓                        │
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │ MemoryPrincipalStore│  │ DynamoDBPrincipalStore       │  │
│  │ - Dev/testing       │  │ - Production                 │  │
│  └─────────────────────┘  └─────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ CertificateStore (interface)                          │  │
│  │ - Get(serial_number) → cert metadata                 │  │
│  │ - Register(cert_metadata)                            │  │
│  │ - Revoke(serial_number)                              │  │
│  │ - List() → []CertMetadata                            │  │
│  └──────────────────┬───────────────┬───────────────────┘  │
│                     ↓               ↓                        │
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │ MemoryCertStore     │  │ DynamoDBCertStore            │  │
│  │ - Dev/testing       │  │ - Production                 │  │
│  └─────────────────────┘  └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                                ↓
                   ┌────────────────────────┐
                   │ DynamoDB: principals   │
                   │ PK: principal_id       │
                   │ - type (worker/user)   │
                   │ - status (active)      │
                   │ - created_at           │
                   └────────────────────────┘
                                ↓
                   ┌────────────────────────┐
                   │ DynamoDB: certificates │
                   │ PK: serial_number      │
                   │ - principal_id         │
                   │ - fingerprint          │
                   │ - issued_at            │
                   │ - expires_at           │
                   │ - revoked (bool)       │
                   └────────────────────────┘
```

### Data Model

#### DynamoDB Table: `principals`

**Primary Key:**
- `principal_id` (String, Hash Key) - Unique principal identifier (e.g., "worker-prod-01", "user@example.com")

**Attributes:**
```
principal_id         - Principal identifier (PK)
type                 - Principal type: worker, user, service, admin
status               - Principal status: active, suspended, deleted
created_at           - Unix milliseconds (timestamp of principal creation)
created_by           - Principal ID of creator (for audit trail)
email                - Optional contact email
description          - Human-readable description
max_certificates     - Optional limit on active certificates (default: 3)
metadata             - JSON blob for extensibility (team, cost center, etc.)
```

**Global Secondary Indexes:**

| Index | Partition Key | Sort Key | Projection | Purpose |
|-------|---------------|----------|------------|---------|
| **GSI1** | `status` | `created_at` | ALL | List principals by status and creation time |
| **GSI2** | `type` | `created_at` | ALL | List principals by type (all workers, all users) |

**Why track principals separately?**
- **Instant revocation**: Suspend principal to immediately block all their certificates
- **Audit trail**: Track who created each principal and when
- **Metadata management**: Store contact info, team ownership, purpose
- **Quota enforcement**: Limit number of active certificates per principal
- **Authorization**: Principal types can map to different permissions
- **Operational queries**: "List all active workers", "Find principals by team"

#### DynamoDB Table: `certificates`

**Primary Key:**
- `serial_number` (String, Hash Key) - X.509 certificate serial number (hex-encoded)

**Attributes:**
```
serial_number        - Certificate serial number (hex, e.g., "a1b2c3d4e5f6")
principal_id         - Principal identifier (e.g., "worker-prod-01", "user@example.com")
fingerprint          - SHA-256 fingerprint of certificate (for quick lookup)
subject_dn           - Certificate subject DN (e.g., "CN=worker-prod-01,O=Airunner")
issued_at            - Unix milliseconds (timestamp of certificate issuance)
expires_at           - Unix milliseconds (cert expiry, typically 90 days from issuance)
revoked              - Boolean (true if certificate is revoked)
revoked_at           - Unix milliseconds (timestamp of revocation, null if not revoked)
revocation_reason    - Optional reason code (key_compromise, superseded, etc.)
description          - Optional human-readable description
```

**Global Secondary Indexes:**

| Index | Partition Key | Sort Key | Projection | Purpose |
|-------|---------------|----------|------------|---------|
| **GSI1** | `principal_id` | `issued_at` | ALL | List all certs for a principal |
| **GSI2** | `fingerprint` | - | ALL | Quick lookup by cert fingerprint |

**Why track certificates in DynamoDB?**
- Fast revocation checking during TLS handshake
- Audit trail of all issued certificates
- Support multiple certs per principal (rotation overlap)
- Can query "which principals have expiring certs"

#### In-Memory Store Schemas

**Principal Store:**
```go
type MemoryPrincipalStore struct {
    mu         sync.RWMutex
    principals map[string]*PrincipalMetadata  // principal_id → metadata
}

type PrincipalMetadata struct {
    PrincipalID      string            // Unique identifier
    Type             string            // worker, user, service, admin
    Status           string            // active, suspended, deleted
    CreatedAt        time.Time
    CreatedBy        string            // Principal ID of creator
    Email            string            // Optional contact
    Description      string            // Human-readable description
    MaxCertificates  int               // Limit on active certs (0 = unlimited)
    Metadata         map[string]string // Extensible key-value pairs
}
```

**Certificate Store:**
```go
type MemoryCertStore struct {
    mu            sync.RWMutex
    certs         map[string]*CertMetadata           // serial_number → metadata
    principalCerts map[string]map[string]*CertMetadata // principal_id → (serial → metadata)
    fingerprints  map[string]*CertMetadata           // fingerprint → metadata
}

type CertMetadata struct {
    SerialNumber     string    // Hex-encoded serial number
    PrincipalID      string    // Principal who owns this cert
    Fingerprint      string    // SHA-256 fingerprint (base64)
    SubjectDN        string    // Full subject DN
    IssuedAt         time.Time
    ExpiresAt        time.Time
    Revoked          bool
    RevokedAt        *time.Time
    RevocationReason string
    Description      string
}
```

### X.509 Certificate Structure

**Certificate Details:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 01:93:6d:3f:a2:b1:7c:4e:8f:5d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Airunner Root CA, O=Airunner, C=US
        Validity:
            Not Before: Dec 24 00:00:00 2024 GMT
            Not After : Mar 24 23:59:59 2025 GMT (90 days)
        Subject: CN=worker-prod-01, O=Airunner
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 Extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                DNS:worker-prod-01
            X509v3 Authority Key Identifier:
                keyid:AB:CD:EF:...
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:...
```

**Key Fields:**
- **Serial Number**: Unique identifier for revocation
- **Subject CN**: Principal ID (e.g., "worker-prod-01")
- **Validity**: 90-day lifetime (configurable)
- **Extended Key Usage**: Client Authentication
- **Public Key**: ECDSA P-256 (same keys as JWT approach)

### Certificate Authority (CA)

**Two approaches for CA:**

#### Option 1: Self-Signed CA (Recommended for Start)

```go
// Generate CA key pair (one-time setup)
caPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Create CA certificate
caCert := &x509.Certificate{
    SerialNumber: big.NewInt(1),
    Subject: pkix.Name{
        CommonName:   "Airunner Root CA",
        Organization: []string{"Airunner"},
        Country:      []string{"US"},
    },
    NotBefore:             time.Now(),
    NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
    KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
    BasicConstraintsValid: true,
    IsCA:                  true,
    MaxPathLen:            0,
}

// Self-sign CA cert
caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivateKey.PublicKey, caPrivateKey)
```

**CA Storage:**
- Store CA private key in AWS Secrets Manager (highly restricted access)
- Distribute CA certificate bundle to all servers and clients
- CA private key only used by admin tools for signing CSRs

#### Option 2: AWS Private CA (Production-Ready)

```go
// Use AWS Certificate Manager Private CA
import "github.com/aws/aws-sdk-go-v2/service/acmpca"

// Issue certificate from AWS Private CA
input := &acmpca.IssueCertificateInput{
    CertificateAuthorityArn: aws.String("arn:aws:acm-pca:..."),
    Csr:                     csrBytes,
    SigningAlgorithm:        types.SigningAlgorithmSha256withecdsa,
    Validity: &types.Validity{
        Type:  types.ValidityPeriodTypeDays,
        Value: aws.Int64(90),
    },
}

output, err := pcaClient.IssueCertificate(ctx, input)
certArn := output.CertificateArn
```

**Benefits:**
- Managed CA infrastructure
- Automatic CRL generation
- OCSP responder
- Audit logging via CloudTrail
- HSM-backed CA keys

**Cost:** ~$400/month per CA + $0.75 per cert issued

## Infrastructure Configuration

### Architecture: Single-Listener NLB with Let's Encrypt

The infrastructure uses a simple single-listener Network Load Balancer with Let's Encrypt for the server certificate. Since Let's Encrypt is publicly trusted, clients don't need a discovery endpoint to download CA certificates.

```
┌────────────────────────────────────────────────────────────────┐
│ Internet                                                        │
└──────────────────────────────┬─────────────────────────────────┘
                               │ Port 443 (mTLS)
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ Network Load Balancer (NLB)                                    │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Listener: 443 (TCP Passthrough)                          │ │
│  │ - No TLS termination (server handles TLS)                │ │
│  │ - Forwards to ECS port 443                               │ │
│  └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────┬─────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│ ECS Tasks (Private Subnets)                                    │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ airunner-server (single process)                         │ │
│  │                                                           │ │
│  │  Port 443: mTLS API                                      │ │
│  │  ├─ Server cert: Let's Encrypt (publicly trusted)        │ │
│  │  ├─ Client CA: Custom CA (validates client certs)        │ │
│  │  ├─ Client auth: REQUIRED                                │ │
│  │  └─ Endpoints:                                            │ │
│  │     ├─ All gRPC/Connect RPC APIs                         │ │
│  │     └─ GET /health (health check)                        │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ DynamoDB               │
                │ - certificates table   │
                │   (revocation tracking)│
                └────────────────────────┘
```

**Key Design Points:**

1. **Single mTLS Endpoint (Port 443)**
   - NLB listener with pure TCP passthrough (no TLS termination)
   - Server handles full TLS handshake
   - Server certificate from Let's Encrypt (auto-renewal via certbot)
   - Client certificates validated against custom CA
   - All APIs require valid client certificate
   - No public endpoints (maximum security)

2. **Two-Way Certificate Validation**
   - **Server → Client**: Server presents Let's Encrypt cert (clients trust automatically)
   - **Client → Server**: Client presents custom CA cert (server validates against CA pool)

3. **Simplified Bootstrap**
   - No CA certificate distribution needed (Let's Encrypt already trusted)
   - Admin generates and distributes client certificates directly
   - Workers connect immediately with client cert

### AWS Resources

#### Resources to ADD

**1. DynamoDB Principals Table**

```hcl
resource "aws_dynamodb_table" "principals" {
  name         = "${local.name_prefix}_principals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "type"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  # GSI1: List principals by status and creation time
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "status"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI2: List principals by type (all workers, all users)
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "type"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}_principals"
  })
}
```

**2. DynamoDB Certificate Metadata Table**

```hcl
resource "aws_dynamodb_table" "certificates" {
  name         = "${local.name_prefix}_certificates"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "serial_number"

  attribute {
    name = "serial_number"
    type = "S"
  }

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "issued_at"
    type = "N"
  }

  attribute {
    name = "fingerprint"
    type = "S"
  }

  # GSI1: List all certificates for a principal
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "principal_id"
    range_key       = "issued_at"
    projection_type = "ALL"
  }

  # GSI2: Quick lookup by certificate fingerprint
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "fingerprint"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}_certificates"
  })
}
```

**3. SSM Parameters for Certificates**

```hcl
# Server certificate (Let's Encrypt)
resource "aws_ssm_parameter" "server_cert" {
  name        = "/${var.application}/${var.environment}/server-cert"
  description = "Server TLS certificate (Let's Encrypt, auto-renewed)"
  type        = "String"
  value       = "placeholder"

  lifecycle {
    ignore_changes = [value]  # Updated by certbot deploy hook
  }

  tags = {
    Name = "${var.application}-${var.environment}-server-cert"
  }
}

# Server private key
resource "aws_ssm_parameter" "server_key" {
  name        = "/${var.application}/${var.environment}/server-key"
  description = "Server TLS private key"
  type        = "SecureString"
  value       = "placeholder"

  lifecycle {
    ignore_changes = [value]  # Updated by certbot deploy hook
  }

  tags = {
    Name = "${var.application}-${var.environment}-server-key"
  }
}

# Client CA certificate (for validating client certificates)
resource "aws_ssm_parameter" "client_ca_cert" {
  name        = "/${var.application}/${var.environment}/client-ca-cert"
  description = "CA certificate for mTLS client validation"
  type        = "String"
  value       = "placeholder"

  lifecycle {
    ignore_changes = [value]  # Managed manually after CA init
  }

  tags = {
    Name = "${var.application}-${var.environment}-client-ca-cert"
  }
}
```

**4. Secrets Manager for CA Private Key**

```hcl
resource "aws_secretsmanager_secret" "ca_private_key" {
  name        = "/${var.application}/${var.environment}/ca-private-key"
  description = "Certificate Authority private key (admin access only)"

  tags = {
    Name = "${var.application}-${var.environment}-ca-key"
  }
}

# Note: Secret value uploaded manually after CA initialization
# This prevents accidental CA key generation via Terraform
```

**5. Network Load Balancer with Single Listener**

```hcl
# NLB replaces ALB
resource "aws_lb" "main" {
  name               = "${local.name_prefix}-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = aws_subnet.public[*].id
  ip_address_type    = "dualstack"

  enable_deletion_protection = false

  tags = {
    Name = "${local.name_prefix}-nlb"
  }
}

# Single target group for mTLS API
resource "aws_lb_target_group" "mtls" {
  name_prefix = "mtls-"
  port        = 443
  protocol    = "TCP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    protocol            = "HTTPS"
    path                = "/health"
    port                = "443"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-mtls-tg"
  }
}

# Single mTLS listener (TCP passthrough)
resource "aws_lb_listener" "mtls" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mtls.arn
  }
}
```

**6. Updated Security Groups**

```hcl
resource "aws_security_group" "airunner" {
  name        = "${local.name_prefix}-ecs-sg"
  description = "ECS task security group"
  vpc_id      = aws_vpc.main.id

  # mTLS API (port 443)
  ingress {
    description     = "mTLS API from NLB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.nlb.id]
  }

  egress {
    description = "Allow all outbound (IPv4)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description      = "Allow all outbound (IPv6)"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${local.name_prefix}-ecs-sg"
  }
}

# NLB security group (for target group health checks)
resource "aws_security_group" "nlb" {
  name        = "${local.name_prefix}-nlb-sg"
  description = "NLB security group"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-nlb-sg"
  }
}
```

**7. Updated IAM Policies**

```hcl
# Execution role policy (updated)
resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.execution.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogs"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ]
        Resource = "${aws_cloudwatch_log_group.airunner.arn}:*"
      },
      {
        Sid      = "ECRAuthentication"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "AllowSSMParameterRead"
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "ssm:GetParameter"
        ]
        Resource = [
          aws_ssm_parameter.server_cert.arn,
          aws_ssm_parameter.server_key.arn,
          aws_ssm_parameter.client_ca_cert.arn
        ]
      }
    ]
  })
}

# Task role policy (updated)
resource "aws_iam_role_policy" "task_sqs_dynamodb" {
  name = "ecs-task-sqs-dynamodb-${local.name_prefix}"
  role = aws_iam_role.task.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSQSOperations"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:SendMessage",
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:GetQueueAttributes"
        ]
        Resource = [
          aws_sqs_queue.default.arn,
          aws_sqs_queue.default_dlq.arn,
          aws_sqs_queue.priority.arn,
          aws_sqs_queue.priority_dlq.arn
        ]
      },
      {
        Sid    = "AllowDynamoDBOperations"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchWriteItem"
        ]
        Resource = [
          aws_dynamodb_table.jobs.arn,
          "${aws_dynamodb_table.jobs.arn}/index/*",
          aws_dynamodb_table.job_events.arn,
          aws_dynamodb_table.principals.arn,
          "${aws_dynamodb_table.principals.arn}/index/*",
          aws_dynamodb_table.certificates.arn,
          "${aws_dynamodb_table.certificates.arn}/index/*"
        ]
      }
    ]
  })
}
```

**8. Updated ECS Task Definition**

```hcl
resource "aws_ecs_task_definition" "airunner" {
  family                   = local.name_prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["EC2"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([
    {
      name  = local.name_prefix
      image = var.container_image
      command = [
        "rpc-server",
        "--listen", "0.0.0.0:443",
        "--hostname", "airunner-${var.environment}.${var.domain_name}"
      ]
      essential = true
      portMappings = [
        {
          containerPort = 443
          hostPort      = 443
          protocol      = "tcp"
          name          = "mtls-api"
        }
      ]
      environment = [
        {
          name  = "AIRUNNER_STORE_TYPE"
          value = "sqs"
        },
        {
          name  = "AIRUNNER_SQS_QUEUE_DEFAULT"
          value = aws_sqs_queue.default.url
        },
        {
          name  = "AIRUNNER_SQS_QUEUE_PRIORITY"
          value = aws_sqs_queue.priority.url
        },
        {
          name  = "AIRUNNER_DYNAMODB_JOBS_TABLE"
          value = aws_dynamodb_table.jobs.name
        },
        {
          name  = "AIRUNNER_DYNAMODB_EVENTS_TABLE"
          value = aws_dynamodb_table.job_events.name
        },
        {
          name  = "AIRUNNER_PRINCIPAL_TABLE"
          value = aws_dynamodb_table.principals.name
        },
        {
          name  = "AIRUNNER_CERT_TABLE"
          value = aws_dynamodb_table.certificates.name
        },
        {
          name  = "AIRUNNER_DEFAULT_VISIBILITY_TIMEOUT"
          value = "300"
        },
        {
          name  = "AIRUNNER_EVENTS_TTL_DAYS"
          value = "30"
        },
        {
          name  = "AWS_REGION"
          value = data.aws_region.current.id
        },
        {
          name  = "AWS_USE_DUALSTACK_ENDPOINT"
          value = "true"
        }
      ]
      secrets = [
        {
          name      = "AIRUNNER_SERVER_CERT"
          valueFrom = aws_ssm_parameter.server_cert.arn
        },
        {
          name      = "AIRUNNER_SERVER_KEY"
          valueFrom = aws_ssm_parameter.server_key.arn
        },
        {
          name      = "AIRUNNER_CLIENT_CA_CERT"
          valueFrom = aws_ssm_parameter.client_ca_cert.arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.airunner.name
          "awslogs-region"        = data.aws_region.current.id
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    Name = "${local.name_prefix}-task-definition"
  }

  depends_on = [
    aws_iam_role_policy.execution,
    aws_sqs_queue.default,
    aws_sqs_queue.priority,
    aws_dynamodb_table.jobs,
    aws_dynamodb_table.job_events,
    aws_dynamodb_table.principals,
    aws_dynamodb_table.certificates
  ]
}
```

**9. Updated ECS Service**

```hcl
resource "aws_ecs_service" "airunner" {
  name            = local.name_prefix
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.airunner.arn
  desired_count   = var.desired_count
  launch_type     = "EC2"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.airunner.id]
  }

  # Register with single mTLS target group
  load_balancer {
    target_group_arn = aws_lb_target_group.mtls.arn
    container_name   = local.name_prefix
    container_port   = 443
  }

  tags = {
    Name = "${local.name_prefix}-service"
  }

  depends_on = [
    aws_lb_listener.mtls,
    aws_iam_role_policy.execution,
    aws_ecs_capacity_provider.main
  ]
}
```

#### Resources to REMOVE

```hcl
# Delete these JWT-based resources:

# 1. TLS key pair generation
resource "tls_private_key" "jwt" { ... }

# 2. JWT signing key SSM parameter
resource "aws_ssm_parameter" "jwt_signing_key" { ... }

# 3. JWT public key SSM parameter
resource "aws_ssm_parameter" "jwt_public_key" { ... }

# 4. Token signing secret (if exists separately)
resource "aws_ssm_parameter" "token_signing_secret" { ... }
```

#### Resources to REMOVE (ACM no longer needed)

```hcl
# Delete ACM certificate resources (replaced by Let's Encrypt)
resource "aws_acm_certificate" "main" { ... }
resource "aws_acm_certificate_validation" "main" { ... }
resource "aws_route53_record" "acm_validation" { ... }
```

#### Resources to KEEP (But Update)

```hcl
# Route53 records (same DNS name, points to NLB instead of ALB)
resource "aws_route53_record" "alb" { ... }       # Update to point to NLB
resource "aws_route53_record" "alb_ipv6" { ... }  # Update to point to NLB
```

### Infrastructure Comparison: JWT vs mTLS

| Component | Current (JWT) | New (mTLS + Let's Encrypt) |
|-----------|---------------|----------------------------|
| **Load Balancer** | ALB (Layer 7, HTTPS termination) | NLB (Layer 4, TCP passthrough) |
| **Listeners** | 1 (port 443) | 1 (port 443) |
| **Target Groups** | 1 | 1 |
| **TLS Certificates** | ACM certificate on ALB | Let's Encrypt on server |
| **Certificate Renewal** | Automatic (ACM) | Automatic (certbot) |
| **Authentication** | JWT bearer tokens (application layer) | X.509 client certificates (TLS layer) |
| **Secret Storage** | SSM (2 params: signing key, public key) | SSM (3 params: server cert/key, client CA) + Secrets Manager (CA key) |
| **Backend Storage** | None (stateless tokens) | DynamoDB (principals, certificates) |
| **IAM Permissions** | SSM read (2 parameters) | SSM read (3 parameters) + DynamoDB (principals + certificates tables) |
| **Health Checks** | HTTPS on port 8080 | HTTPS on port 443 |
| **Security Groups** | Single ingress rule (port 8080) | Single ingress rule (port 443) |
| **ECS Service** | Single target group | Single target group |
| **Complexity** | Medium | Low (simpler than JWT!) |

### Bootstrap Sequence

After deploying infrastructure with `terraform apply`:

```bash
# 1. Initialize Certificate Authority (for client certificates)
./bin/airunner-cli ca init --output-dir=./ca --common-name="Airunner Client CA"

# 2. Upload client CA certificate to SSM
aws ssm put-parameter \
  --name /airunner/${ENVIRONMENT}/client-ca-cert \
  --value file://ca/ca-cert.pem \
  --type String \
  --overwrite

# 3. Upload CA private key to Secrets Manager (restricted access)
aws secretsmanager put-secret-value \
  --secret-id /airunner/${ENVIRONMENT}/ca-private-key \
  --secret-binary fileb://ca/ca-key.pem

# 4. Obtain Let's Encrypt certificate for server
certbot certonly --dns-route53 \
  -d airunner-${ENVIRONMENT}.${DOMAIN}

# 5. Upload server certificate to SSM
aws ssm put-parameter \
  --name /airunner/${ENVIRONMENT}/server-cert \
  --value file:///etc/letsencrypt/live/airunner-${ENVIRONMENT}.${DOMAIN}/fullchain.pem \
  --type String \
  --overwrite

aws ssm put-parameter \
  --name /airunner/${ENVIRONMENT}/server-key \
  --value file:///etc/letsencrypt/live/airunner-${ENVIRONMENT}.${DOMAIN}/privkey.pem \
  --type SecureString \
  --overwrite

# 6. Set up certbot auto-renewal (updates SSM on renewal)
cat > /etc/letsencrypt/renewal-hooks/deploy/update-ssm.sh <<'EOF'
#!/bin/bash
aws ssm put-parameter \
  --name /airunner/${ENVIRONMENT}/server-cert \
  --value file://${RENEWED_LINEAGE}/fullchain.pem \
  --type String \
  --overwrite

aws ssm put-parameter \
  --name /airunner/${ENVIRONMENT}/server-key \
  --value file://${RENEWED_LINEAGE}/privkey.pem \
  --type SecureString \
  --overwrite

# Restart ECS service to pick up new certificate
aws ecs update-service \
  --cluster airunner-${ENVIRONMENT}-cluster \
  --service airunner-${ENVIRONMENT} \
  --force-new-deployment
EOF

chmod +x /etc/letsencrypt/renewal-hooks/deploy/update-ssm.sh

# 7. Restart ECS service to pick up initial configuration
aws ecs update-service \
  --cluster airunner-${ENVIRONMENT}-cluster \
  --service airunner-${ENVIRONMENT} \
  --force-new-deployment

# 8. Test server is running
curl https://airunner-${ENVIRONMENT}.${DOMAIN}/health
# Should fail with "certificate required" (mTLS is working!)

# 9. Create first admin principal (bootstrap)
# Note: Use temporary cert for initial setup, or create principal record directly in DynamoDB
aws dynamodb put-item \
  --table-name airunner-${ENVIRONMENT}_principals \
  --item '{
    "principal_id": {"S": "admin-bootstrap"},
    "type": {"S": "admin"},
    "status": {"S": "active"},
    "created_at": {"N": "'$(date +%s)000'"},
    "created_by": {"S": "system"},
    "description": {"S": "Bootstrap administrator"}
  }'

# 10. Generate client certificates for workers (see next section)
```

### Local Development Configuration

For local development without AWS infrastructure:

```bash
# 1. Initialize local CA (for client certificates)
./bin/airunner-cli ca init --output-dir=./ca

# 2. Generate server certificate (can use custom CA for local dev)
./bin/airunner-cli cert generate localhost-server --dns-names="localhost,127.0.0.1"
./bin/airunner-cli cert sign localhost-server \
  --ca-key=ca/ca-key.pem \
  --ca-cert=ca/ca-cert.pem

# 3. Run server locally (same binary, different config)
./bin/airunner-server \
  --listen=0.0.0.0:8443 \
  --server-cert=~/.airunner/keys/localhost-server-cert.pem \
  --server-key=~/.airunner/keys/localhost-server-private.pem \
  --client-ca-cert=./ca/ca-cert.pem \
  --store-type=memory \
  --cert-store-type=memory

# 4. Generate client certificate
./bin/airunner-cli cert generate worker-dev
./bin/airunner-cli cert sign worker-dev \
  --ca-key=ca/ca-key.pem \
  --ca-cert=ca/ca-cert.pem

# 5. Test mTLS endpoint
./bin/airunner-cli worker \
  --server=https://localhost:8443 \
  --ca-cert=ca/ca-cert.pem \  # Trust our local CA for server cert
  --client-cert=~/.airunner/keys/worker-dev-cert.pem \
  --client-key=~/.airunner/keys/worker-dev-private.pem

# Alternative: Use system curl to test
curl --cert ~/.airunner/keys/worker-dev-cert.pem \
     --key ~/.airunner/keys/worker-dev-private.pem \
     --cacert ca/ca-cert.pem \
     https://localhost:8443/health
```

**Key Benefits:**
- Same code path for local development and production
- Single server process (simpler than dual-listener setup)
- For local dev: Use custom CA for server cert (simpler)
- For production: Use Let's Encrypt for server cert (publicly trusted)
- Client certificates always from custom CA (same in both environments)

## Implementation Details

### 1. PrincipalStore Interface

**File:** `internal/store/principal_store.go` (new file)

```go
package store

import (
    "context"
    "errors"
    "time"
)

// PrincipalMetadata represents metadata about a principal
type PrincipalMetadata struct {
    PrincipalID      string            // Unique identifier
    Type             string            // worker, user, service, admin
    Status           string            // active, suspended, deleted
    CreatedAt        time.Time
    CreatedBy        string            // Principal ID of creator
    Email            string            // Optional contact
    Description      string            // Human-readable description
    MaxCertificates  int               // Limit on active certs (0 = unlimited)
    Metadata         map[string]string // Extensible key-value pairs
}

// PrincipalStore manages principal metadata
type PrincipalStore interface {
    // Get retrieves principal metadata by ID
    Get(ctx context.Context, principalID string) (*PrincipalMetadata, error)

    // Create creates a new principal
    Create(ctx context.Context, principal *PrincipalMetadata) error

    // Update updates principal metadata
    Update(ctx context.Context, principal *PrincipalMetadata) error

    // Suspend suspends a principal (blocks all authentication)
    Suspend(ctx context.Context, principalID string, reason string) error

    // Activate activates a previously suspended principal
    Activate(ctx context.Context, principalID string) error

    // Delete soft-deletes a principal
    Delete(ctx context.Context, principalID string) error

    // List returns all principals (optional filter by type/status)
    List(ctx context.Context, filters map[string]string) ([]*PrincipalMetadata, error)
}

// Common errors
var (
    ErrPrincipalNotFound      = errors.New("principal not found")
    ErrPrincipalAlreadyExists = errors.New("principal already exists")
    ErrPrincipalSuspended     = errors.New("principal has been suspended")
    ErrPrincipalDeleted       = errors.New("principal has been deleted")
)
```

### 2. CertificateStore Interface

**File:** `internal/store/certificate_store.go` (new file)

```go
package store

import (
    "context"
    "crypto/x509"
    "errors"
    "time"
)

// CertMetadata represents metadata about an issued certificate
type CertMetadata struct {
    SerialNumber     string    // Hex-encoded serial number
    PrincipalID      string    // Principal who owns this cert
    Fingerprint      string    // SHA-256 fingerprint (base64)
    SubjectDN        string    // Full subject distinguished name
    IssuedAt         time.Time
    ExpiresAt        time.Time
    Revoked          bool
    RevokedAt        *time.Time
    RevocationReason string
    Description      string
}

// CertificateStore manages certificate metadata for revocation checking
type CertificateStore interface {
    // Get retrieves certificate metadata by serial number
    Get(ctx context.Context, serialNumber string) (*CertMetadata, error)

    // GetByPrincipal retrieves all certificates for a principal
    GetByPrincipal(ctx context.Context, principalID string) ([]*CertMetadata, error)

    // GetByFingerprint retrieves certificate metadata by SHA-256 fingerprint
    GetByFingerprint(ctx context.Context, fingerprint string) (*CertMetadata, error)

    // Register stores certificate metadata
    Register(ctx context.Context, cert *CertMetadata) error

    // Revoke marks a certificate as revoked
    Revoke(ctx context.Context, serialNumber string, reason string) error

    // List returns all registered certificates
    List(ctx context.Context) ([]*CertMetadata, error)
}

// Common errors
var (
    ErrCertNotFound        = errors.New("certificate not found")
    ErrCertAlreadyExists   = errors.New("certificate already exists")
    ErrCertRevoked         = errors.New("certificate has been revoked")
    ErrCertExpired         = errors.New("certificate has expired")
)

// Helper: Extract metadata from X.509 certificate
func NewCertMetadata(cert *x509.Certificate, principalID string) *CertMetadata {
    fingerprint := sha256.Sum256(cert.Raw)

    return &CertMetadata{
        SerialNumber: cert.SerialNumber.Text(16),
        PrincipalID:  principalID,
        Fingerprint:  base64.StdEncoding.EncodeToString(fingerprint[:]),
        SubjectDN:    cert.Subject.String(),
        IssuedAt:     cert.NotBefore,
        ExpiresAt:    cert.NotAfter,
        Revoked:      false,
    }
}
```

### 3. Server TLS Configuration with Principal and Revocation Checking

**File:** `internal/auth/mtls.go` (new file)

```go
package auth

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "os"
    "sync"
    "time"

    "connectrpc.com/authn"
    "github.com/rs/zerolog/log"

    "github.com/wolfeidau/airunner/internal/store"
)

// NewMTLSConfig creates a TLS config for mutual TLS authentication
func NewMTLSConfig(caCertPath string, principalStore store.PrincipalStore, certStore store.CertificateStore) (*tls.Config, error) {
    // Load CA certificate bundle
    caCert, err := os.ReadFile(caCertPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read CA cert: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to parse CA cert")
    }

    // Create authentication checker (principal + revocation)
    authChecker := &authChecker{
        principalStore: principalStore,
        certStore:      certStore,
        cache:          newAuthCache(5 * time.Minute),
    }

    tlsConfig := &tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs:  caCertPool,
        MinVersion: tls.VersionTLS13, // TLS 1.3 required

        // Custom verification to check principal status and certificate revocation
        VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
                return errors.New("no verified certificate chains")
            }

            // Get client certificate (first in chain)
            clientCert := verifiedChains[0][0]

            // Check principal status and certificate revocation
            return authChecker.Check(context.Background(), clientCert)
        },
    }

    return tlsConfig, nil
}

// authChecker checks principal status and certificate revocation
type authChecker struct {
    principalStore store.PrincipalStore
    certStore      store.CertificateStore
    cache          *authCache
}

func (a *authChecker) Check(ctx context.Context, cert *x509.Certificate) error {
    serialNumber := cert.SerialNumber.Text(16)
    principalID := cert.Subject.CommonName

    // Check cache first
    if status, cached := a.cache.Get(serialNumber); cached {
        if status != "allowed" {
            return fmt.Errorf("authentication failed: %s", status)
        }
        return nil
    }

    // Check 1: Principal status
    principal, err := a.principalStore.Get(ctx, principalID)
    if err != nil {
        // Principal not found - this could be:
        // 1. Principal created before we started tracking
        // 2. Database error
        // 3. Invalid principal_id in certificate

        log.Warn().
            Str("principal_id", principalID).
            Str("serial_number", serialNumber).
            Err(err).
            Msg("principal not found in database")

        // For security, reject unknown principals in production:
        a.cache.Set(serialNumber, "principal_not_found")
        return store.ErrPrincipalNotFound
    }

    // Check if principal is suspended
    if principal.Status == "suspended" {
        log.Warn().
            Str("principal_id", principalID).
            Str("serial_number", serialNumber).
            Msg("suspended principal rejected")

        a.cache.Set(serialNumber, "principal_suspended")
        return store.ErrPrincipalSuspended
    }

    // Check if principal is deleted
    if principal.Status == "deleted" {
        log.Warn().
            Str("principal_id", principalID).
            Str("serial_number", serialNumber).
            Msg("deleted principal rejected")

        a.cache.Set(serialNumber, "principal_deleted")
        return store.ErrPrincipalDeleted
    }

    // Check 2: Certificate revocation
    certMetadata, err := a.certStore.Get(ctx, serialNumber)
    if err != nil {
        // Certificate not in our database
        log.Warn().
            Str("serial_number", serialNumber).
            Str("principal_id", principalID).
            Err(err).
            Msg("certificate not found in database")

        // Cache as allowed (short TTL) - certificate tracking is optional
        a.cache.Set(serialNumber, "allowed")
        return nil
    }

    // Check if certificate is revoked
    if certMetadata.Revoked {
        log.Warn().
            Str("serial_number", serialNumber).
            Str("principal_id", principalID).
            Time("revoked_at", *certMetadata.RevokedAt).
            Str("reason", certMetadata.RevocationReason).
            Msg("revoked certificate rejected")

        a.cache.Set(serialNumber, "cert_revoked")
        return store.ErrCertRevoked
    }

    // All checks passed - cache as allowed
    a.cache.Set(serialNumber, "allowed")
    return nil
}

// authCache caches authentication status
type authCache struct {
    mu      sync.RWMutex
    entries map[string]*authCacheEntry
    ttl     time.Duration
}

type authCacheEntry struct {
    status    string // "allowed", "principal_suspended", "cert_revoked", etc.
    cachedAt  time.Time
}

func newAuthCache(ttl time.Duration) *authCache {
    return &authCache{
        entries: make(map[string]*authCacheEntry),
        ttl:     ttl,
    }
}

func (c *authCache) Get(serialNumber string) (status string, found bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    entry, exists := c.entries[serialNumber]
    if !exists {
        return "", false
    }

    if time.Since(entry.cachedAt) > c.ttl {
        return "", false
    }

    return entry.status, true
}

func (c *authCache) Set(serialNumber string, status string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.entries[serialNumber] = &authCacheEntry{
        status:   status,
        cachedAt: time.Now(),
    }
}

// ExtractPrincipalFromCert extracts principal ID from certificate CN
func ExtractPrincipalFromCert(cert *x509.Certificate) string {
    return cert.Subject.CommonName
}

// MTLSAuthFunc creates an authentication function for mTLS
func NewMTLSAuthFunc() authn.AuthFunc {
    return func(ctx context.Context, req authn.Request) (any, error) {
        // Skip health check
        if req.URL().Path == "/health" {
            return nil, nil
        }

        // Extract client certificate from TLS connection state
        // This is populated by the TLS layer during handshake
        tlsInfo := req.Peer()
        if tlsInfo == nil {
            return nil, authn.Errorf("no TLS peer info")
        }

        // In Connect RPC, we can access TLS state from the request
        // The certificate has already been verified by VerifyPeerCertificate
        certs := tlsInfo.Certs
        if len(certs) == 0 {
            return nil, authn.Errorf("no client certificate")
        }

        clientCert := certs[0]
        principalID := ExtractPrincipalFromCert(clientCert)

        log.Debug().
            Str("principal_id", principalID).
            Str("serial_number", clientCert.SerialNumber.Text(16)).
            Msg("mTLS authentication successful")

        return principalID, nil
    }
}
```

### 4. CLI Principal Management Commands

**File:** `cmd/cli/internal/commands/principal.go` (new file)

```go
package commands

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net/http"
    "os"
    "time"

    "connectrpc.com/connect"
    "github.com/rs/zerolog/log"

    jobv1 "github.com/wolfeidau/airunner/gen/job/v1"
)

type PrincipalCmd struct {
    Create  PrincipalCreateCmd  `cmd:"" help:"Create a new principal"`
    List    PrincipalListCmd    `cmd:"" help:"List principals"`
    Suspend PrincipalSuspendCmd `cmd:"" help:"Suspend a principal"`
    Activate PrincipalActivateCmd `cmd:"" help:"Activate a suspended principal"`
    Get     PrincipalGetCmd     `cmd:"" help:"Get principal details"`
}

type PrincipalCreateCmd struct {
    PrincipalID string        `arg:"" help:"Principal identifier (e.g., worker-prod-01)"`
    Type        string        `help:"Principal type" enum:"worker,user,service,admin" default:"worker"`
    Email       string        `help:"Contact email"`
    Description string        `help:"Description"`
    Server      string        `help:"Server URL" default:"https://localhost:8993"`
    CACert      string        `help:"Path to CA cert" env:"AIRUNNER_CA_CERT" required:""`
    ClientKey   string        `help:"Path to admin private key" required:""`
    ClientCert  string        `help:"Path to admin certificate" required:""`
    Timeout     time.Duration `help:"Client timeout" default:"30s"`
}

func (c *PrincipalCreateCmd) Run(ctx context.Context, globals *Globals) error {
    // Create mTLS client
    clientCert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
    if err != nil {
        return fmt.Errorf("failed to load client credentials: %w", err)
    }

    caCert, err := os.ReadFile(c.CACert)
    if err != nil {
        return fmt.Errorf("failed to read CA cert: %w", err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS13,
    }

    httpClient := &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
        Timeout:   c.Timeout,
    }

    client := jobv1connect.NewJobServiceClient(httpClient, c.Server)

    req := &jobv1.CreatePrincipalRequest{
        PrincipalId: c.PrincipalID,
        Type:        c.Type,
        Email:       c.Email,
        Description: c.Description,
    }

    resp, err := client.CreatePrincipal(ctx, connect.NewRequest(req))
    if err != nil {
        return fmt.Errorf("failed to create principal: %w", err)
    }

    log.Info().
        Str("principal_id", c.PrincipalID).
        Time("created_at", resp.Msg.CreatedAt.AsTime()).
        Msg("principal created")

    fmt.Printf("Principal created: %s\n", c.PrincipalID)
    fmt.Printf("Type: %s\n", c.Type)
    fmt.Printf("Status: active\n")

    return nil
}

type PrincipalSuspendCmd struct {
    PrincipalID string        `arg:"" help:"Principal identifier"`
    Reason      string        `help:"Reason for suspension" required:""`
    Server      string        `help:"Server URL" default:"https://localhost:8993"`
    CACert      string        `help:"Path to CA cert" env:"AIRUNNER_CA_CERT" required:""`
    ClientKey   string        `help:"Path to admin private key" required:""`
    ClientCert  string        `help:"Path to admin certificate" required:""`
    Timeout     time.Duration `help:"Client timeout" default:"30s"`
}

func (c *PrincipalSuspendCmd) Run(ctx context.Context, globals *Globals) error {
    // Create mTLS client (same as PrincipalCreateCmd)
    // ... [omitted for brevity]

    req := &jobv1.SuspendPrincipalRequest{
        PrincipalId: c.PrincipalID,
        Reason:      c.Reason,
    }

    _, err := client.SuspendPrincipal(ctx, connect.NewRequest(req))
    if err != nil {
        return fmt.Errorf("failed to suspend principal: %w", err)
    }

    log.Info().
        Str("principal_id", c.PrincipalID).
        Str("reason", c.Reason).
        Msg("principal suspended")

    fmt.Printf("Principal suspended: %s\n", c.PrincipalID)
    fmt.Printf("All certificates for this principal are now blocked\n")

    return nil
}
```

### 5. CLI Certificate Management Commands

**File:** `cmd/cli/internal/commands/cert.go` (new file)

```go
package commands

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "time"

    "github.com/google/uuid"
    "github.com/rs/zerolog/log"
    "connectrpc.com/connect"

    jobv1 "github.com/wolfeidau/airunner/gen/job/v1"
    "github.com/wolfeidau/airunner/internal/client"
)

type CertCmd struct {
    Generate CertGenerateCmd `cmd:"" help:"Generate key pair and CSR"`
    Sign     CertSignCmd     `cmd:"" help:"Sign CSR to produce certificate (admin only)"`
    Register CertRegisterCmd `cmd:"" help:"Register certificate with server"`
    List     CertListCmd     `cmd:"" help:"List registered certificates"`
    Revoke   CertRevokeCmd   `cmd:"" help:"Revoke a certificate"`
    Renew    CertRenewCmd    `cmd:"" help:"Renew expiring certificate"`
}

type CertGenerateCmd struct {
    PrincipalID string `arg:"" help:"Principal identifier (e.g., worker-prod-01)"`
    KeysDir     string `help:"Directory to store keys" default:"~/.airunner/keys"`
    Force       bool   `help:"Overwrite existing keys" default:"false"`
}

func (c *CertGenerateCmd) Run(ctx context.Context, globals *Globals) error {
    keysDir := expandPath(c.KeysDir)

    if err := os.MkdirAll(keysDir, 0700); err != nil {
        return fmt.Errorf("failed to create keys directory: %w", err)
    }

    privateKeyPath := filepath.Join(keysDir, fmt.Sprintf("%s-private.pem", c.PrincipalID))
    csrPath := filepath.Join(keysDir, fmt.Sprintf("%s-csr.pem", c.PrincipalID))

    // Check if keys already exist
    if !c.Force {
        if _, err := os.Stat(privateKeyPath); err == nil {
            return fmt.Errorf("private key already exists: %s (use --force to overwrite)", privateKeyPath)
        }
    }

    // Generate ECDSA P-256 key pair
    log.Info().Msg("generating ECDSA P-256 key pair...")
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return fmt.Errorf("failed to generate key pair: %w", err)
    }

    // Marshal private key
    privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
    if err != nil {
        return fmt.Errorf("failed to marshal private key: %w", err)
    }

    privateKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: privateKeyBytes,
    })

    // Create Certificate Signing Request (CSR)
    csrTemplate := &x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName:   c.PrincipalID,
            Organization: []string{"Airunner"},
        },
        DNSNames:           []string{c.PrincipalID}, // SAN
        SignatureAlgorithm: x509.ECDSAWithSHA256,
    }

    csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
    if err != nil {
        return fmt.Errorf("failed to create CSR: %w", err)
    }

    csrPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE REQUEST",
        Bytes: csrDER,
    })

    // Write private key (chmod 0600)
    if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
        return fmt.Errorf("failed to write private key: %w", err)
    }

    // Write CSR
    if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
        return fmt.Errorf("failed to write CSR: %w", err)
    }

    fmt.Printf("\nGenerated key pair and CSR for principal: %s\n", c.PrincipalID)
    fmt.Printf("Private key: %s\n", privateKeyPath)
    fmt.Printf("CSR: %s\n", csrPath)
    fmt.Printf("\nNext steps:\n")
    fmt.Printf("  1. Send CSR to admin for signing:\n")
    fmt.Printf("     Admin runs: airunner-cli cert sign %s --csr=%s\n", c.PrincipalID, csrPath)
    fmt.Printf("  2. Admin sends back signed certificate\n")
    fmt.Printf("  3. Register certificate with server:\n")
    fmt.Printf("     airunner-cli cert register %s --cert=<cert-file>\n", c.PrincipalID)

    return nil
}

type CertSignCmd struct {
    PrincipalID string `arg:"" help:"Principal identifier"`
    CSRPath     string `help:"Path to CSR file" required:""`
    CAKeyPath   string `help:"Path to CA private key" env:"AIRUNNER_CA_KEY" required:""`
    CACertPath  string `help:"Path to CA certificate" env:"AIRUNNER_CA_CERT" required:""`
    TTLDays     int    `help:"Certificate lifetime in days" default:"90"`
    OutputPath  string `help:"Output certificate path" default:""`
}

func (c *CertSignCmd) Run(ctx context.Context, globals *Globals) error {
    // Read CSR
    csrPEM, err := os.ReadFile(c.CSRPath)
    if err != nil {
        return fmt.Errorf("failed to read CSR: %w", err)
    }

    csrBlock, _ := pem.Decode(csrPEM)
    if csrBlock == nil {
        return fmt.Errorf("failed to decode CSR PEM")
    }

    csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse CSR: %w", err)
    }

    // Verify CSR signature
    if err := csr.CheckSignature(); err != nil {
        return fmt.Errorf("invalid CSR signature: %w", err)
    }

    // Load CA private key
    caKeyPEM, err := os.ReadFile(c.CAKeyPath)
    if err != nil {
        return fmt.Errorf("failed to read CA key: %w", err)
    }

    caKeyBlock, _ := pem.Decode(caKeyPEM)
    caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse CA key: %w", err)
    }

    // Load CA certificate
    caCertPEM, err := os.ReadFile(c.CACertPath)
    if err != nil {
        return fmt.Errorf("failed to read CA cert: %w", err)
    }

    caCertBlock, _ := pem.Decode(caCertPEM)
    caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse CA cert: %w", err)
    }

    // Generate serial number (UUIDv7 for time-ordering)
    serialNumber := new(big.Int)
    uuidBytes := uuid.Must(uuid.NewV7())
    serialNumber.SetBytes(uuidBytes[:])

    // Create certificate
    now := time.Now()
    template := &x509.Certificate{
        SerialNumber: serialNumber,
        Subject:      csr.Subject,
        DNSNames:     csr.DNSNames,
        NotBefore:    now,
        NotAfter:     now.Add(time.Duration(c.TTLDays) * 24 * time.Hour),
        KeyUsage:     x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }

    // Sign certificate with CA
    certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
    if err != nil {
        return fmt.Errorf("failed to create certificate: %w", err)
    }

    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certDER,
    })

    // Determine output path
    outputPath := c.OutputPath
    if outputPath == "" {
        outputPath = filepath.Join(filepath.Dir(c.CSRPath), fmt.Sprintf("%s-cert.pem", c.PrincipalID))
    }

    // Write certificate
    if err := os.WriteFile(outputPath, certPEM, 0644); err != nil {
        return fmt.Errorf("failed to write certificate: %w", err)
    }

    fmt.Printf("Certificate issued successfully!\n")
    fmt.Printf("Serial Number: %s\n", serialNumber.Text(16))
    fmt.Printf("Principal: %s\n", c.PrincipalID)
    fmt.Printf("Valid From: %s\n", template.NotBefore.Format(time.RFC3339))
    fmt.Printf("Valid Until: %s\n", template.NotAfter.Format(time.RFC3339))
    fmt.Printf("Certificate: %s\n", outputPath)
    fmt.Printf("\nNext step: Send certificate to principal for registration\n")

    return nil
}

type CertRegisterCmd struct {
    PrincipalID string        `arg:"" help:"Principal identifier"`
    CertPath    string        `help:"Path to signed certificate" required:""`
    Server      string        `help:"Server URL" default:"https://localhost:8993"`
    CACert      string        `help:"Path to CA cert for mTLS" env:"AIRUNNER_CA_CERT" required:""`
    ClientKey   string        `help:"Path to client private key (for bootstrap)" required:""`
    ClientCert  string        `help:"Path to client cert (for bootstrap)" required:""`
    Description string        `help:"Optional description"`
    Timeout     time.Duration `help:"Client timeout" default:"30s"`
}

func (c *CertRegisterCmd) Run(ctx context.Context, globals *Globals) error {
    // Read certificate to register
    certPEM, err := os.ReadFile(c.CertPath)
    if err != nil {
        return fmt.Errorf("failed to read certificate: %w", err)
    }

    certBlock, _ := pem.Decode(certPEM)
    cert, err := x509.ParseCertificate(certBlock.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse certificate: %w", err)
    }

    // Load mTLS client credentials (bootstrap admin cert)
    clientCert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
    if err != nil {
        return fmt.Errorf("failed to load client credentials: %w", err)
    }

    // Load CA cert
    caCert, err := os.ReadFile(c.CACert)
    if err != nil {
        return fmt.Errorf("failed to read CA cert: %w", err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // Create mTLS client
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS13,
    }

    httpClient := &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
        Timeout:   c.Timeout,
    }

    client := jobv1connect.NewJobServiceClient(httpClient, c.Server)

    // Register certificate
    fingerprint := sha256.Sum256(cert.Raw)
    req := &jobv1.RegisterCertificateRequest{
        SerialNumber: cert.SerialNumber.Text(16),
        PrincipalId:  c.PrincipalID,
        Fingerprint:  base64.StdEncoding.EncodeToString(fingerprint[:]),
        SubjectDn:    cert.Subject.String(),
        IssuedAt:     timestamppb.New(cert.NotBefore),
        ExpiresAt:    timestamppb.New(cert.NotAfter),
        Description:  c.Description,
    }

    resp, err := client.RegisterCertificate(ctx, connect.NewRequest(req))
    if err != nil {
        return fmt.Errorf("failed to register certificate: %w", err)
    }

    log.Info().
        Str("principal_id", c.PrincipalID).
        Str("serial_number", cert.SerialNumber.Text(16)).
        Time("registered_at", resp.Msg.RegisteredAt.AsTime()).
        Msg("certificate registered successfully")

    fmt.Printf("Certificate registered for principal: %s\n", c.PrincipalID)
    fmt.Printf("Serial Number: %s\n", cert.SerialNumber.Text(16))
    fmt.Printf("\nYou can now use this certificate for mTLS authentication\n")

    return nil
}

type CertRevokeCmd struct {
    SerialNumber string        `arg:"" help:"Certificate serial number (hex)"`
    Reason       string        `help:"Revocation reason" default:"unspecified"`
    Server       string        `help:"Server URL" default:"https://localhost:8993"`
    CACert       string        `help:"Path to CA cert" env:"AIRUNNER_CA_CERT" required:""`
    ClientKey    string        `help:"Path to admin private key" required:""`
    ClientCert   string        `help:"Path to admin certificate" required:""`
    Timeout      time.Duration `help:"Client timeout" default:"30s"`
}

func (c *CertRevokeCmd) Run(ctx context.Context, globals *Globals) error {
    // Create mTLS client
    clientCert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
    if err != nil {
        return fmt.Errorf("failed to load client credentials: %w", err)
    }

    caCert, err := os.ReadFile(c.CACert)
    if err != nil {
        return fmt.Errorf("failed to read CA cert: %w", err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS13,
    }

    httpClient := &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
        Timeout:   c.Timeout,
    }

    client := jobv1connect.NewJobServiceClient(httpClient, c.Server)

    req := &jobv1.RevokeCertificateRequest{
        SerialNumber: c.SerialNumber,
        Reason:       c.Reason,
    }

    _, err = client.RevokeCertificate(ctx, connect.NewRequest(req))
    if err != nil {
        return fmt.Errorf("failed to revoke certificate: %w", err)
    }

    log.Info().Str("serial_number", c.SerialNumber).Msg("certificate revoked")
    fmt.Printf("Certificate revoked: %s\n", c.SerialNumber)

    return nil
}
```

### 6. Worker Setup with mTLS

**File:** `cmd/cli/internal/commands/worker.go` (modify existing)

```go
type WorkerCmd struct {
    // ... existing fields ...

    // mTLS configuration
    CACert     string `help:"Path to CA certificate bundle" env:"AIRUNNER_CA_CERT"`
    ClientCert string `help:"Path to client certificate" env:"AIRUNNER_CLIENT_CERT"`
    ClientKey  string `help:"Path to client private key" env:"AIRUNNER_CLIENT_KEY"`

    // Certificate auto-renewal
    RenewalThreshold time.Duration `help:"Renew cert when this much time remains" default:"720h"` // 30 days
}

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
    // Load mTLS credentials
    clientCert, err := tls.LoadX509KeyPair(w.ClientCert, w.ClientKey)
    if err != nil {
        return fmt.Errorf("failed to load client certificate: %w", err)
    }

    // Load CA cert bundle
    caCert, err := os.ReadFile(w.CACert)
    if err != nil {
        return fmt.Errorf("failed to read CA cert: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return fmt.Errorf("failed to parse CA cert")
    }

    // Parse client certificate to check expiry
    cert, err := x509.ParseCertificate(clientCert.Certificate[0])
    if err != nil {
        return fmt.Errorf("failed to parse client cert: %w", err)
    }

    principalID := cert.Subject.CommonName

    log.Info().
        Str("principal_id", principalID).
        Str("serial_number", cert.SerialNumber.Text(16)).
        Time("expires_at", cert.NotAfter).
        Msg("loaded client certificate")

    // Check if certificate is expiring soon
    timeUntilExpiry := time.Until(cert.NotAfter)
    if timeUntilExpiry < w.RenewalThreshold {
        log.Warn().
            Dur("time_until_expiry", timeUntilExpiry).
            Dur("renewal_threshold", w.RenewalThreshold).
            Msg("certificate expiring soon - renewal recommended")
    }

    // Create TLS config
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS13,
    }

    // Create HTTP client with mTLS
    httpClient := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    // Create Connect RPC client
    client := jobv1connect.NewJobServiceClient(httpClient, w.Server)

    // Start certificate renewal monitor
    if w.RenewalThreshold > 0 {
        go w.monitorCertExpiry(ctx, cert, w.RenewalThreshold)
    }

    log.Info().
        Str("principal_id", principalID).
        Str("server", w.Server).
        Msg("worker started with mTLS authentication")

    // ... rest of worker logic (no token rotation needed!)

    return nil
}

func (w *WorkerCmd) monitorCertExpiry(ctx context.Context, cert *x509.Certificate, threshold time.Duration) {
    ticker := time.NewTicker(24 * time.Hour) // Check daily
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            timeUntilExpiry := time.Until(cert.NotAfter)

            if timeUntilExpiry < threshold {
                log.Warn().
                    Str("serial_number", cert.SerialNumber.Text(16)).
                    Dur("time_until_expiry", timeUntilExpiry).
                    Msg("certificate renewal required")

                // In production, you might:
                // 1. Request new certificate automatically
                // 2. Send alert to ops team
                // 3. Gracefully shutdown worker
            }
        }
    }
}
```

### 7. Server Configuration

**File:** `cmd/server/internal/commands/rpc.go` (modify existing)

```go
type RPCCmd struct {
    // ... existing fields ...

    // mTLS configuration
    CACert         string `help:"Path to CA certificate bundle" env:"AIRUNNER_CA_CERT"`
    ServerCert     string `help:"Path to server certificate" env:"AIRUNNER_SERVER_CERT"`
    ServerKey      string `help:"Path to server private key" env:"AIRUNNER_SERVER_KEY"`
    PrincipalTable string `help:"DynamoDB table for principal metadata" env:"AIRUNNER_PRINCIPAL_TABLE"`
    CertTable      string `help:"DynamoDB table for certificate metadata" env:"AIRUNNER_CERT_TABLE"`
}

func (s *RPCCmd) Run(ctx context.Context, globals *Globals) error {
    // ... existing setup ...

    var handler http.Handler

    if s.NoAuth {
        log.Warn().Msg("authentication disabled (development only)")
        handler = mux
    } else {
        // Initialize PrincipalStore
        var principalStore store.PrincipalStore

        if s.StoreType == "memory" {
            principalStore = store.NewMemoryPrincipalStore()
            log.Info().Msg("using in-memory principal store")
        } else {
            if s.PrincipalTable == "" {
                return fmt.Errorf("AIRUNNER_PRINCIPAL_TABLE required for production")
            }
            principalStore = store.NewDynamoDBPrincipalStore(dynamoClient, s.PrincipalTable)
            log.Info().Str("table", s.PrincipalTable).Msg("using DynamoDB principal store")
        }

        // Initialize CertificateStore
        var certStore store.CertificateStore

        if s.StoreType == "memory" {
            certStore = store.NewMemoryCertStore()
            log.Info().Msg("using in-memory certificate store")
        } else {
            if s.CertTable == "" {
                return fmt.Errorf("AIRUNNER_CERT_TABLE required for production")
            }
            certStore = store.NewDynamoDBCertStore(dynamoClient, s.CertTable)
            log.Info().Str("table", s.CertTable).Msg("using DynamoDB certificate store")
        }

        // Create mTLS config with principal and certificate stores
        tlsConfig, err := auth.NewMTLSConfig(s.CACert, principalStore, certStore)
        if err != nil {
            return fmt.Errorf("failed to initialize mTLS: %w", err)
        }

        log.Info().Msg("mTLS authentication enabled with principal validation")

        // Create mTLS auth middleware
        authFunc := auth.NewMTLSAuthFunc()
        middleware := authn.NewMiddleware(authFunc)
        handler = middleware.Wrap(mux)

        // Configure server TLS
        server.TLSConfig = tlsConfig
    }

    // Start HTTPS server with mTLS
    if s.ServerCert != "" && s.ServerKey != "" {
        log.Info().
            Str("addr", s.Addr).
            Msg("starting HTTPS server with mTLS")

        return server.ListenAndServeTLS(s.ServerCert, s.ServerKey)
    }

    // Fallback to HTTP (dev only)
    log.Info().Str("addr", s.Addr).Msg("starting HTTP server")
    return server.ListenAndServe()
}
```

### 8. Protocol Buffers (RPC API)

**File:** `api/job/v1/job.proto` (add new RPC methods)

```protobuf
service JobService {
    // ... existing methods ...

    // Principal Management
    rpc CreatePrincipal(CreatePrincipalRequest) returns (CreatePrincipalResponse) {
        option idempotency_level = IDEMPOTENT;
    }

    rpc GetPrincipal(GetPrincipalRequest) returns (GetPrincipalResponse) {
        option idempotency_level = NO_SIDE_EFFECTS;
    }

    rpc ListPrincipals(ListPrincipalsRequest) returns (ListPrincipalsResponse) {
        option idempotency_level = NO_SIDE_EFFECTS;
    }

    rpc SuspendPrincipal(SuspendPrincipalRequest) returns (SuspendPrincipalResponse) {
        option idempotency_level = IDEMPOTENT;
    }

    rpc ActivatePrincipal(ActivatePrincipalRequest) returns (ActivatePrincipalResponse) {
        option idempotency_level = IDEMPOTENT;
    }

    // Certificate Management
    rpc RegisterCertificate(RegisterCertificateRequest) returns (RegisterCertificateResponse) {
        option idempotency_level = IDEMPOTENT;
    }

    rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse) {
        option idempotency_level = IDEMPOTENT;
    }

    rpc ListCertificates(ListCertificatesRequest) returns (ListCertificatesResponse) {
        option idempotency_level = NO_SIDE_EFFECTS;
    }
}

// Principal Messages
message CreatePrincipalRequest {
    string principal_id = 1;
    string type = 2;           // worker, user, service, admin
    string email = 3;          // Optional contact email
    string description = 4;    // Human-readable description
}

message CreatePrincipalResponse {
    google.protobuf.Timestamp created_at = 1;
}

message GetPrincipalRequest {
    string principal_id = 1;
}

message GetPrincipalResponse {
    Principal principal = 1;
}

message ListPrincipalsRequest {
    string type = 1;    // Optional filter by type
    string status = 2;  // Optional filter by status
}

message ListPrincipalsResponse {
    repeated Principal principals = 1;
}

message SuspendPrincipalRequest {
    string principal_id = 1;
    string reason = 2;
}

message SuspendPrincipalResponse {
    google.protobuf.Timestamp suspended_at = 1;
}

message ActivatePrincipalRequest {
    string principal_id = 1;
}

message ActivatePrincipalResponse {
    google.protobuf.Timestamp activated_at = 1;
}

message Principal {
    string principal_id = 1;
    string type = 2;
    string status = 3;
    google.protobuf.Timestamp created_at = 4;
    string created_by = 5;
    string email = 6;
    string description = 7;
    int32 max_certificates = 8;
}

// Certificate Messages (existing)

message RegisterCertificateRequest {
    string serial_number = 1;  // Hex-encoded serial number
    string principal_id = 2;
    string fingerprint = 3;    // SHA-256 fingerprint (base64)
    string subject_dn = 4;
    google.protobuf.Timestamp issued_at = 5;
    google.protobuf.Timestamp expires_at = 6;
    string description = 7;
}

message RegisterCertificateResponse {
    google.protobuf.Timestamp registered_at = 1;
}

message RevokeCertificateRequest {
    string serial_number = 1;
    string reason = 2;  // key_compromise, superseded, cessation_of_operation, etc.
}

message RevokeCertificateResponse {
    google.protobuf.Timestamp revoked_at = 1;
}

message ListCertificatesRequest {
    string principal_id = 1;  // Optional filter by principal
}

message ListCertificatesResponse {
    repeated Certificate certificates = 1;
}

message Certificate {
    string serial_number = 1;
    string principal_id = 2;
    string fingerprint = 3;
    string subject_dn = 4;
    google.protobuf.Timestamp issued_at = 5;
    google.protobuf.Timestamp expires_at = 6;
    bool revoked = 7;
    google.protobuf.Timestamp revoked_at = 8;
    string revocation_reason = 9;
    string description = 10;
}
```

### 9. Infrastructure: DynamoDB Tables

**File:** `infra/backend.tf` (add new tables)

**Principals Table:**
```hcl
resource "aws_dynamodb_table" "principals" {
  name         = "${local.name_prefix}_principals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_id"

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "type"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "N"
  }

  # GSI1: List principals by status and creation time
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "status"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI2: List principals by type (all workers, all users)
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "type"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.tags, {
    Name = "${local.name_prefix}_principals"
  })
}
```

**Certificates Table:**
```hcl
resource "aws_dynamodb_table" "certificates" {
  name         = "${local.name_prefix}_certificates"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "serial_number"

  attribute {
    name = "serial_number"
    type = "S"
  }

  attribute {
    name = "principal_id"
    type = "S"
  }

  attribute {
    name = "issued_at"
    type = "N"
  }

  attribute {
    name = "fingerprint"
    type = "S"
  }

  # GSI1: List certs by principal
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "principal_id"
    range_key       = "issued_at"
    projection_type = "ALL"
  }

  # GSI2: Lookup by fingerprint
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "fingerprint"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.tags, {
    Name = "${local.name_prefix}_certificates"
  })
}
```

### 10. Certificate Authority Setup

**File:** `cmd/cli/internal/commands/ca.go` (new file - admin tool)

```go
package commands

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "time"

    "github.com/rs/zerolog/log"
)

type CACmd struct {
    Init CAInitCmd `cmd:"" help:"Initialize Certificate Authority"`
}

type CAInitCmd struct {
    OutputDir string `help:"Directory to store CA files" default:"./ca"`
    CommonName string `help:"CA common name" default:"Airunner Root CA"`
    ValidYears int    `help:"CA validity period in years" default:"10"`
}

func (c *CAInitCmd) Run(ctx context.Context, globals *Globals) error {
    // Create output directory
    if err := os.MkdirAll(c.OutputDir, 0700); err != nil {
        return fmt.Errorf("failed to create output directory: %w", err)
    }

    // Generate CA private key
    log.Info().Msg("generating CA private key (ECDSA P-256)...")
    caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return fmt.Errorf("failed to generate CA key: %w", err)
    }

    // Create CA certificate
    serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return fmt.Errorf("failed to generate serial number: %w", err)
    }

    template := &x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            CommonName:   c.CommonName,
            Organization: []string{"Airunner"},
            Country:      []string{"US"},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(time.Duration(c.ValidYears) * 365 * 24 * time.Hour),
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
        MaxPathLen:            0,
    }

    // Self-sign CA certificate
    log.Info().Msg("creating self-signed CA certificate...")
    caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
    if err != nil {
        return fmt.Errorf("failed to create CA certificate: %w", err)
    }

    // Marshal CA private key
    caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
    if err != nil {
        return fmt.Errorf("failed to marshal CA key: %w", err)
    }

    caKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: caKeyBytes,
    })

    caCertPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: caCertDER,
    })

    // Write files
    caKeyPath := filepath.Join(c.OutputDir, "ca-key.pem")
    caCertPath := filepath.Join(c.OutputDir, "ca-cert.pem")

    if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
        return fmt.Errorf("failed to write CA key: %w", err)
    }

    if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
        return fmt.Errorf("failed to write CA cert: %w", err)
    }

    cert, _ := x509.ParseCertificate(caCertDER)

    fmt.Printf("\n✓ Certificate Authority initialized!\n\n")
    fmt.Printf("CA Details:\n")
    fmt.Printf("  Common Name: %s\n", cert.Subject.CommonName)
    fmt.Printf("  Serial: %s\n", cert.SerialNumber.Text(16))
    fmt.Printf("  Valid From: %s\n", cert.NotBefore.Format(time.RFC3339))
    fmt.Printf("  Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339))
    fmt.Printf("\nFiles created:\n")
    fmt.Printf("  CA Private Key: %s (KEEP SECURE!)\n", caKeyPath)
    fmt.Printf("  CA Certificate: %s (distribute to all clients/servers)\n", caCertPath)
    fmt.Printf("\nIMPORTANT - Next Steps:\n")
    fmt.Printf("  1. Store CA private key in AWS Secrets Manager:\n")
    fmt.Printf("       aws secretsmanager create-secret --name airunner/ca-key --secret-binary fileb://%s\n", caKeyPath)
    fmt.Printf("  2. Distribute CA certificate to all servers and workers\n")
    fmt.Printf("  3. Delete local copy of CA private key (use Secrets Manager for signing)\n")

    log.Info().
        Str("ca_key", caKeyPath).
        Str("ca_cert", caCertPath).
        Msg("CA initialized")

    return nil
}
```

## Implementation Plan

Since this is a greenfield implementation (no existing users to migrate), the implementation is straightforward:

### Phase 1: Infrastructure & Certificates

**1. Update Infrastructure (Terraform):**
```bash
cd infra

# Remove JWT resources, add mTLS resources
# - Remove: tls_private_key.jwt, aws_ssm_parameter.jwt_*
# - Change: ALB → NLB with TCP passthrough
# - Add: DynamoDB principals table
# - Add: DynamoDB certificates table
# - Add: 3 SSM parameters (server cert/key, client CA)

terraform plan
terraform apply
```

**2. Initialize Certificate Authority:**
```bash
# Generate CA for client certificates
./bin/airunner-cli ca init --output-dir=./ca --common-name="Airunner Client CA"

# Upload to AWS
aws ssm put-parameter \
  --name /airunner/dev/client-ca-cert \
  --value file://ca/ca-cert.pem \
  --type String

aws secretsmanager create-secret \
  --name /airunner/dev/ca-private-key \
  --secret-binary fileb://ca/ca-key.pem
```

**3. Obtain Let's Encrypt Certificate:**
```bash
# Get server certificate (auto-renewable)
certbot certonly --dns-route53 -d airunner-dev.wolfeidau.com

# Upload to SSM
aws ssm put-parameter \
  --name /airunner/dev/server-cert \
  --value file:///etc/letsencrypt/live/airunner-dev.wolfeidau.com/fullchain.pem \
  --type String

aws ssm put-parameter \
  --name /airunner/dev/server-key \
  --value file:///etc/letsencrypt/live/airunner-dev.wolfeidau.com/privkey.pem \
  --type SecureString

# Set up auto-renewal (see Bootstrap Sequence section)
```

### Phase 2: Application Code

**1. Implement mTLS Authentication:**
- Create `internal/store/principal_store.go` (PrincipalStore interface)
- Create `internal/store/certificate_store.go` (CertificateStore interface)
- Create `internal/auth/mtls.go` (updated with principal status checking)
- Update `cmd/server/internal/commands/rpc.go` (replace JWT with mTLS)
- Delete `internal/auth/jwt.go` and `internal/auth/token.go`

**2. Implement Principal Management:**
- Create `cmd/cli/internal/commands/principal.go` (create, list, suspend, activate)
- Implement `internal/store/dynamodb_principal_store.go`
- Implement `internal/store/memory_principal_store.go`

**3. Implement Certificate Management:**
- Create `cmd/cli/internal/commands/cert.go` (generate, sign, register, revoke, list)
- Create `cmd/cli/internal/commands/ca.go` (init)
- Update `cmd/cli/internal/commands/worker.go` (mTLS client)
- Implement `internal/store/dynamodb_cert_store.go`
- Implement `internal/store/memory_cert_store.go`

**4. Update Protocol Buffers:**
- Add principal management RPCs to `api/job/v1/job.proto`
- Add certificate management RPCs to `api/job/v1/job.proto`
- Run `make proto-generate`

### Phase 3: Testing & Deployment

**1. Local Testing:**
```bash
# Generate local CA and certificates
./bin/airunner-cli ca init --output-dir=./ca
./bin/airunner-cli cert generate localhost-server
./bin/airunner-cli cert sign localhost-server

# Run server locally
./bin/airunner-server \
  --listen=0.0.0.0:8443 \
  --server-cert=~/.airunner/keys/localhost-server-cert.pem \
  --server-key=~/.airunner/keys/localhost-server-private.pem \
  --client-ca-cert=./ca/ca-cert.pem \
  --store-type=memory \
  --cert-store-type=memory

# Generate worker certificate
./bin/airunner-cli cert generate worker-local
./bin/airunner-cli cert sign worker-local

# Test worker connection
./bin/airunner-cli worker \
  --server=https://localhost:8443 \
  --ca-cert=ca/ca-cert.pem \
  --client-cert=~/.airunner/keys/worker-local-cert.pem \
  --client-key=~/.airunner/keys/worker-local-private.pem
```

**2. Deploy to AWS:**
```bash
# Build and push container
make build
docker build -t airunner:latest .
docker push <ecr-repo>/airunner:latest

# Deploy via ECS
aws ecs update-service \
  --cluster airunner-dev-cluster \
  --service airunner-dev \
  --force-new-deployment
```

**3. Create Principals and Generate Certificates:**
```bash
# For each worker - first create principal
WORKER_ID="worker-01"

# Create principal (using admin cert)
./bin/airunner-cli principal create $WORKER_ID \
  --type=worker \
  --email=ops@example.com \
  --description="Production worker 01" \
  --client-cert=~/.airunner/keys/admin-bootstrap-cert.pem \
  --client-key=~/.airunner/keys/admin-bootstrap-private.pem

# Generate certificate for principal
./bin/airunner-cli cert generate $WORKER_ID
./bin/airunner-cli cert sign $WORKER_ID \
  --ca-key=ca/ca-key.pem \
  --ca-cert=ca/ca-cert.pem

# Register certificate
./bin/airunner-cli cert register $WORKER_ID \
  --cert=~/.airunner/keys/${WORKER_ID}-cert.pem \
  --client-cert=~/.airunner/keys/admin-bootstrap-cert.pem \
  --client-key=~/.airunner/keys/admin-bootstrap-private.pem

# Deploy cert to worker (via secure channel)
# Worker connects with:
./bin/airunner-cli worker \
  --server=https://airunner-dev.wolfeidau.com \
  --client-cert=~/.airunner/keys/${WORKER_ID}-cert.pem \
  --client-key=~/.airunner/keys/${WORKER_ID}-private.pem
```

### Phase 4: Cleanup

**1. Remove JWT Code:**
- Delete `internal/auth/jwt.go`
- Delete `internal/auth/token.go`
- Remove JWT-related tests
- Remove `JWT_PUBLIC_KEY` references from docs

**2. Update Documentation:**
- Update README with mTLS setup instructions
- Document certificate generation workflow
- Document certificate renewal process

## Operational Considerations

### Certificate Lifecycle Management

**Certificate Expiry Monitoring:**
```bash
# Daily cron job to check expiring certs
airunner-cli cert list --expiring-within=30d

# Alert if certs expiring soon
if [ $(airunner-cli cert list --expiring-within=7d --format=count) -gt 0 ]; then
    send-alert "Certificates expiring within 7 days!"
fi
```

**Certificate Renewal Process:**
```bash
# Worker monitors own cert expiry
# When 30 days remaining:
# 1. Generate new key pair
airunner-cli cert generate worker-prod-01 --force

# 2. Submit CSR to admin (via API or secure channel)
# 3. Admin signs and returns new cert
# 4. Worker registers new cert
# 5. Worker reloads TLS config (graceful reload)
# 6. Old cert expires naturally (overlap period)
```

### Revocation

**Principal-level suspension (blocks ALL certificates immediately):**
```bash
# Suspend entire principal (fastest, blocks all their certs)
airunner-cli principal suspend worker-prod-01 \
  --reason="Security incident - investigating" \
  --client-cert=admin-cert.pem \
  --client-key=admin-key.pem

# All servers reject ALL certs for this principal within cache TTL (5 minutes)

# Later, reactivate if cleared
airunner-cli principal activate worker-prod-01 \
  --client-cert=admin-cert.pem \
  --client-key=admin-key.pem
```

**Certificate-level revocation (single certificate):**
```bash
# Revoke specific compromised cert (when principal has multiple certs)
airunner-cli cert revoke a1b2c3d4e5f6 \
  --reason=key_compromise \
  --client-cert=admin-cert.pem \
  --client-key=admin-key.pem

# Only this specific cert is rejected, other certs for same principal still valid
```

### Monitoring Metrics

```go
// internal/telemetry/metrics.go
var (
    MTLSAuthTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "airunner_mtls_auth_total",
            Help: "Total mTLS authentication attempts",
        },
        []string{"result"}, // success, cert_expired, cert_revoked, invalid
    )

    MTLSCertExpiryGauge = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "airunner_mtls_cert_expiry_seconds",
            Help: "Seconds until certificate expiry",
        },
        []string{"principal_id", "serial_number"},
    )

    RevocationCacheHitRate = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "airunner_revocation_cache_hits_total",
            Help: "Certificate revocation cache hits",
        },
    )
)
```

### Alerts

**Critical:**
- Certificate expiring within 7 days
- Revoked certificate usage detected
- CA private key accessed (CloudTrail)

**Warning:**
- Certificate expiring within 30 days
- Revocation cache miss rate > 20%
- TLS handshake failures > 1%

## Comparison: mTLS vs JWT vs HTTP Signatures

| Aspect | JWT Bearer | HTTP Signatures | mTLS |
|--------|-----------|-----------------|------|
| **Message Integrity** | ❌ | ✅ | ✅ |
| **Replay Protection** | ❌ | ✅ | ✅ |
| **Implementation** | Medium | High | Low |
| **Application Code** | Yes | Yes | No |
| **Performance** | Best | Good | Excellent |
| **Certificate Mgmt** | Simple | Simple | Standard PKI |
| **Maturity** | Very Mature | New (2024) | Very Mature |
| **Debugging** | Easy | Hard | Medium |
| **Zero-downtime rotation** | Yes | N/A | Yes |

## Conclusion

**mTLS is the recommended approach** for airunner because:

1. ✅ **Solves message integrity and replay protection** - Your actual requirements
2. ✅ **Zero application code** - TLS handles everything at transport layer
3. ✅ **Battle-tested** - Used by Google, Netflix, Stripe for service-to-service auth
4. ✅ **Industry standard** - Standard PKI infrastructure and tools
5. ✅ **Best performance** - No per-request signing overhead
6. ✅ **Works with Connect RPC** - First-class support

The main trade-off is certificate management complexity vs JWT's simplicity, but standard PKI tools make this manageable.