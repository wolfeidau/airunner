# mTLS Operations Runbook

## Overview

This runbook provides operational procedures for managing mTLS authentication in production. These procedures cover common Day 2 operations including principal management, certificate revocation, rotation, and monitoring.

**Audience:** Operations engineers, SREs, platform administrators

**Prerequisites:**
- Admin certificate and key (`admin-cert.pem`, `admin-key.pem`)
- AWS CLI configured with appropriate permissions
- Access to DynamoDB tables (principals, certificates)
- `airunner-cli` binary

## Table of Contents

- [Suspend a Principal](#suspend-a-principal)
- [Activate a Suspended Principal](#activate-a-suspended-principal)
- [Revoke a Specific Certificate](#revoke-a-specific-certificate)
- [Rotate Server Certificate](#rotate-server-certificate)
- [Monitor Certificate Expiry](#monitor-certificate-expiry)
- [Emergency Procedures](#emergency-procedures)
- [Metrics and Monitoring](#metrics-and-monitoring)

## Suspend a Principal

**Use Case:** Immediately revoke access for a compromised or terminated principal (user, worker, service).

**Effect:** All certificates for this principal will be rejected, even if not individually revoked.

### Procedure

```bash
# Suspend a principal with reason
airunner-cli principal suspend <principal-id> \
  --reason="<reason>" \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem

# Example: Suspend compromised worker
airunner-cli principal suspend worker-prod-01 \
  --reason="Compromised credentials detected" \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem
```

**Using AWS CLI (if airunner-cli unavailable):**

```bash
# Update principal status in DynamoDB
aws dynamodb update-item \
  --table-name airunner_prod_principals \
  --key '{"principal_id": {"S": "worker-prod-01"}}' \
  --update-expression "SET #status = :suspended, suspended_at = :now, suspended_reason = :reason" \
  --expression-attribute-names '{"#status": "status"}' \
  --expression-attribute-values '{
    ":suspended": {"S": "suspended"},
    ":now": {"N": "'"$(date +%s000)"'"},
    ":reason": {"S": "Compromised credentials detected"}
  }'
```

**Verification:**

```bash
# Verify principal is suspended
airunner-cli principal get worker-prod-01 \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem

# Expected output:
# Principal: worker-prod-01
# Status: suspended
# Suspended At: 2024-12-25T10:30:00Z
# Suspended Reason: Compromised credentials detected

# Test that suspended principal cannot authenticate
# (Should fail with "principal suspended" error)
curl --cacert ca-cert.pem \
     --cert worker-prod-01-cert.pem \
     --key worker-prod-01-key.pem \
     https://airunner.example.com/job.v1.JobService/ListJobs

# Expected: 401 Unauthorized (principal suspended: Compromised credentials detected)
```

**Rollback:**

To re-activate the principal, see [Activate a Suspended Principal](#activate-a-suspended-principal).

---

## Activate a Suspended Principal

**Use Case:** Restore access for a previously suspended principal after investigation/remediation.

### Procedure

```bash
# Activate a suspended principal
airunner-cli principal activate <principal-id> \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem

# Example
airunner-cli principal activate worker-prod-01 \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem
```

**Using AWS CLI:**

```bash
aws dynamodb update-item \
  --table-name airunner_prod_principals \
  --key '{"principal_id": {"S": "worker-prod-01"}}' \
  --update-expression "SET #status = :active REMOVE suspended_at, suspended_reason" \
  --expression-attribute-names '{"#status": "status"}' \
  --expression-attribute-values '{":active": {"S": "active"}}'
```

---

## Revoke a Specific Certificate

**Use Case:** Revoke a single compromised certificate without affecting the principal's other certificates.

**Effect:** Only the specific certificate serial number is revoked; principal can still authenticate with other valid certificates.

### Procedure

```bash
# List certificates for a principal
airunner-cli certificate list worker-prod-01 \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem

# Expected output:
# Serial: 01936d3fa2b17c4e8f5d
# Issued: 2024-12-25T00:00:00Z
# Expires: 2025-03-25T23:59:59Z
# Status: active
#
# Serial: 01936d3fa2b17c4e8f5e
# Issued: 2024-12-26T00:00:00Z
# Expires: 2025-03-26T23:59:59Z
# Status: active

# Revoke specific certificate by serial number
airunner-cli certificate revoke <serial-number> \
  --reason="<reason>" \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem

# Example
airunner-cli certificate revoke 01936d3fa2b17c4e8f5d \
  --reason="key_compromise" \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem
```

**Revocation Reasons:**
- `key_compromise` - Private key has been compromised
- `superseded` - Certificate has been replaced by a newer one
- `cessation_of_operation` - Principal no longer performs the role
- `affiliation_changed` - Principal's affiliation changed

**Using AWS CLI:**

```bash
aws dynamodb update-item \
  --table-name airunner_prod_certificates \
  --key '{"serial_number": {"S": "01936d3fa2b17c4e8f5d"}}' \
  --update-expression "SET revoked = :true, revoked_at = :now, revocation_reason = :reason" \
  --expression-attribute-values '{
    ":true": {"BOOL": true},
    ":now": {"N": "'"$(date +%s000)"'"},
    ":reason": {"S": "key_compromise"}
  }'
```

---

## Rotate Server Certificate

**Use Case:** Renew server certificate before expiry or in response to compromise.

**Effect:** Server will use new certificate; clients unaffected (they verify via CA certificate which remains the same).

### Procedure

**Step 1: Generate new server certificate**

```bash
# Generate new server certificate using bootstrap command
# (Will not regenerate CA, only server cert)
airunner-cli bootstrap \
  --environment=prod \
  --domain=airunner.example.com \
  --aws-region=ap-southeast-2 \
  --output-dir=./new-server-certs

# Expected: Creates new server-cert.pem and server-key.pem
# Uploads to SSM automatically
```

**Step 2: Verify new certificate uploaded**

```bash
# Verify SSM parameter updated
aws ssm get-parameter \
  --name /airunner/prod/server-cert \
  --query 'Parameter.LastModifiedDate'

# Should show recent timestamp
```

**Step 3: Rolling restart of ECS service**

```bash
# Force new deployment (will pick up new certificates from SSM)
aws ecs update-service \
  --cluster airunner-prod \
  --service airunner-prod \
  --force-new-deployment \
  --region ap-southeast-2

# Monitor deployment
aws ecs describe-services \
  --cluster airunner-prod \
  --services airunner-prod \
  --query 'services[0].deployments' \
  --region ap-southeast-2
```

**Step 4: Verify new certificate in use**

```bash
# Check certificate from server
openssl s_client -connect airunner.example.com:443 -showcerts </dev/null 2>/dev/null | \
  openssl x509 -noout -dates

# Expected: New "Not After" date (90 days from now)
```

**Rollback:**

If issues occur:

```bash
# Restore previous certificate from backup
aws ssm put-parameter \
  --name /airunner/prod/server-cert \
  --value "$(cat backup/server-cert.pem)" \
  --overwrite

aws ssm put-parameter \
  --name /airunner/prod/server-key \
  --value "$(cat backup/server-key.pem)" \
  --type SecureString \
  --overwrite

# Force new deployment
aws ecs update-service \
  --cluster airunner-prod \
  --service airunner-prod \
  --force-new-deployment
```

---

## Monitor Certificate Expiry

**Use Case:** Proactively monitor certificate expiration to prevent outages.

### Monitoring Queries

**List certificates expiring in next 30 days:**

```bash
# Using airunner-cli
airunner-cli certificate list \
  --expiring-within=30d \
  --server=https://airunner.example.com \
  --cacert=~/.airunner/ca-cert.pem \
  --client-cert=~/.airunner/admin-cert.pem \
  --client-key=~/.airunner/admin-key.pem
```

**Using AWS CLI:**

```bash
# DynamoDB query for expiring certificates
THRESHOLD=$(($(date +%s) + 2592000))000  # 30 days from now in milliseconds

aws dynamodb scan \
  --table-name airunner_prod_certificates \
  --filter-expression "expires_at < :threshold AND revoked = :false" \
  --expression-attribute-values '{
    ":threshold": {"N": "'"$THRESHOLD"'"},
    ":false": {"BOOL": false}
  }' \
  --projection-expression "serial_number,principal_id,expires_at"
```

### Alert Thresholds

Set up CloudWatch alarms or monitoring alerts:

- **Warning:** Certificates expiring in < 30 days
- **Critical:** Certificates expiring in < 7 days
- **Emergency:** Certificates expiring in < 24 hours

### Automated Rotation

**Recommended:** Implement automated certificate rotation for workers:

```bash
# Worker rotation script (run daily via cron)
#!/bin/bash
CERT_FILE=~/.airunner/worker-cert.pem
DAYS_UNTIL_EXPIRY=$(openssl x509 -in $CERT_FILE -noout -checkend $((7*24*60*60)))

if [ $? -ne 0 ]; then
  echo "Certificate expiring soon, requesting renewal..."
  airunner-cli certificate renew \
    --server=https://airunner.example.com \
    --cacert=~/.airunner/ca-cert.pem \
    --client-cert=$CERT_FILE \
    --client-key=~/.airunner/worker-key.pem
fi
```

---

## Emergency Procedures

### Emergency: Mass Revocation

**Scenario:** CA key compromised, need to revoke all certificates

**Procedure:**

```bash
# 1. Suspend all principals except emergency admin
aws dynamodb scan \
  --table-name airunner_prod_principals \
  --filter-expression "principal_id <> :admin" \
  --expression-attribute-values '{":admin": {"S": "admin-emergency"}}' \
  --projection-expression "principal_id" | \
  jq -r '.Items[].principal_id.S' | \
  while read principal_id; do
    aws dynamodb update-item \
      --table-name airunner_prod_principals \
      --key '{"principal_id": {"S": "'"$principal_id"'"}}' \
      --update-expression "SET #status = :suspended, suspended_reason = :reason" \
      --expression-attribute-names '{"#status": "status"}' \
      --expression-attribute-values '{
        ":suspended": {"S": "suspended"},
        ":reason": {"S": "Emergency: CA compromise"}
      }'
  done

# 2. Generate new CA
airunner-cli bootstrap \
  --environment=prod \
  --domain=airunner.example.com \
  --force-new-ca

# 3. Distribute new CA certificate to all clients
# 4. Re-issue certificates for all principals
# 5. Gradually re-activate principals with new certificates
```

### Emergency: Complete Service Outage

**Scenario:** mTLS causing complete authentication failures

**Temporary Mitigation:**

```bash
# Enable no-auth mode temporarily (development only, NOT for production)
# Only if absolutely necessary and approved by security team

# Update ECS task definition to add --no-auth flag
# This should ONLY be used for emergency access to restore service
```

**Permanent Fix:** Follow rollback procedures in deployment runbook.

---

## Metrics and Monitoring

### Prometheus Metrics

The server exposes metrics on port 8080 (health check endpoint):

```bash
curl http://airunner.example.com:8080/metrics
```

**Key Metrics:**

```prometheus
# Authentication attempts
mtls_auth_total{result="success",principal_type="worker"} 1234
mtls_auth_total{result="failure",principal_type="worker"} 5
mtls_auth_total{result="revoked",principal_type="worker"} 2

# Cache performance
mtls_cache_hits{type="principal"} 5678
mtls_cache_hits{type="certificate"} 3456

# Certificate expiry (days until expiration)
cert_expiry_days{principal_id="worker-prod-01",serial="01936d3fa2b17c4e8f5d"} 45
cert_expiry_days{principal_id="admin-bootstrap",serial="01936d3fa2b17c4e8f5e"} 12
```

### Recommended Alerts

```yaml
# Alert: Certificate expiring soon
- alert: CertificateExpiringSoon
  expr: cert_expiry_days < 7
  for: 1h
  annotations:
    summary: "Certificate {{ $labels.principal_id }}/{{ $labels.serial }} expires in {{ $value }} days"

# Alert: High authentication failure rate
- alert: HighAuthFailureRate
  expr: rate(mtls_auth_total{result="failure"}[5m]) > 0.1
  for: 5m
  annotations:
    summary: "High mTLS authentication failure rate: {{ $value }}"

# Alert: Revoked certificate usage detected
- alert: RevokedCertificateUsage
  expr: increase(mtls_auth_total{result="revoked"}[5m]) > 0
  for: 1m
  annotations:
    summary: "Revoked certificate usage detected"
    description: "Someone is attempting to use a revoked certificate"
```

### CloudWatch Logs Insights

**Query: Recent authentication failures**

```
fields @timestamp, principal_id, serial, @message
| filter @message like /authentication error/
| sort @timestamp desc
| limit 100
```

**Query: Certificate revocations**

```
fields @timestamp, principal_id, serial, revocation_reason
| filter @message like /revoked certificate/
| sort @timestamp desc
| limit 50
```

---

## Additional Resources

- **Architecture Documentation:** `00-architecture.md`
- **Implementation Guide:** `README.md`
- **Deployment Procedures:** `04-phase4-deployment.md`
- **Cleanup Procedures:** `05-phase5-cleanup.md`

**For questions or issues:** Contact the platform engineering team or file an issue in the project repository.
