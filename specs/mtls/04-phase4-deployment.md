# Phase 4: Deployment

[← Back to README](README.md) | [← Phase 3: Infrastructure](03-phase3-infrastructure.md) | [Phase 5: Cleanup →](05-phase5-cleanup.md) | [Operations Runbook](operations-runbook.md)

## Overview

**Goal:** Deploy mTLS authentication to production environment.

**Duration:** 1-2 hours

**Prerequisites:**
- Phase 3 Terraform reviewed and ready to apply
- AWS credentials configured
- Access to production environment

**Success Criteria:**
- [ ] Bootstrap command completes successfully
- [ ] All certificates uploaded to AWS
- [ ] Terraform apply successful
- [ ] ECS service updated and healthy
- [ ] Health check endpoint accessible
- [ ] mTLS API accessible with client cert
- [ ] Authorization working correctly

## Step 1: Run Bootstrap Command

Run the bootstrap command to create CA, server certificates, and admin credentials for production:

```bash
./bin/airunner-cli bootstrap \
  --environment=prod \
  --domain=airunner.example.com \
  --aws-region=ap-southeast-2 \
  --output-dir=./prod-certs
```

**Expected Output:**

```
Bootstrap: airunner.example.com
═══════════════════════════════

[1/6] Certificate Authority
      ✓ CA exists: ./prod-certs/ca-cert.pem
      ✓ CA key exists: ./prod-certs/ca-key.pem
      ✓ CA valid until: 2034-12-25

[2/6] Server Certificate
      ✓ Generated new server certificate
      ✓ Subject: CN=airunner.example.com
      ✓ SAN: airunner.example.com, localhost, 127.0.0.1
      ✓ Valid until: 2025-03-25

[3/6] Admin Principal
      ✓ Principal exists: admin-bootstrap (active)

[4/6] Admin Certificate
      ✓ Generated new admin certificate
      ✓ Subject: CN=admin-bootstrap
      ✓ OID extensions: type=admin, id=admin-bootstrap
      ✓ Registered in certificates table
      ✓ Valid until: 2025-03-25

[5/6] AWS Upload
      ✓ SSM: /airunner/prod/ca-cert (updated)
      ✓ SSM: /airunner/prod/server-cert (updated)
      ✓ SSM: /airunner/prod/server-key (updated)
      ✓ Secrets Manager: /airunner/prod/ca-key (updated)

[6/6] Verification
      ✓ All DynamoDB tables accessible
      ✓ All SSM parameters set
      ✓ CA key in Secrets Manager

Bootstrap complete!
══════════════════

Files created in ./prod-certs/:
  ca-cert.pem          - CA certificate (distribute to all clients)
  ca-key.pem           - CA private key (DELETE after backup!)
  server-cert.pem      - Server certificate
  server-key.pem       - Server private key
  admin-cert.pem       - Admin certificate
  admin-key.pem        - Admin private key

IMPORTANT: Back up ca-key.pem securely, then delete local copy!
           The CA key is now stored in AWS Secrets Manager.
```

**Post-Bootstrap Actions:**

```bash
# 1. Back up CA key securely (e.g., encrypted archive)
tar -czf ca-key-backup-$(date +%Y%m%d).tar.gz prod-certs/ca-key.pem
# Upload to secure location (S3 with encryption, vault, etc.)

# 2. Delete local CA key
rm prod-certs/ca-key.pem

# 3. Distribute CA certificate to clients
# This file is needed by all clients to verify the server certificate
cp prod-certs/ca-cert.pem ~/.airunner/ca-cert.pem
```

## Step 2: Apply Terraform Changes

Apply the infrastructure changes:

```bash
cd infra/

# Final review of changes
terraform plan

# Apply changes
terraform apply

# Expected output:
# aws_dynamodb_table.principals: Creating...
# aws_dynamodb_table.certificates: Creating...
# aws_ssm_parameter.ca_cert: Creating...
# aws_ssm_parameter.server_cert: Creating...
# aws_ssm_parameter.server_key: Creating...
# aws_secretsmanager_secret.ca_key: Creating...
# aws_lb.main: Creating...
# ... (more resources)
# Apply complete! Resources: 15 added, 2 changed, 0 destroyed.
```

## Step 3: Deploy ECS Service

Update the ECS service to pick up the new task definition:

```bash
aws ecs update-service \
  --cluster airunner-prod \
  --service airunner-prod \
  --force-new-deployment \
  --region ap-southeast-2
```

**Monitor deployment:**

```bash
# Watch task status
aws ecs describe-services \
  --cluster airunner-prod \
  --services airunner-prod \
  --query 'services[0].deployments' \
  --region ap-southeast-2

# Watch task logs
aws logs tail /ecs/airunner-prod --follow --region ap-southeast-2
```

**Expected log output:**

```
INFO  mTLS authentication enabled
INFO  Starting health check server addr=0.0.0.0:8080
INFO  Starting mTLS API server addr=0.0.0.0:443
INFO  TLS configuration: MinVersion=TLS1.2 ClientAuth=RequireAndVerifyClientCert
INFO  Loaded CA certificate for client verification
INFO  Loaded server certificate: CN=airunner.example.com
```

## Step 4: Verification

### 4.1 Health Check

```bash
# Test health check endpoint
curl http://airunner.example.com:8080/health

# Expected output:
# ok
```

### 4.2 mTLS Connection Test

```bash
# Test mTLS API with admin certificate
curl --cacert prod-certs/ca-cert.pem \
     --cert prod-certs/admin-cert.pem \
     --key prod-certs/admin-key.pem \
     https://airunner.example.com/job.v1.PrincipalService/ListPrincipals

# Expected: 200 OK with principal list
```

### 4.3 Authorization Test

Test that authorization is enforced:

```bash
# Admin can manage principals ✓
curl --cacert prod-certs/ca-cert.pem \
     --cert prod-certs/admin-cert.pem \
     --key prod-certs/admin-key.pem \
     https://airunner.example.com/job.v1.PrincipalService/CreatePrincipal \
     -d '{"principal_id":"worker-01","type":"PRINCIPAL_TYPE_WORKER"}'

# Expected: 200 OK

# Worker cannot manage principals ✗ (after creating worker cert)
curl --cacert prod-certs/ca-cert.pem \
     --cert worker-cert.pem \
     --key worker-key.pem \
     https://airunner.example.com/job.v1.PrincipalService/CreatePrincipal \
     -d '{"principal_id":"worker-02","type":"PRINCIPAL_TYPE_WORKER"}'

# Expected: 403 Forbidden (PermissionDenied)
```

### 4.4 Certificate Verification

Verify certificate OID extensions:

```bash
# Check admin certificate
openssl x509 -in prod-certs/admin-cert.pem -text -noout | grep -A2 "1.3.6.1.4.1.99999"

# Expected output:
# 1.3.6.1.4.1.99999.1.1:
#     admin
# 1.3.6.1.4.1.99999.1.2:
#     admin-bootstrap
```

## Step 5: Create First Worker Principal

Now that the system is running, create your first worker principal:

```bash
# 1. Create worker principal
./bin/airunner-cli principal create worker-prod-01 \
  --type=worker \
  --server=https://airunner.example.com \
  --cacert=prod-certs/ca-cert.pem \
  --client-cert=prod-certs/admin-cert.pem \
  --client-key=prod-certs/admin-key.pem

# 2. Generate worker certificate (using admin credentials to sign)
./bin/airunner-cli certificate generate worker-prod-01 \
  --type=worker \
  --server=https://airunner.example.com \
  --cacert=prod-certs/ca-cert.pem \
  --client-cert=prod-certs/admin-cert.pem \
  --client-key=prod-certs/admin-key.pem \
  --output-dir=./worker-certs

# 3. Test worker authentication
curl --cacert prod-certs/ca-cert.pem \
     --cert worker-certs/worker-prod-01-cert.pem \
     --key worker-certs/worker-prod-01-key.pem \
     https://airunner.example.com/job.v1.JobService/DequeueJob

# Expected: 200 OK (worker can dequeue jobs)
```

## Troubleshooting

### Issue: Certificate verification failed

**Symptoms:**
```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

**Solution:**
- Verify `ca-cert.pem` matches the CA that signed the server certificate
- Check server certificate is correctly loaded in ECS task

### Issue: Client certificate rejected

**Symptoms:**
```
curl: (56) OpenSSL SSL_read: error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate
```

**Solution:**
- Verify client certificate has correct OID extensions: `openssl x509 -in cert.pem -text -noout`
- Check principal exists in DynamoDB and status is "active"
- Check certificate is registered in certificates table

### Issue: Permission denied

**Symptoms:**
```
{
  "code": "permission_denied",
  "message": "permission denied: worker requires principals:manage"
}
```

**Solution:**
- This is expected - worker cannot manage principals
- Use admin certificate for principal management operations
- Check authorization matrix in architecture doc

### Issue: Health check failing

**Symptoms:**
- ECS tasks continuously restarting
- Target group shows unhealthy targets

**Solution:**
- Check security group allows port 8080 from NLB
- Verify health check endpoint responds: `curl http://localhost:8080/health` from within container
- Check ECS task logs for errors

## Rollback Plan

If deployment fails, rollback procedure:

```bash
# 1. Revert ECS service to previous task definition
aws ecs update-service \
  --cluster airunner-prod \
  --service airunner-prod \
  --task-definition airunner-prod:PREVIOUS_REVISION

# 2. Revert Terraform changes
cd infra/
terraform apply -target=... # Revert specific resources

# 3. Re-enable JWT authentication temporarily
# Update task definition to use --no-auth or restore JWT env vars
```

## Success Checklist

- [ ] Bootstrap command completed successfully
- [ ] CA and certificates created and uploaded to AWS
- [ ] Terraform apply successful (no errors)
- [ ] ECS service deployed and healthy
- [ ] Health check returns "ok"
- [ ] mTLS connection successful with admin cert
- [ ] Authorization enforced (admin can manage, worker cannot)
- [ ] First worker principal created and tested
- [ ] Monitoring shows no errors
- [ ] CA key backed up and local copy deleted

## Next Steps

Once Phase 4 is complete and production deployment is verified, proceed to **[Phase 5: Cleanup](05-phase5-cleanup.md)** to remove old JWT code.

---

[← Back to README](README.md) | [← Phase 3: Infrastructure](03-phase3-infrastructure.md) | [Phase 5: Cleanup →](05-phase5-cleanup.md) | [Operations Runbook](operations-runbook.md)
