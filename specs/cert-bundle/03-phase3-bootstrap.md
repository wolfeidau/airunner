# Phase 3: Bootstrap Support

[← README](README.md) | [← Phase 2](02-phase2-integration.md) | [Architecture](00-architecture.md)

## Goal

Update the bootstrap command to automatically generate certificate bundles during the certificate creation process, making it easy for users to adopt the new bundle approach.

**Duration:** ~20 minutes

## Prerequisites

- ✅ Phase 1 completed (`internal/tlscerts` package created and tested)
- ✅ Phase 2 completed (CLI integration with `--cert-bundle` flag)
- ✅ All previous tests passing

## Success Criteria

- [ ] Bootstrap creates `admin-bundle.pem` file
- [ ] Bundle contains client cert + CA cert in correct order
- [ ] Summary messages mention bundle usage
- [ ] Bundle works with CLI commands
- [ ] Bootstrap still creates individual files for backward compatibility
- [ ] End-to-end workflow verified (bootstrap → use bundle)

## Step 1: Add createCertificateBundle Method

### 1.1 Add Bundle Creation Method

**File:** `cmd/cli/internal/commands/bootstrap.go`

Add this method after the `ensureAdminCert()` method (around line 150):

```go
// createCertificateBundle creates a bundle containing client cert + CA cert
func (cmd *BootstrapCmd) createCertificateBundle(paths certificatePaths) error {
	log.Info().Msg("Creating certificate bundle for admin...")

	// Read admin certificate
	adminCertPEM, err := os.ReadFile(paths.adminCert)
	if err != nil {
		return fmt.Errorf("failed to read admin cert: %w", err)
	}

	// Read CA certificate
	caCertPEM, err := os.ReadFile(paths.caCert)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	// Combine: client cert first, then CA cert (following cfssl pattern)
	bundlePath := filepath.Join(cmd.OutputDir, "admin-bundle.pem")
	bundleData := append(adminCertPEM, caCertPEM...)

	if err := os.WriteFile(bundlePath, bundleData, 0o644); err != nil {
		return fmt.Errorf("failed to write cert bundle: %w", err)
	}

	log.Info().Str("path", bundlePath).Msg("Created certificate bundle")
	return nil
}
```

**Notes:**
- Client cert is written first (following standard and cfssl pattern)
- CA cert is appended second
- Bundle has 0644 permissions (public data, not sensitive)
- Uses the existing `certificatePaths` struct for file paths

### 1.2 Call Bundle Creation in Run Method

**File:** `cmd/cli/internal/commands/bootstrap.go`

Find the section where admin certificate is created (around line 107) and add the bundle creation call:

**Before:**
```go
if err = cmd.ensureAdminCert(ctx, paths, signer, certStore); err != nil {
	return fmt.Errorf("failed to ensure admin certificate: %w", err)
}

if err = cmd.uploadCertificatesToSSM(ctx, paths); err != nil {
```

**After:**
```go
if err = cmd.ensureAdminCert(ctx, paths, signer, certStore); err != nil {
	return fmt.Errorf("failed to ensure admin certificate: %w", err)
}

// Create certificate bundle (admin cert + CA cert)
if err = cmd.createCertificateBundle(paths); err != nil {
	return fmt.Errorf("failed to create certificate bundle: %w", err)
}

if err = cmd.uploadCertificatesToSSM(ctx, paths); err != nil {
```

## Step 2: Update Summary Messages

### 2.1 Update AWS Bootstrap Summary

**File:** `cmd/cli/internal/commands/bootstrap.go`

Find the `printAWSBootstrapSummary()` method (around line 180) and update it:

**Before:**
```go
func (cmd *BootstrapCmd) printAWSBootstrapSummary(paths certificatePaths) {
	log.Info().Msg("✓ Bootstrap completed successfully!")
	log.Info().Msg("")
	log.Info().Msg("Certificate files generated:")
	log.Info().Str("ca-cert", paths.caCert).Msg("  CA certificate")
	log.Info().Str("admin-cert", paths.adminCert).Msg("  Admin certificate")
	log.Info().Str("admin-key", paths.adminKey).Msg("  Admin private key")
	log.Info().Msg("")
	log.Info().Msg("Certificates uploaded to SSM Parameter Store:")
	log.Info().Str("ca-cert", fmt.Sprintf("/airunner/%s/ca-cert", cmd.Environment)).Msg("  CA certificate")
	log.Info().Str("server-cert", fmt.Sprintf("/airunner/%s/server-cert", cmd.Environment)).Msg("  Server certificate")
	log.Info().Str("server-key", fmt.Sprintf("/airunner/%s/server-key", cmd.Environment)).Msg("  Server private key")
	log.Info().Msg("")
	log.Info().Msg("Next steps:")
	log.Info().Msg("  1. Deploy the infrastructure with Terraform")
	log.Info().Msg("  2. Use admin credentials to authenticate with the server")
	log.Info().Msgf("  3. Store %s securely (contains private key)", paths.adminKey)
}
```

**After:**
```go
func (cmd *BootstrapCmd) printAWSBootstrapSummary(paths certificatePaths) {
	bundlePath := filepath.Join(cmd.OutputDir, "admin-bundle.pem")

	log.Info().Msg("✓ Bootstrap completed successfully!")
	log.Info().Msg("")
	log.Info().Msg("Certificate files generated:")
	log.Info().Str("ca-cert", paths.caCert).Msg("  CA certificate")
	log.Info().Str("admin-cert", paths.adminCert).Msg("  Admin certificate")
	log.Info().Str("admin-key", paths.adminKey).Msg("  Admin private key")
	log.Info().Str("admin-bundle", bundlePath).Msg("  Admin cert bundle (cert + CA)")
	log.Info().Msg("")
	log.Info().Msg("Certificates uploaded to SSM Parameter Store:")
	log.Info().Str("ca-cert", fmt.Sprintf("/airunner/%s/ca-cert", cmd.Environment)).Msg("  CA certificate")
	log.Info().Str("server-cert", fmt.Sprintf("/airunner/%s/server-cert", cmd.Environment)).Msg("  Server certificate")
	log.Info().Str("server-key", fmt.Sprintf("/airunner/%s/server-key", cmd.Environment)).Msg("  Server private key")
	log.Info().Msg("")
	log.Info().Msg("Using certificate bundle (recommended):")
	log.Info().Msg("  1. Store admin-bundle.pem on disk (not sensitive)")
	log.Info().Msg("  2. Store admin-key.pem in 1Password (sensitive)")
	log.Info().Msgf("  3. Use: --cert-bundle=%s --client-key=<from-1password>", bundlePath)
	log.Info().Msg("")
	log.Info().Msg("OR using individual files (backward compatible):")
	log.Info().Msgf("  --ca-cert=%s --client-cert=%s --client-key=%s", paths.caCert, paths.adminCert, paths.adminKey)
	log.Info().Msg("")
	log.Info().Msg("Next steps:")
	log.Info().Msg("  1. Deploy the infrastructure with Terraform")
	log.Info().Msg("  2. Use admin credentials to authenticate with the server")
}
```

**Key changes:**
- Added `admin-bundle` to certificate files list
- Added "Using certificate bundle (recommended)" section
- Provided example command with bundle flags
- Kept backward compatible approach visible
- Removed "Store admin-key securely" (implied by 1Password instruction)

### 2.2 Update Local Bootstrap Summary

**File:** `cmd/cli/internal/commands/bootstrap.go`

Find the `printLocalBootstrapSummary()` method (around line 200) and update it:

**Before:**
```go
func (cmd *BootstrapCmd) printLocalBootstrapSummary(paths certificatePaths) {
	log.Info().Msg("✓ Bootstrap completed successfully!")
	log.Info().Msg("")
	log.Info().Msg("Certificate files generated:")
	log.Info().Str("ca-cert", paths.caCert).Msg("  CA certificate")
	log.Info().Str("server-cert", paths.serverCert).Msg("  Server certificate")
	log.Info().Str("server-key", paths.serverKey).Msg("  Server private key")
	log.Info().Str("admin-cert", paths.adminCert).Msg("  Admin certificate")
	log.Info().Str("admin-key", paths.adminKey).Msg("  Admin private key")
	log.Info().Msg("")
	log.Info().Msg("Next steps:")
	log.Info().Msg("  1. Start the server with these certificates")
	log.Info().Msg("  2. Use admin credentials to authenticate with the server")
	log.Info().Msgf("  3. Store %s securely (contains private key)", paths.adminKey)
}
```

**After:**
```go
func (cmd *BootstrapCmd) printLocalBootstrapSummary(paths certificatePaths) {
	bundlePath := filepath.Join(cmd.OutputDir, "admin-bundle.pem")

	log.Info().Msg("✓ Bootstrap completed successfully!")
	log.Info().Msg("")
	log.Info().Msg("Certificate files generated:")
	log.Info().Str("ca-cert", paths.caCert).Msg("  CA certificate")
	log.Info().Str("server-cert", paths.serverCert).Msg("  Server certificate")
	log.Info().Str("server-key", paths.serverKey).Msg("  Server private key")
	log.Info().Str("admin-cert", paths.adminCert).Msg("  Admin certificate")
	log.Info().Str("admin-key", paths.adminKey).Msg("  Admin private key")
	log.Info().Str("admin-bundle", bundlePath).Msg("  Admin cert bundle (cert + CA)")
	log.Info().Msg("")
	log.Info().Msg("Using certificate bundle (recommended):")
	log.Info().Msgf("  ./bin/airunner-cli list --cert-bundle=%s --client-key=%s", bundlePath, paths.adminKey)
	log.Info().Msg("")
	log.Info().Msg("OR using individual files (backward compatible):")
	log.Info().Msgf("  ./bin/airunner-cli list --ca-cert=%s --client-cert=%s --client-key=%s", paths.caCert, paths.adminCert, paths.adminKey)
	log.Info().Msg("")
	log.Info().Msg("Next steps:")
	log.Info().Msg("  1. Start the server with these certificates")
	log.Info().Msg("  2. Use admin credentials to authenticate with the server")
}
```

**Key changes:**
- Added `admin-bundle` to certificate files list
- Provided concrete example commands for both bundle and individual file approaches
- Removed redundant "store securely" message (already shown in AWS summary)

## Step 3: Build and Test

### 3.1 Build the CLI

```bash
make build-cli
```

**Expected output:**
```
go build -o ./bin/airunner-cli ./cmd/cli
```

### 3.2 Clean Previous Bootstrap Output

```bash
rm -rf ./certs
```

This ensures we're testing a fresh bootstrap run.

### 3.3 Run Bootstrap (Local)

```bash
./bin/airunner-cli bootstrap --environment local
```

**Expected output should include:**
```
INFO Creating certificate bundle for admin...
INFO Created certificate bundle path=./certs/admin-bundle.pem
✓ Bootstrap completed successfully!

Certificate files generated:
  CA certificate                    ca-cert=./certs/ca-cert.pem
  Server certificate                server-cert=./certs/server-cert.pem
  Server private key                server-key=./certs/server-key.pem
  Admin certificate                 admin-cert=./certs/admin-cert.pem
  Admin private key                 admin-key=./certs/admin-key.pem
  Admin cert bundle (cert + CA)     admin-bundle=./certs/admin-bundle.pem

Using certificate bundle (recommended):
  ./bin/airunner-cli list --cert-bundle=./certs/admin-bundle.pem --client-key=./certs/admin-key.pem

OR using individual files (backward compatible):
  ./bin/airunner-cli list --ca-cert=./certs/ca-cert.pem --client-cert=./certs/admin-cert.pem --client-key=./certs/admin-key.pem
```

### 3.4 Verify Bundle File

```bash
ls -lh ./certs/admin-bundle.pem
```

**Expected:** File should exist and be readable.

```bash
openssl storeutl -noout -text -certs ./certs/admin-bundle.pem | grep "Certificate:"
```

**Expected output:**
```
Certificate:
Certificate:
```

Should show exactly 2 certificates.

### 3.5 Verify Bundle Contents

Verify the first certificate is the admin cert:

```bash
# Extract first certificate from bundle
openssl storeutl -noout -text -certs ./certs/admin-bundle.pem | head -30 | grep "Subject:"
```

**Expected:** Should show the admin principal subject (with role=admin).

Verify the second certificate is the CA cert:

```bash
# Extract second certificate from bundle
openssl storeutl -noout -text -certs ./certs/admin-bundle.pem | tail -30 | grep "Subject:"
```

**Expected:** Should show the CA subject.

## Step 4: End-to-End Testing

### 4.1 Start the Server (if not running)

```bash
./bin/airunner-server \
  --ca-cert=./certs/ca-cert.pem \
  --server-cert=./certs/server-cert.pem \
  --server-key=./certs/server-key.pem \
  --store-type=memory \
  --grpc-bind=:8080
```

**Wait for:** `Server listening on :8080`

### 4.2 Test CLI with Bundle

In a new terminal:

```bash
./bin/airunner-cli list \
  --server="https://localhost:8080" \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem
```

**Expected output:**
```
No jobs found
```

Or if jobs exist, a table showing jobs. The important thing is no certificate errors.

### 4.3 Test Submit with Bundle

```bash
./bin/airunner-cli submit \
  --server="https://localhost:8080" \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem \
  --repository="github.com/example/test"
```

**Expected:** Job submitted successfully with a job ID returned.

### 4.4 Test Worker with Bundle

```bash
./bin/airunner-cli worker \
  --server="https://localhost:8080" \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem \
  --timeout=10
```

**Expected:** Worker starts and processes jobs (or waits if no jobs available).

Press Ctrl+C to stop after verifying it connects successfully.

### 4.5 Test Backward Compatibility

Verify the old three-file approach still works:

```bash
./bin/airunner-cli list \
  --server="https://localhost:8080" \
  --ca-cert=./certs/ca-cert.pem \
  --client-cert=./certs/admin-cert.pem \
  --client-key=./certs/admin-key.pem
```

**Expected:** Should work identically to the bundle approach.

## Step 5: AWS Bootstrap Testing (Optional)

If you have AWS credentials configured:

### 5.1 Run AWS Bootstrap

```bash
AWS_ENDPOINT=http://localhost:4566 ./bin/airunner-cli bootstrap --environment local
```

**Note:** This uses LocalStack if available, or real AWS if configured.

### 5.2 Verify AWS Summary

**Expected output should include:**
```
Using certificate bundle (recommended):
  1. Store admin-bundle.pem on disk (not sensitive)
  2. Store admin-key.pem in 1Password (sensitive)
  3. Use: --cert-bundle=./certs/admin-bundle.pem --client-key=<from-1password>

OR using individual files (backward compatible):
  --ca-cert=./certs/ca-cert.pem --client-cert=./certs/admin-cert.pem --client-key=./certs/admin-key.pem
```

## Verification Checklist

- [ ] Bootstrap creates `admin-bundle.pem` file
- [ ] Bundle contains exactly 2 certificates (verified with openssl)
- [ ] First certificate in bundle is admin cert
- [ ] Second certificate in bundle is CA cert
- [ ] Summary messages mention bundle usage with examples
- [ ] CLI commands work with bundle (list, submit, worker)
- [ ] Backward compatibility maintained (three-file approach still works)
- [ ] Bundle file has correct permissions (0644)

## Troubleshooting

### Bundle File Not Created

**Error:** `admin-bundle.pem` doesn't exist after bootstrap.

**Solution:**
- Check logs for errors during bundle creation
- Verify `createCertificateBundle()` is called in `Run()` method
- Verify admin cert and CA cert files exist before bundle creation
- Check file permissions on output directory

### Bundle Has Wrong Number of Certificates

**Error:** `openssl storeutl` shows more or fewer than 2 certificates.

**Solution:**
- Verify the bundle creation logic appends exactly 2 files: admin cert + CA cert
- Check that no other PEM data is accidentally included
- Verify file contents with:
  ```bash
  head -5 ./certs/admin-bundle.pem  # Should show BEGIN CERTIFICATE
  tail -5 ./certs/admin-bundle.pem  # Should show END CERTIFICATE
  ```

### CLI Fails with Bundle

**Error:** `failed to parse cert bundle: cert bundle must contain at least 2 certificates`

**Solution:**
- Verify bundle was created correctly (2 certificates)
- Check that `internal/tlscerts` package is working (run unit tests)
- Verify Phase 1 implementation is correct

### Bundle Has Certificates in Wrong Order

**Error:** TLS handshake fails, or client cert not recognized.

**Solution:**
- Verify bundle creation appends admin cert FIRST, then CA cert
- Check with:
  ```bash
  openssl storeutl -noout -text -certs ./certs/admin-bundle.pem | grep -A 5 "Certificate:"
  ```
- First certificate should have Subject with role=admin
- Second certificate should be the CA

## Summary of Changes

### Files Modified:

1. **`cmd/cli/internal/commands/bootstrap.go`**
   - Added `createCertificateBundle()` method (~25 lines)
   - Called bundle creation after admin cert creation (1 line)
   - Updated `printAWSBootstrapSummary()` (~10 lines added)
   - Updated `printLocalBootstrapSummary()` (~10 lines added)

**Total changes:** ~46 lines added/modified in 1 file

### Files Created:
- `./certs/admin-bundle.pem` (created during bootstrap, not committed to git)

## What Users See

After bootstrap completion, users now see clear guidance on two approaches:

**Bundle approach (recommended):**
```bash
./bin/airunner-cli list \
  --cert-bundle=./certs/admin-bundle.pem \
  --client-key=./certs/admin-key.pem
```

**Individual files (backward compatible):**
```bash
./bin/airunner-cli list \
  --ca-cert=./certs/ca-cert.pem \
  --client-cert=./certs/admin-cert.pem \
  --client-key=./certs/admin-key.pem
```

Users can choose their preferred approach. The bundle approach reduces files from 3 to 2, making it easier to store the single sensitive file (admin-key.pem) in 1Password.

## Next Steps

After completing Phase 3, the certificate bundle feature is fully implemented!

### Recommended Follow-Up:

1. ✅ Test end-to-end workflow in production environment
2. ✅ Update any deployment documentation to recommend bundle approach
3. ✅ Consider adding bundle creation to documentation (how to manually create bundles)
4. → Update README or user documentation with bundle usage examples

### Optional Enhancements (Future):

- Add `./bin/airunner-cli bundle-certs` command to create bundles from existing certs
- Add bundle validation command to verify bundle format
- Support multiple CA certs in bundle (full chain)
- Add bundle to SSM Parameter Store (for production use)

---

[← README](README.md) | [← Phase 2](02-phase2-integration.md) | [Architecture](00-architecture.md)
