// Package cli provides the bootstrap command for mTLS setup
//
// This is an example/reference implementation of the bootstrap command.
// The complete implementation is 505 lines and can be found in the original spec:
// specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 2279-2783
//
// Bootstrap command structure and flow:
//
// 1. Check/Create CA
//    - Check if ca-cert.pem exists locally
//    - Check if ca-key exists in Secrets Manager
//    - Generate new CA if needed (ECDSA P-256, 10-year validity)
//    - Download from AWS if exists
//
// 2. Check/Create Server Certificate
//    - Check if server-cert.pem exists locally
//    - Check if SSM has server-cert (not placeholder)
//    - Generate server key pair and sign with CA
//    - Add SAN: domain, localhost, 127.0.0.1
//    - 90-day validity
//
// 3. Check/Create Admin Principal
//    - Check if principal exists in DynamoDB
//    - Create principal record if not (status=active, type=admin)
//
// 4. Check/Create Admin Certificate
//    - Check if admin-cert.pem exists locally
//    - Generate admin key pair with custom OID extensions
//    - Register in DynamoDB certificates table
//
// 5. Upload to AWS (idempotent)
//    - Put ca-cert.pem to SSM
//    - Put server-cert.pem to SSM
//    - Put server-key.pem to SSM SecureString
//    - Put ca-key.pem to Secrets Manager
//
// 6. Verify and Report
//    - Verify all resources exist
//    - Print summary with next steps
//
// Key functions:
//
// func (cmd *BootstrapCmd) ensureCA() error
//     - Ensures CA certificate and key exist (locally or in AWS)
//
// func (cmd *BootstrapCmd) ensureServerCert() error
//     - Ensures server certificate exists and is valid
//
// func (cmd *BootstrapCmd) ensureAdminPrincipal(ctx context.Context) error
//     - Ensures admin principal exists in DynamoDB
//
// func (cmd *BootstrapCmd) ensureAdminCert(ctx context.Context) error
//     - Ensures admin client certificate exists with OID extensions
//
// func (cmd *BootstrapCmd) uploadToAWS(ctx context.Context) error
//     - Uploads all certificates and keys to AWS (SSM/Secrets Manager)
//
// func (cmd *BootstrapCmd) verify(ctx context.Context) error
//     - Verifies all resources are accessible
//
// func (cmd *BootstrapCmd) printSummary()
//     - Prints completion summary and next steps
//
// See the original spec for the complete implementation with all helper functions,
// error handling, progress output, and AWS integration.

package cli

// Placeholder file - see spec lines 2279-2783 for complete 505-line implementation
