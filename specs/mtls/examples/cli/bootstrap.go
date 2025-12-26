// Package cli provides the bootstrap command for mTLS setup
//
// This is an example/reference implementation of the bootstrap command.
// The complete implementation is 505 lines and can be found in the original spec:
// specs/api_auth_v2_pki_implementation_alternative_with_mtls.md lines 2279-2783
//
// Bootstrap command supports two modes based on --environment flag:
//
// Local Mode (--environment=local):
//    1. Generate CA key pair to ./certs/ca-key.pem
//    2. Create FileSigner
//    3. Sign server certificate
//    4. Sign admin certificate
//    5. Save all to local files
//
// AWS Mode (--environment=dev|staging|prod):
//    1. Read KMS key ID from SSM: /airunner/{env}/ca-kms-key-id
//    2. Create KMSSigner with KMS key
//    3. Sign CA certificate (self-signed via KMS)
//    4. Sign server certificate via KMS
//    5. Sign admin certificate via KMS
//    6. Upload certificates to SSM (public certs only, no private keys!)
//    7. Store principal and certificate records in DynamoDB
//
// Key difference: AWS mode NEVER creates or stores CA private key locally.
// All signing operations performed via KMS API.
//
// Key functions:
//
// func (cmd *BootstrapCommand) Run(ctx context.Context) error
//     - Main entry point, routes to local or AWS mode
//
// func (cmd *BootstrapCommand) runLocalBootstrap(ctx context.Context) error
//     - Local mode: file-based CA key, FileSigner
//
// func (cmd *BootstrapCommand) runAWSBootstrap(ctx context.Context) error
//     - AWS mode: KMS signing, no local CA key
//
// func (cmd *BootstrapCommand) createSigner(ctx context.Context) (pki.CASigner, error)
//     - Creates FileSigner (local) or KMSSigner (AWS)
//
// func (cmd *BootstrapCmd) ensureServerCert(signer pki.CASigner) error
//     - Creates server certificate using provided signer
//
// func (cmd *BootstrapCmd) ensureAdminPrincipal(ctx context.Context) error
//     - Ensures admin principal exists in DynamoDB
//
// func (cmd *BootstrapCmd) ensureAdminCert(ctx context.Context, signer pki.CASigner) error
//     - Creates admin certificate with OID extensions using provided signer
//
// func (cmd *BootstrapCmd) uploadToAWS(ctx context.Context) error
//     - Uploads certificates to SSM (certs only, not CA key)
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
