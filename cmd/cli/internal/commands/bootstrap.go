package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/pki"
	"github.com/wolfeidau/airunner/internal/store"
	awsstore "github.com/wolfeidau/airunner/internal/store/aws"
)

// BootstrapCmd handles mTLS bootstrap for development and production
type BootstrapCmd struct {
	Environment string `help:"environment name (local, dev, prod)" default:"local" enum:"local,dev,prod"`
	Domain      string `help:"server domain name" default:"localhost"`
	AWSRegion   string `help:"AWS region" default:"us-east-1" env:"AWS_REGION"`
	OutputDir   string `help:"output directory for certificates" default:"./certs"`
	AWSEndpoint string `help:"AWS endpoint (for LocalStack)" env:"AWS_ENDPOINT" default:""`
	Force       bool   `help:"force regeneration of all certificates" default:"false"`
}

// certificatePaths holds paths to generated certificates
type certificatePaths struct {
	caCert     string
	caKey      string
	serverCert string
	serverKey  string
	adminCert  string
	adminKey   string
}

// CertValidation holds certificate validation results
type CertValidation struct {
	Path          string
	Exists        bool
	Expired       bool
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	ShouldRotate  bool
}

// Run executes the bootstrap command
func (cmd *BootstrapCmd) Run(ctx context.Context, globals *Globals) error {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.TimeOnly}).With().Timestamp().Logger()

	log.Info().
		Str("environment", cmd.Environment).
		Str("domain", cmd.Domain).
		Msg("Starting mTLS bootstrap")

	// Create output directory
	if err := os.MkdirAll(cmd.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	paths := cmd.certificatePaths()

	// Get environment-specific handler
	handler, err := cmd.getBootstrapHandler(ctx)
	if err != nil {
		return fmt.Errorf("failed to get bootstrap handler: %w", err)
	}

	// Setup environment-specific infrastructure and CA signer
	signer, err := handler.Setup(ctx, paths)
	if err != nil {
		return err
	}

	// Shared operations: ensure certificates and principals
	if err = cmd.ensureServerCert(paths, signer); err != nil {
		return fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	// Initialize stores for certificate registration
	principalStore, certStore, err := cmd.createStores(ctx)
	if err != nil {
		return fmt.Errorf("failed to create stores: %w", err)
	}

	if err = cmd.ensureAdminPrincipal(ctx, principalStore); err != nil {
		return fmt.Errorf("failed to ensure admin principal: %w", err)
	}

	if err = cmd.ensureAdminCert(ctx, paths, signer, certStore); err != nil {
		return fmt.Errorf("failed to ensure admin certificate: %w", err)
	}

	// Environment-specific finalization
	return handler.Finalize(ctx, paths)
}

// setupLocalSigner creates a FileSigner for local development
func (cmd *BootstrapCmd) setupLocalSigner(ctx context.Context, paths certificatePaths) (pki.CASigner, error) {
	log.Info().Msg("Setting up local file-based signer...")

	// Validate existing CA certificate (365-day rotation threshold)
	caValidation, err := validateCertificate(paths.caCert, 365*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to validate CA certificate: %w", err)
	}

	// Determine if we should regenerate and log appropriately
	switch {
	case cmd.Force:
		log.Info().Msg("Force flag set, regenerating CA certificate...")
	case caValidation.ShouldRotate && caValidation.Expired:
		log.Error().
			Int("days_expired", -caValidation.DaysRemaining).
			Msg("CA certificate is expired, regenerating...")
	case caValidation.ShouldRotate:
		log.Warn().
			Int("days_remaining", caValidation.DaysRemaining).
			Msg("CA certificate approaching expiry, regenerating...")
	case caValidation.Exists && fileExists(paths.caKey):
		log.Info().
			Int("days_remaining", caValidation.DaysRemaining).
			Msg("CA certificate is valid, using existing...")

		// Create signer from existing files
		return pki.NewFileSigner(paths.caKey, paths.caCert)
	default:
		log.Info().Msg("Generating new CA certificate...")
	}

	// Generate new CA key pair
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Airunner CA (%s)", cmd.Environment),
			Organization: []string{"Airunner"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save CA certificate
	if err := saveCertificate(paths.caCert, caCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Save CA key
	if err := savePrivateKey(paths.caKey, caKey); err != nil {
		return nil, fmt.Errorf("failed to save CA key: %w", err)
	}

	log.Info().
		Str("path_cert", paths.caCert).
		Str("path_key", paths.caKey).
		Msg("Generated and saved CA certificate")

	// Create signer from generated files
	return pki.NewFileSigner(paths.caKey, paths.caCert)
}

// setupKMSSigner creates a KMSSigner for AWS production
func (cmd *BootstrapCmd) setupKMSSigner(ctx context.Context, paths certificatePaths) (pki.CASigner, error) {
	log.Info().Msg("Setting up KMS-based signer...")

	// Load AWS config
	awsConfig, err := cmd.loadAWSConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Get KMS key ID from SSM parameter
	kmsKeyID, err := cmd.getKMSKeyID(ctx, awsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS key ID: %w", err)
	}

	log.Info().Str("kms_key_id", kmsKeyID).Msg("Using KMS key for CA signing")

	// Check if CA certificate already exists
	caValidation, err := validateCertificate(paths.caCert, 365*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to validate CA certificate: %w", err)
	}

	var caCertPEM []byte

	if caValidation.Exists && !cmd.Force && !caValidation.ShouldRotate {
		log.Info().
			Int("days_remaining", caValidation.DaysRemaining).
			Msg("CA certificate is valid, using existing...")

		// Load existing CA certificate
		caCertPEM, err = os.ReadFile(paths.caCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
	} else {
		// Generate new CA certificate using KMS
		log.Info().Msg("Generating new CA certificate with KMS...")

		caCertPEM, err = cmd.generateKMSCACertificate(ctx, awsConfig, kmsKeyID, paths.caCert)
		if err != nil {
			return nil, fmt.Errorf("failed to generate KMS CA certificate: %w", err)
		}
	}

	// Create KMS signer
	return pki.NewKMSSigner(ctx, awsConfig, kmsKeyID, caCertPEM)
}

// getKMSKeyID retrieves the KMS key ID from SSM Parameter Store
func (cmd *BootstrapCmd) getKMSKeyID(ctx context.Context, awsConfig aws.Config) (string, error) {
	ssmClient := ssm.NewFromConfig(awsConfig)
	paramName := fmt.Sprintf("/airunner/%s/ca-kms-key-id", cmd.Environment)

	output, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(paramName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get KMS key ID from SSM parameter %s: %w", paramName, err)
	}

	return *output.Parameter.Value, nil
}

// generateKMSCACertificate generates a self-signed CA certificate using KMS
func (cmd *BootstrapCmd) generateKMSCACertificate(ctx context.Context, awsConfig aws.Config, kmsKeyID, certPath string) ([]byte, error) {
	kmsClient := kms.NewFromConfig(awsConfig)

	// Get the public key from KMS
	pubKeyOutput, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(kmsKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not ECDSA")
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Airunner CA (%s)", cmd.Environment),
			Organization: []string{"Airunner"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		PublicKey:             ecdsaPubKey,
	}

	// Create a temporary KMS signer just for signing the CA cert
	// We need a placeholder CA cert to bootstrap the signer
	placeholderCACertDER, err := x509.CreateCertificate(rand.Reader, template, template, ecdsaPubKey, ecdsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create placeholder CA cert: %w", err)
	}

	placeholderCACertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: placeholderCACertDER,
	})

	// Now create the real signer and sign properly
	kmsSigner, err := pki.NewKMSSigner(ctx, awsConfig, kmsKeyID, placeholderCACertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS signer: %w", err)
	}

	// Sign the CA certificate (self-signed via KMS)
	caCertDER, err := kmsSigner.SignCertificate(template)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CA certificate with KMS: %w", err)
	}

	// Parse and save the certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if err := saveCertificate(certPath, caCert); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	log.Info().
		Str("path_cert", certPath).
		Msg("Generated and saved KMS-signed CA certificate")

	return caCertPEM, nil
}

// ensureServerCert ensures the server certificate exists
func (cmd *BootstrapCmd) ensureServerCert(paths certificatePaths, signer pki.CASigner) error {
	// Validate existing server certificate (7-day rotation window)
	serverValidation, err := validateCertificate(paths.serverCert, 7*24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to validate server certificate: %w", err)
	}

	// Determine if we should regenerate and log appropriately
	switch {
	case cmd.Force:
		log.Info().Msg("Force flag set, regenerating server certificate...")
	case serverValidation.ShouldRotate && serverValidation.Expired:
		log.Error().
			Int("days_expired", -serverValidation.DaysRemaining).
			Msg("Server certificate is expired, regenerating...")
	case serverValidation.ShouldRotate:
		log.Warn().
			Int("days_remaining", serverValidation.DaysRemaining).
			Msg("Server certificate within rotation window, regenerating...")
	case serverValidation.Exists && fileExists(paths.serverKey):
		log.Info().
			Int("days_remaining", serverValidation.DaysRemaining).
			Msg("Server certificate is valid, using existing...")
		return nil
	default:
		log.Info().Msg("Generating server certificate...")
	}

	// Generate server key pair
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cmd.Domain,
			Organization: []string{"Airunner"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour), // 90 days
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{cmd.Domain, "localhost"},
		IPAddresses: nil, // Add IP addresses if needed
		PublicKey:   &serverKey.PublicKey,
	}

	// Sign the server certificate with CA (via signer)
	serverCertDER, err := signer.SignCertificate(template)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}

	// Save server certificate
	if err := saveCertificate(paths.serverCert, serverCert); err != nil {
		return fmt.Errorf("failed to save server certificate: %w", err)
	}

	// Save server key
	if err := savePrivateKey(paths.serverKey, serverKey); err != nil {
		return fmt.Errorf("failed to save server key: %w", err)
	}

	log.Info().
		Str("path_cert", paths.serverCert).
		Str("path_key", paths.serverKey).
		Msg("Generated and saved server certificate")

	return nil
}

// ensureAdminPrincipal ensures the admin principal exists in the store
func (cmd *BootstrapCmd) ensureAdminPrincipal(ctx context.Context, principalStore store.PrincipalStore) error {
	principalID := "admin-bootstrap"

	// Check if principal already exists
	existing, err := principalStore.Get(ctx, principalID)
	if err == nil {
		log.Info().
			Str("principal_id", principalID).
			Str("type", string(existing.Type)).
			Msg("Admin principal already exists")
		return nil
	}

	if !errors.Is(err, store.ErrPrincipalNotFound) {
		return fmt.Errorf("failed to check principal: %w", err)
	}

	// Create admin principal
	principal := &store.PrincipalMetadata{
		PrincipalID:     principalID,
		Type:            store.PrincipalTypeAdmin,
		Status:          store.PrincipalStatusActive,
		CreatedAt:       time.Now(),
		CreatedBy:       "bootstrap",
		Email:           "",
		Description:     "Bootstrap admin principal",
		MaxCertificates: 10,
	}

	if err := principalStore.Create(ctx, principal); err != nil {
		return fmt.Errorf("failed to create admin principal: %w", err)
	}

	log.Info().
		Str("principal_id", principalID).
		Msg("Created admin principal")

	return nil
}

// ensureAdminCert ensures the admin client certificate exists
func (cmd *BootstrapCmd) ensureAdminCert(ctx context.Context, paths certificatePaths, signer pki.CASigner, certStore store.CertificateStore) error {
	// Validate existing admin certificate (7-day rotation window)
	adminValidation, err := validateCertificate(paths.adminCert, 7*24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to validate admin certificate: %w", err)
	}

	// Determine if we should regenerate and log appropriately
	switch {
	case cmd.Force:
		log.Info().Msg("Force flag set, regenerating admin certificate...")
	case adminValidation.ShouldRotate && adminValidation.Expired:
		log.Error().
			Int("days_expired", -adminValidation.DaysRemaining).
			Msg("Admin certificate is expired, regenerating...")
	case adminValidation.ShouldRotate:
		log.Warn().
			Int("days_remaining", adminValidation.DaysRemaining).
			Msg("Admin certificate within rotation window, regenerating...")
	case adminValidation.Exists && fileExists(paths.adminKey):
		log.Info().
			Int("days_remaining", adminValidation.DaysRemaining).
			Msg("Admin certificate is valid, checking registration...")

		// Load existing certificate to check registration
		cert, err := loadCertificate(paths.adminCert)
		if err != nil {
			return fmt.Errorf("failed to load existing admin certificate: %w", err)
		}

		serialNumber := cert.SerialNumber.Text(16)

		// Check if certificate is registered in the store
		_, err = certStore.Get(ctx, serialNumber)
		if err != nil {
			if errors.Is(err, store.ErrCertNotFound) {
				// Certificate exists but not registered - register it now
				log.Info().
					Str("serial_number", serialNumber).
					Msg("Existing certificate not registered, registering now...")

				certMeta := store.NewCertMetadataFromX509(cert)
				certMeta.Description = "Bootstrap admin certificate"

				if err := certStore.Register(ctx, certMeta); err != nil && !errors.Is(err, store.ErrCertAlreadyExists) {
					return fmt.Errorf("failed to register existing certificate: %w", err)
				}

				log.Info().
					Str("serial_number", serialNumber).
					Msg("Successfully registered existing certificate")
			} else {
				// Other error checking registration
				log.Error().Err(err).Msg("failed to check certificate registration")
				return fmt.Errorf("failed to check certificate registration: %w", err)
			}
		} else {
			log.Info().
				Str("serial_number", serialNumber).
				Msg("Certificate already registered")
		}

		return nil
	default:
		log.Info().Msg("Generating admin certificate with custom OID extensions...")
	}

	// Generate admin key pair
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate admin key: %w", err)
	}

	// Create admin certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Encode custom OID extensions
	principalTypeValue, err := asn1.Marshal("admin")
	if err != nil {
		return fmt.Errorf("failed to marshal principal type: %w", err)
	}

	principalIDValue, err := asn1.Marshal("admin-bootstrap")
	if err != nil {
		return fmt.Errorf("failed to marshal principal ID: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "admin-bootstrap",
			Organization: []string{"Airunner"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour), // 90 days
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		PublicKey:   &adminKey.PublicKey,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       pki.OIDPrincipalType,
				Critical: false,
				Value:    principalTypeValue,
			},
			{
				Id:       pki.OIDPrincipalID,
				Critical: false,
				Value:    principalIDValue,
			},
		},
	}

	// Sign the admin certificate with CA (via signer)
	adminCertDER, err := signer.SignCertificate(template)
	if err != nil {
		return fmt.Errorf("failed to create admin certificate: %w", err)
	}

	adminCert, err := x509.ParseCertificate(adminCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse admin certificate: %w", err)
	}

	// Save admin certificate
	if err := saveCertificate(paths.adminCert, adminCert); err != nil {
		return fmt.Errorf("failed to save admin certificate: %w", err)
	}

	// Save admin key
	if err := savePrivateKey(paths.adminKey, adminKey); err != nil {
		return fmt.Errorf("failed to save admin key: %w", err)
	}

	// Register certificate in store
	certMeta := store.NewCertMetadataFromX509(adminCert)
	certMeta.Description = "Bootstrap admin certificate"

	if err := certStore.Register(ctx, certMeta); err != nil && !errors.Is(err, store.ErrCertAlreadyExists) {
		return fmt.Errorf("failed to register certificate: %w", err)
	}

	log.Info().
		Str("path_cert", paths.adminCert).
		Str("path_key", paths.adminKey).
		Str("serial_number", certMeta.SerialNumber).
		Msg("Generated and registered admin certificate")

	return nil
}

// createStores creates principal and certificate stores
func (cmd *BootstrapCmd) createStores(ctx context.Context) (store.PrincipalStore, store.CertificateStore, error) {
	// Always use DynamoDB stores (LocalStack for local, AWS for dev/prod)
	// This ensures principals and certificates persist between bootstrap and server runs
	awsConfig, err := cmd.loadAWSConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	dynamoClient := dynamodb.NewFromConfig(awsConfig)

	principalsTable := fmt.Sprintf("airunner_%s_principals", cmd.Environment)
	certificatesTable := fmt.Sprintf("airunner_%s_certificates", cmd.Environment)

	principalStore := awsstore.NewPrincipalStore(dynamoClient, principalsTable)
	certStore := awsstore.NewCertificateStore(dynamoClient, certificatesTable)

	return principalStore, certStore, nil
}

// loadAWSConfig loads AWS configuration with optional endpoint override
func (cmd *BootstrapCmd) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(cmd.AWSRegion),
	}

	if cmd.AWSEndpoint != "" {
		// Use BaseEndpoint for LocalStack support
		opts = append(opts, config.WithBaseEndpoint(cmd.AWSEndpoint))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

// uploadToAWS uploads certificates to AWS SSM Parameter Store
// Note: CA private key is NOT uploaded - it exists only in KMS
func (cmd *BootstrapCmd) uploadToAWS(ctx context.Context, awsConfig aws.Config, paths certificatePaths) error {
	log.Info().Msg("Uploading certificates to AWS SSM Parameter Store...")

	ssmClient := ssm.NewFromConfig(awsConfig)
	prefix := fmt.Sprintf("/airunner/%s", cmd.Environment)

	// Upload CA cert to SSM (public certificate only)
	caCertPEM, err := os.ReadFile(paths.caCert)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	if err := cmd.putSSMParameter(ctx, ssmClient, fmt.Sprintf("%s/ca-cert", prefix), string(caCertPEM), ssmtypes.ParameterTypeString); err != nil {
		return fmt.Errorf("failed to upload CA cert: %w", err)
	}

	// Upload server cert to SSM (public certificate only)
	serverCertPEM, err := os.ReadFile(paths.serverCert)
	if err != nil {
		return fmt.Errorf("failed to read server cert: %w", err)
	}

	if err := cmd.putSSMParameter(ctx, ssmClient, fmt.Sprintf("%s/server-cert", prefix), string(serverCertPEM), ssmtypes.ParameterTypeString); err != nil {
		return fmt.Errorf("failed to upload server cert: %w", err)
	}

	// Upload server key to SSM (SecureString - needed for TLS termination)
	serverKeyPEM, err := os.ReadFile(paths.serverKey)
	if err != nil {
		return fmt.Errorf("failed to read server key: %w", err)
	}

	if err := cmd.putSSMParameter(ctx, ssmClient, fmt.Sprintf("%s/server-key", prefix), string(serverKeyPEM), ssmtypes.ParameterTypeSecureString); err != nil {
		return fmt.Errorf("failed to upload server key: %w", err)
	}

	log.Info().Msg("Successfully uploaded certificates to AWS SSM Parameter Store")
	log.Info().Msg("Note: CA private key remains in KMS and is never uploaded")

	return nil
}

// putSSMParameter puts a parameter in SSM Parameter Store
func (cmd *BootstrapCmd) putSSMParameter(ctx context.Context, client *ssm.Client, name, value string, paramType ssmtypes.ParameterType) error {
	_, err := client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(name),
		Value:     aws.String(value),
		Type:      paramType,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return err
	}

	log.Info().Str("parameter", name).Msg("Uploaded to SSM Parameter Store")
	return nil
}

// certificatePaths creates the certificate paths for the configured output directory
func (cmd *BootstrapCmd) certificatePaths() certificatePaths {
	return certificatePaths{
		caCert:     filepath.Join(cmd.OutputDir, "ca-cert.pem"),
		caKey:      filepath.Join(cmd.OutputDir, "ca-key.pem"),
		serverCert: filepath.Join(cmd.OutputDir, "server-cert.pem"),
		serverKey:  filepath.Join(cmd.OutputDir, "server-key.pem"),
		adminCert:  filepath.Join(cmd.OutputDir, "admin-cert.pem"),
		adminKey:   filepath.Join(cmd.OutputDir, "admin-key.pem"),
	}
}

// printLocalBootstrapSummary prints the summary for local development bootstrap
func (cmd *BootstrapCmd) printLocalBootstrapSummary(paths certificatePaths) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Bootstrap Complete - Local Development")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("\nEnvironment: %s\n", cmd.Environment)
	fmt.Printf("Domain:     %s\n\n", cmd.Domain)

	fmt.Println("Infrastructure created:")
	fmt.Printf("  DynamoDB:       airunner_%s_principals, airunner_%s_certificates\n", cmd.Environment, cmd.Environment)
	fmt.Printf("  SQS Queues:     airunner_%s_default, airunner_%s_priority, airunner_%s_dlq\n", cmd.Environment, cmd.Environment, cmd.Environment)
	fmt.Printf("  Certificates:   %s\n\n", cmd.OutputDir)

	fmt.Println("Certificate paths:")
	fmt.Printf("  CA Certificate:     %s\n", paths.caCert)
	fmt.Printf("  CA Key:             %s\n", paths.caKey)
	fmt.Printf("  Server Certificate: %s\n", paths.serverCert)
	fmt.Printf("  Server Key:         %s\n", paths.serverKey)
	fmt.Printf("  Admin Certificate:  %s\n", paths.adminCert)
	fmt.Printf("  Admin Key:          %s\n\n", paths.adminKey)

	fmt.Println("Next steps:")
	fmt.Println("  1. Start the server with mTLS enabled:")
	fmt.Printf("     ./bin/airunner-server rpc-server --enable-mtls \\\n")
	fmt.Printf("       --mtls-listen=0.0.0.0:443 \\\n")
	fmt.Printf("       --health-listen=0.0.0.0:8080 \\\n")
	fmt.Printf("       --ca-cert=%s \\\n", paths.caCert)
	fmt.Printf("       --server-cert=%s \\\n", paths.serverCert)
	fmt.Printf("       --server-key=%s\n\n", paths.serverKey)

	fmt.Println("  2. Test connectivity:")
	fmt.Printf("     curl --cacert %s \\\n", paths.caCert)
	fmt.Printf("          --cert %s \\\n", paths.adminCert)
	fmt.Printf("          --key %s \\\n", paths.adminKey)
	fmt.Printf("          https://%s:443/health\n\n", cmd.Domain)
}

// printAWSBootstrapSummary prints the summary for AWS production bootstrap
func (cmd *BootstrapCmd) printAWSBootstrapSummary(paths certificatePaths) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Bootstrap Complete - AWS Production")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("\nEnvironment: %s\n", cmd.Environment)
	fmt.Printf("Region:     %s\n", cmd.AWSRegion)
	fmt.Printf("Domain:     %s\n\n", cmd.Domain)

	fmt.Println("AWS resources configured:")
	fmt.Printf("  KMS Key:              Retrieved from /airunner/%s/ca-kms-key-id\n", cmd.Environment)
	fmt.Printf("  SSM Parameters:       /airunner/%s/{ca-cert,server-cert,server-key}\n", cmd.Environment)
	fmt.Printf("  DynamoDB Tables:      airunner_%s_principals, airunner_%s_certificates\n", cmd.Environment, cmd.Environment)
	fmt.Printf("  Local Certificates:  %s\n\n", cmd.OutputDir)

	fmt.Println("Certificate paths (local copy):")
	fmt.Printf("  CA Certificate:     %s\n", paths.caCert)
	fmt.Printf("  Server Certificate: %s\n", paths.serverCert)
	fmt.Printf("  Server Key:         %s\n\n", paths.serverKey)

	fmt.Println("Note: CA private key exists only in KMS and was never extracted.")
	fmt.Println("All certificates are also stored in AWS SSM Parameter Store.")
}

// File utility functions

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

func saveCertificate(path string, cert *x509.Certificate) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return os.WriteFile(path, certPEM, 0600)
}

func savePrivateKey(path string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(path, keyPEM, 0600)
}

// validateCertificate checks if a certificate exists and its validity status
func validateCertificate(path string, rotationThreshold time.Duration) (*CertValidation, error) {
	validation := &CertValidation{Path: path}

	// Check if file exists
	if !fileExists(path) {
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
