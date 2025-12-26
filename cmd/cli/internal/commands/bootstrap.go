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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/pki"
	"github.com/wolfeidau/airunner/internal/store"
)

// BootstrapCmd handles mTLS bootstrap for development and production
type BootstrapCmd struct {
	Environment string `help:"environment name (local, dev, prod)" default:"local" enum:"local,dev,prod"`
	Domain      string `help:"server domain name" default:"localhost"`
	AWSRegion   string `help:"AWS region" default:"us-east-1" env:"AWS_REGION"`
	OutputDir   string `help:"output directory for certificates" default:"./certs"`
	AWSEndpoint string `help:"AWS endpoint (for LocalStack)" default:"" env:"AWS_ENDPOINT"`
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

// Run executes the bootstrap command
func (cmd *BootstrapCmd) Run(ctx context.Context, globals *Globals) error {
	log.Info().
		Str("environment", cmd.Environment).
		Str("domain", cmd.Domain).
		Str("output_dir", cmd.OutputDir).
		Msg("Starting mTLS bootstrap")

	// Create output directory
	if err := os.MkdirAll(cmd.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	paths := certificatePaths{
		caCert:     filepath.Join(cmd.OutputDir, "ca-cert.pem"),
		caKey:      filepath.Join(cmd.OutputDir, "ca-key.pem"),
		serverCert: filepath.Join(cmd.OutputDir, "server-cert.pem"),
		serverKey:  filepath.Join(cmd.OutputDir, "server-key.pem"),
		adminCert:  filepath.Join(cmd.OutputDir, "admin-cert.pem"),
		adminKey:   filepath.Join(cmd.OutputDir, "admin-key.pem"),
	}

	// Step 1: Ensure CA exists
	caCert, caKey, err := cmd.ensureCA(paths)
	if err != nil {
		return fmt.Errorf("failed to ensure CA: %w", err)
	}

	// Step 2: Ensure server certificate exists
	if err := cmd.ensureServerCert(paths, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	// Initialize AWS clients if not local
	if cmd.Environment != "local" {
		awsConfig, err := cmd.loadAWSConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to load AWS config: %w", err)
		}

		// Step 5: Upload certificates to AWS
		if err := cmd.uploadToAWS(ctx, awsConfig, paths); err != nil {
			return fmt.Errorf("failed to upload to AWS: %w", err)
		}
	}

	// Initialize stores
	principalStore, certStore, err := cmd.createStores(ctx)
	if err != nil {
		return fmt.Errorf("failed to create stores: %w", err)
	}

	// Step 3: Ensure admin principal exists
	if err := cmd.ensureAdminPrincipal(ctx, principalStore); err != nil {
		return fmt.Errorf("failed to ensure admin principal: %w", err)
	}

	// Step 4: Ensure admin certificate exists
	if err := cmd.ensureAdminCert(ctx, paths, caCert, caKey, certStore); err != nil {
		return fmt.Errorf("failed to ensure admin certificate: %w", err)
	}

	// Step 6: Print summary
	cmd.printSummary(paths)

	return nil
}

// ensureCA ensures the CA certificate and key exist
func (cmd *BootstrapCmd) ensureCA(paths certificatePaths) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Check if CA cert and key already exist
	if fileExists(paths.caCert) && fileExists(paths.caKey) {
		log.Info().Msg("CA certificate and key already exist, loading...")

		caCert, err := loadCertificate(paths.caCert)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}

		caKey, err := loadPrivateKey(paths.caKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load CA key: %w", err)
		}

		log.Info().
			Str("subject", caCert.Subject.CommonName).
			Time("not_before", caCert.NotBefore).
			Time("not_after", caCert.NotAfter).
			Msg("Loaded existing CA certificate")

		return caCert, caKey, nil
	}

	log.Info().Msg("Generating new CA certificate...")

	// Generate CA key pair
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
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
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save CA certificate
	if err := saveCertificate(paths.caCert, caCert); err != nil {
		return nil, nil, fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Save CA key
	if err := savePrivateKey(paths.caKey, caKey); err != nil {
		return nil, nil, fmt.Errorf("failed to save CA key: %w", err)
	}

	log.Info().
		Str("path_cert", paths.caCert).
		Str("path_key", paths.caKey).
		Msg("Generated and saved CA certificate")

	return caCert, caKey, nil
}

// ensureServerCert ensures the server certificate exists
func (cmd *BootstrapCmd) ensureServerCert(paths certificatePaths, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	// Check if server cert and key already exist
	if fileExists(paths.serverCert) && fileExists(paths.serverKey) {
		log.Info().Msg("Server certificate already exists")
		return nil
	}

	log.Info().Msg("Generating server certificate...")

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
	}

	// Sign the server certificate with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
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
func (cmd *BootstrapCmd) ensureAdminCert(ctx context.Context, paths certificatePaths, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, certStore store.CertificateStore) error {
	// Check if admin cert already exists
	if fileExists(paths.adminCert) && fileExists(paths.adminKey) {
		log.Info().Msg("Admin certificate already exists")
		return nil
	}

	log.Info().Msg("Generating admin certificate with custom OID extensions...")

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

	// Sign the admin certificate with CA
	adminCertDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &adminKey.PublicKey, caKey)
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
	if cmd.Environment == "local" {
		// Use in-memory stores for local development
		return store.NewMemoryPrincipalStore(), store.NewMemoryCertificateStore(), nil
	}

	// Use DynamoDB stores for dev/prod
	awsConfig, err := cmd.loadAWSConfig(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	dynamoClient := dynamodb.NewFromConfig(awsConfig)

	principalsTable := fmt.Sprintf("airunner_%s_principals", cmd.Environment)
	certificatesTable := fmt.Sprintf("airunner_%s_certificates", cmd.Environment)

	principalStore := store.NewDynamoDBPrincipalStore(dynamoClient, principalsTable)
	certStore := store.NewDynamoDBCertificateStore(dynamoClient, certificatesTable)

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

// uploadToAWS uploads certificates to AWS SSM and Secrets Manager
func (cmd *BootstrapCmd) uploadToAWS(ctx context.Context, awsConfig aws.Config, paths certificatePaths) error {
	log.Info().Msg("Uploading certificates to AWS...")

	ssmClient := ssm.NewFromConfig(awsConfig)
	secretsClient := secretsmanager.NewFromConfig(awsConfig)

	prefix := fmt.Sprintf("/airunner/%s", cmd.Environment)

	// Upload CA cert to SSM
	caCertPEM, err := os.ReadFile(paths.caCert)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	if err := cmd.putSSMParameter(ctx, ssmClient, fmt.Sprintf("%s/ca-cert", prefix), string(caCertPEM), ssmtypes.ParameterTypeString); err != nil {
		return fmt.Errorf("failed to upload CA cert: %w", err)
	}

	// Upload server cert to SSM
	serverCertPEM, err := os.ReadFile(paths.serverCert)
	if err != nil {
		return fmt.Errorf("failed to read server cert: %w", err)
	}

	if err := cmd.putSSMParameter(ctx, ssmClient, fmt.Sprintf("%s/server-cert", prefix), string(serverCertPEM), ssmtypes.ParameterTypeString); err != nil {
		return fmt.Errorf("failed to upload server cert: %w", err)
	}

	// Upload server key to SSM (SecureString)
	serverKeyPEM, err := os.ReadFile(paths.serverKey)
	if err != nil {
		return fmt.Errorf("failed to read server key: %w", err)
	}

	if err := cmd.putSSMParameter(ctx, ssmClient, fmt.Sprintf("%s/server-key", prefix), string(serverKeyPEM), ssmtypes.ParameterTypeSecureString); err != nil {
		return fmt.Errorf("failed to upload server key: %w", err)
	}

	// Upload CA key to Secrets Manager
	caKeyPEM, err := os.ReadFile(paths.caKey)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	if err := cmd.putSecret(ctx, secretsClient, fmt.Sprintf("%s/ca-key", prefix), string(caKeyPEM)); err != nil {
		return fmt.Errorf("failed to upload CA key: %w", err)
	}

	log.Info().Msg("Successfully uploaded all certificates to AWS")

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

// putSecret puts a secret in Secrets Manager
func (cmd *BootstrapCmd) putSecret(ctx context.Context, client *secretsmanager.Client, name, value string) error {
	// Try to create the secret first
	_, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(value),
	})
	if err != nil {
		// If secret exists, update it
		_, err = client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(name),
			SecretString: aws.String(value),
		})
		if err != nil {
			return err
		}
	}

	log.Info().Str("secret", name).Msg("Uploaded to Secrets Manager")
	return nil
}

// printSummary prints a summary of the bootstrap operation
func (cmd *BootstrapCmd) printSummary(paths certificatePaths) {
	fmt.Println("\n=== Bootstrap Complete ===")
	fmt.Printf("Environment: %s\n", cmd.Environment)
	fmt.Printf("Domain: %s\n", cmd.Domain)
	fmt.Printf("Output directory: %s\n\n", cmd.OutputDir)

	fmt.Println("Generated certificates:")
	fmt.Printf("  CA Certificate:     %s\n", paths.caCert)
	fmt.Printf("  CA Key:             %s\n", paths.caKey)
	fmt.Printf("  Server Certificate: %s\n", paths.serverCert)
	fmt.Printf("  Server Key:         %s\n", paths.serverKey)
	fmt.Printf("  Admin Certificate:  %s\n", paths.adminCert)
	fmt.Printf("  Admin Key:          %s\n", paths.adminKey)

	fmt.Println("\nNext steps:")
	fmt.Println("  1. Start the server with mTLS enabled:")
	fmt.Printf("     ./bin/airunner-server --enable-mtls \\\n")
	fmt.Printf("       --mtls-listen=0.0.0.0:443 \\\n")
	fmt.Printf("       --health-listen=0.0.0.0:8080 \\\n")
	fmt.Printf("       --ca-cert=%s \\\n", paths.caCert)
	fmt.Printf("       --server-cert=%s \\\n", paths.serverCert)
	fmt.Printf("       --server-key=%s\n\n", paths.serverKey)

	fmt.Println("  2. Test with admin certificate:")
	fmt.Printf("     curl --cacert %s \\\n", paths.caCert)
	fmt.Printf("          --cert %s \\\n", paths.adminCert)
	fmt.Printf("          --key %s \\\n", paths.adminKey)
	fmt.Printf("          https://%s:443/health\n\n", cmd.Domain)
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

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParseECPrivateKey(block.Bytes)
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
