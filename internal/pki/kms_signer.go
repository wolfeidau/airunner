package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSSigner implements CASigner using AWS KMS for signing operations.
// The CA private key never leaves the KMS HSM - only signing operations are performed.
// This is the recommended approach for production deployments.
type KMSSigner struct {
	kmsClient *kms.Client
	kmsKeyID  string
	caCert    *x509.Certificate
	publicKey *ecdsa.PublicKey
	ctx       context.Context
}

// NewKMSSigner creates a new KMSSigner from an AWS KMS key.
// The kmsKeyID can be a key ID, key ARN, alias name, or alias ARN.
// The caCertPEM must contain the PEM-encoded CA certificate (public key).
func NewKMSSigner(ctx context.Context, awsConfig aws.Config, kmsKeyID string, caCertPEM []byte) (*KMSSigner, error) {
	kmsClient := kms.NewFromConfig(awsConfig)

	// Parse CA certificate
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Get public key from KMS to verify it matches the certificate
	pubKeyOutput, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(kmsKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Parse the public key from KMS (DER-encoded)
	kmsPublicKey, err := x509.ParsePKIXPublicKey(pubKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS public key: %w", err)
	}

	ecdsaPubKey, ok := kmsPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not ECDSA (got %T)", kmsPublicKey)
	}

	// Verify KMS public key matches certificate public key
	certPubKey, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CA certificate public key is not ECDSA")
	}

	if !ecdsaPubKey.Equal(certPubKey) {
		return nil, fmt.Errorf("KMS public key does not match CA certificate public key")
	}

	return &KMSSigner{
		kmsClient: kmsClient,
		kmsKeyID:  kmsKeyID,
		caCert:    caCert,
		publicKey: ecdsaPubKey,
		ctx:       ctx,
	}, nil
}

// SignCertificate signs a certificate template using AWS KMS.
// Returns DER-encoded certificate bytes.
func (s *KMSSigner) SignCertificate(template *x509.Certificate) ([]byte, error) {
	// Create a KMS-backed signer that implements crypto.Signer
	kmsSigner := &kmsCryptoSigner{
		kmsClient: s.kmsClient,
		kmsKeyID:  s.kmsKeyID,
		publicKey: s.publicKey,
		ctx:       s.ctx,
	}

	// Use x509.CreateCertificate with our KMS signer
	return x509.CreateCertificate(rand.Reader, template, s.caCert, template.PublicKey, kmsSigner)
}

// GetCACertificate returns the CA certificate.
func (s *KMSSigner) GetCACertificate() (*x509.Certificate, error) {
	return s.caCert, nil
}

// NewKMSCryptoSigner creates a crypto.Signer backed by AWS KMS.
// This is used for signing self-signed CA certificates where you don't yet have a CA cert.
// For signing other certificates, use NewKMSSigner instead.
func NewKMSCryptoSigner(ctx context.Context, awsConfig aws.Config, kmsKeyID string) (crypto.Signer, error) {
	kmsClient := kms.NewFromConfig(awsConfig)

	// Get public key from KMS
	pubKeyOutput, err := kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(kmsKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Parse the public key
	kmsPublicKey, err := x509.ParsePKIXPublicKey(pubKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS public key: %w", err)
	}

	ecdsaPubKey, ok := kmsPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not ECDSA (got %T)", kmsPublicKey)
	}

	return &kmsCryptoSigner{
		kmsClient: kmsClient,
		kmsKeyID:  kmsKeyID,
		publicKey: ecdsaPubKey,
		ctx:       ctx,
	}, nil
}

// kmsCryptoSigner implements crypto.Signer using AWS KMS
type kmsCryptoSigner struct {
	kmsClient *kms.Client
	kmsKeyID  string
	publicKey *ecdsa.PublicKey
	ctx       context.Context
}

// Public returns the public key
func (k *kmsCryptoSigner) Public() crypto.PublicKey {
	return k.publicKey
}

// Sign signs the digest using AWS KMS
func (k *kmsCryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// KMS expects the digest to be hashed already
	// x509.CreateCertificate provides SHA-256 hash when using ECDSA
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("KMS signer only supports SHA256, got %v", opts.HashFunc())
	}

	// Call KMS to sign the digest
	signOutput, err := k.kmsClient.Sign(k.ctx, &kms.SignInput{
		KeyId:            aws.String(k.kmsKeyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign operation failed: %w", err)
	}

	// KMS returns a DER-encoded signature, but we need to convert it to the format expected by x509
	// Parse the DER signature (which is an ASN.1 SEQUENCE of two INTEGERs: r and s)
	var ecdsaSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signOutput.Signature, &ecdsaSig); err != nil {
		return nil, fmt.Errorf("failed to parse KMS signature: %w", err)
	}

	// Re-encode as ASN.1 DER (this is what x509.CreateCertificate expects)
	signature, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return signature, nil
}
