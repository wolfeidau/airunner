package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// FileSigner implements CASigner using a CA private key stored in a file.
// This is intended for local development only - not for production use.
type FileSigner struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

// NewFileSigner creates a new FileSigner from PEM-encoded key and certificate files.
// The caKeyPath must point to a PEM-encoded ECDSA private key.
// The caCertPath must point to a PEM-encoded X.509 certificate.
func NewFileSigner(caKeyPath, caCertPath string) (*FileSigner, error) {
	// Load CA private key
	keyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Load CA certificate
	certData, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert file: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Verify key and cert match
	if err := verifyCertKeyPair(caCert, caKey); err != nil {
		return nil, fmt.Errorf("CA key and certificate do not match: %w", err)
	}

	return &FileSigner{
		caKey:  caKey,
		caCert: caCert,
	}, nil
}

// SignCertificate signs a certificate template using the file-based CA private key.
// Returns DER-encoded certificate bytes.
func (s *FileSigner) SignCertificate(template *x509.Certificate) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, s.caCert, template.PublicKey, s.caKey)
}

// GetCACertificate returns the CA certificate.
func (s *FileSigner) GetCACertificate() (*x509.Certificate, error) {
	return s.caCert, nil
}

// verifyCertKeyPair checks that a certificate's public key matches a private key
func verifyCertKeyPair(cert *x509.Certificate, key crypto.PrivateKey) error {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not ECDSA")
	}

	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not ECDSA")
	}

	if !ecdsaKey.PublicKey.Equal(certPubKey) {
		return fmt.Errorf("public keys do not match")
	}

	return nil
}
