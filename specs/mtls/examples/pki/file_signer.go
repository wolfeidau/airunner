// Package pki provides PKI utilities for certificate signing
//
// FileSigner implements CASigner using a local CA private key file.
// Used for local development mode.

package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// FileSigner signs certificates using a local CA private key file
type FileSigner struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

// NewFileSigner creates a new file-based signer
func NewFileSigner(keyPath, certPath string) (*FileSigner, error) {
	// Load CA private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}

	// Load CA certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}

	block, _ = pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	return &FileSigner{
		caKey:  caKey,
		caCert: caCert,
	}, nil
}

// SignCertificate signs a certificate template using the local CA key
func (s *FileSigner) SignCertificate(template *x509.Certificate) ([]byte, error) {
	return x509.CreateCertificate(
		rand.Reader,
		template,
		s.caCert,           // CA cert (issuer)
		template.PublicKey, // Certificate public key
		s.caKey,            // CA private key
	)
}

// GetCACertificate returns the CA certificate
func (s *FileSigner) GetCACertificate() (*x509.Certificate, error) {
	return s.caCert, nil
}
