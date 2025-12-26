package pki

import (
	"crypto/x509"
)

// CASigner signs certificate requests to create certificates.
// Implementations include FileSigner (local development) and KMSSigner (AWS production).
type CASigner interface {
	// SignCertificate signs a certificate template and returns the DER-encoded certificate bytes.
	// The template must be fully populated with all required fields (subject, validity, extensions, etc.).
	// The signer will add its signature and return the complete certificate.
	SignCertificate(template *x509.Certificate) ([]byte, error)

	// GetCACertificate returns the CA certificate (public key only).
	// This is used for building certificate chains and verification.
	GetCACertificate() (*x509.Certificate, error)
}
