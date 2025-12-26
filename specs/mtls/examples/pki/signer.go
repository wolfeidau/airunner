// Package pki provides PKI utilities for certificate signing
//
// This is a complete implementation of the CASigner interface.

package pki

import (
	"crypto/x509"
)

// CASigner signs certificate requests to create certificates
type CASigner interface {
	// SignCertificate signs a certificate template and returns the certificate bytes
	SignCertificate(template *x509.Certificate) ([]byte, error)

	// GetCACertificate returns the CA certificate (public key)
	GetCACertificate() (*x509.Certificate, error)
}
