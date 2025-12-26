package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Custom OID arc: 1.3.6.1.4.1.99999.1.x (temporary private arc)
// For production, register a Private Enterprise Number (PEN) with IANA
var (
	// OIDAirunnerArc is the base OID for all Airunner extensions
	OIDAirunnerArc = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	// OIDPrincipalType identifies the principal type (admin, worker, user, service)
	// Value: UTF8String
	OIDPrincipalType = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

	// OIDPrincipalID identifies the unique principal identifier
	// Value: UTF8String
	OIDPrincipalID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
)

// PrincipalType represents the type of principal
type PrincipalType string

const (
	PrincipalTypeAdmin   PrincipalType = "admin"
	PrincipalTypeWorker  PrincipalType = "worker"
	PrincipalTypeUser    PrincipalType = "user"
	PrincipalTypeService PrincipalType = "service"
)

// ErrExtensionNotFound is returned when a required extension is missing
var ErrExtensionNotFound = errors.New("extension not found")

// ExtractPrincipalType extracts the principal type from custom OID extension
func ExtractPrincipalType(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPrincipalType) {
			var principalType string
			if _, err := asn1.Unmarshal(ext.Value, &principalType); err != nil {
				return "", fmt.Errorf("failed to unmarshal principal type: %w", err)
			}
			return principalType, nil
		}
	}
	return "", ErrExtensionNotFound
}

// ExtractPrincipalID extracts the principal ID from custom OID extension
func ExtractPrincipalID(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDPrincipalID) {
			var principalID string
			if _, err := asn1.Unmarshal(ext.Value, &principalID); err != nil {
				return "", fmt.Errorf("failed to unmarshal principal ID: %w", err)
			}
			return principalID, nil
		}
	}
	return "", ErrExtensionNotFound
}

// MustExtractPrincipal extracts both type and ID, falling back to CN for ID
func MustExtractPrincipal(cert *x509.Certificate) (principalType, principalID string, err error) {
	principalType, err = ExtractPrincipalType(cert)
	if err != nil {
		return "", "", fmt.Errorf("principal type: %w", err)
	}

	principalID, err = ExtractPrincipalID(cert)
	if err != nil {
		// Fall back to CommonName if ID extension not present
		principalID = cert.Subject.CommonName
		if principalID == "" {
			return "", "", fmt.Errorf("principal ID: no extension or CN found")
		}
	}

	return principalType, principalID, nil
}
