package store

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"github.com/wolfeidau/airunner/internal/pki"
)

// CertMetadata represents metadata about an issued certificate
type CertMetadata struct {
	SerialNumber     string     `dynamodbav:"serial_number"`
	PrincipalID      string     `dynamodbav:"principal_id"`
	PrincipalType    string     `dynamodbav:"principal_type"`
	Fingerprint      string     `dynamodbav:"fingerprint"`
	SubjectDN        string     `dynamodbav:"subject_dn"`
	IssuedAt         time.Time  `dynamodbav:"issued_at"`
	ExpiresAt        time.Time  `dynamodbav:"expires_at"`
	Revoked          bool       `dynamodbav:"revoked"`
	RevokedAt        *time.Time `dynamodbav:"revoked_at,omitempty"`
	RevocationReason string     `dynamodbav:"revocation_reason,omitempty"`
	Description      string     `dynamodbav:"description,omitempty"`
	TTL              int64      `dynamodbav:"ttl"` // Unix seconds for DynamoDB TTL
}

// CertificateStore manages certificate metadata
type CertificateStore interface {
	// Get retrieves certificate metadata by serial number
	Get(ctx context.Context, serialNumber string) (*CertMetadata, error)

	// GetByPrincipal retrieves all certificates for a principal
	GetByPrincipal(ctx context.Context, principalID string) ([]*CertMetadata, error)

	// GetByFingerprint retrieves certificate by SHA-256 fingerprint
	GetByFingerprint(ctx context.Context, fingerprint string) (*CertMetadata, error)

	// Register stores certificate metadata
	Register(ctx context.Context, cert *CertMetadata) error

	// Revoke marks a certificate as revoked
	Revoke(ctx context.Context, serialNumber string, reason string) error

	// List returns all registered certificates
	List(ctx context.Context, opts ListCertificatesOptions) ([]*CertMetadata, error)
}

// ListCertificatesOptions specifies filters for listing certificates
type ListCertificatesOptions struct {
	PrincipalID    string // Filter by principal (empty = all)
	IncludeRevoked bool   // Include revoked certs (default: false)
	Limit          int    // Max results (0 = default)
}

// Errors
var (
	ErrCertNotFound      = errors.New("certificate not found")
	ErrCertAlreadyExists = errors.New("certificate already exists")
	ErrCertRevoked       = errors.New("certificate is revoked")
	ErrCertExpired       = errors.New("certificate has expired")
)

// NewCertMetadataFromX509 creates CertMetadata from an X.509 certificate
func NewCertMetadataFromX509(cert *x509.Certificate) *CertMetadata {
	fingerprint := sha256.Sum256(cert.Raw)

	// Extract principal type and ID from custom OID extensions
	principalType, _ := pki.ExtractPrincipalType(cert)
	principalID, _ := pki.ExtractPrincipalID(cert)

	// Fall back to CN if principal ID extension not found
	if principalID == "" {
		principalID = cert.Subject.CommonName
	}

	// TTL: 30 days after expiry
	ttl := cert.NotAfter.Add(30 * 24 * time.Hour).Unix()

	return &CertMetadata{
		SerialNumber:  cert.SerialNumber.Text(16),
		PrincipalID:   principalID,
		PrincipalType: principalType,
		Fingerprint:   base64.StdEncoding.EncodeToString(fingerprint[:]),
		SubjectDN:     cert.Subject.String(),
		IssuedAt:      cert.NotBefore,
		ExpiresAt:     cert.NotAfter,
		Revoked:       false,
		TTL:           ttl,
	}
}
