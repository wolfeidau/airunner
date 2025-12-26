// Package pki provides PKI utilities for certificate signing
//
// KMSSigner implements CASigner using AWS KMS for signing operations.
// Used for production AWS deployments.

package pki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSSigner signs certificates using AWS KMS
type KMSSigner struct {
	client *kms.Client
	keyID  string
	caCert *x509.Certificate
}

// NewKMSSigner creates a new KMS-based signer
func NewKMSSigner(cfg aws.Config, keyID string, caCertPEM []byte) (*KMSSigner, error) {
	client := kms.NewFromConfig(cfg)

	// Parse CA certificate
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	return &KMSSigner{
		client: client,
		keyID:  keyID,
		caCert: caCert,
	}, nil
}

// SignCertificate signs a certificate template using KMS
func (s *KMSSigner) SignCertificate(template *x509.Certificate) ([]byte, error) {
	ctx := context.Background()

	// Build TBS (to-be-signed) certificate structure
	tbsCert, err := buildTBSCertificate(template, s.caCert)
	if err != nil {
		return nil, fmt.Errorf("build tbs certificate: %w", err)
	}

	// Hash the TBS certificate
	hash := sha256.Sum256(tbsCert)

	// Sign with KMS
	resp, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          hash[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}

	// Parse ECDSA signature from DER format
	sig, err := parseECDSASignature(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}

	// Assemble final certificate with KMS signature
	return assembleCertificate(tbsCert, sig)
}

// GetCACertificate returns the CA certificate
func (s *KMSSigner) GetCACertificate() (*x509.Certificate, error) {
	return s.caCert, nil
}

// buildTBSCertificate constructs the to-be-signed certificate bytes
func buildTBSCertificate(template, issuer *x509.Certificate) ([]byte, error) {
	// Note: This is a simplified example
	// Production implementation needs full TBSCertificate ASN.1 structure
	// See: https://tools.ietf.org/html/rfc5280#section-4.1

	// For complete implementation, use x509.CreateCertificate with nil key
	// and manually construct the TBS portion
	return nil, fmt.Errorf("not implemented - see full spec for TBS construction")
}

// parseECDSASignature parses DER-encoded ECDSA signature
func parseECDSASignature(der []byte) (*ecdsaSignature, error) {
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

// assembleCertificate assembles the final certificate with signature
func assembleCertificate(tbsCert []byte, sig *ecdsaSignature) ([]byte, error) {
	// Note: This is a simplified example
	// Production implementation needs full Certificate ASN.1 structure
	return nil, fmt.Errorf("not implemented - see full spec for certificate assembly")
}
