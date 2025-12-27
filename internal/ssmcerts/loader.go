package ssmcerts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Certificates holds certificate data in memory
type Certificates struct {
	CACert     []byte
	ServerCert []byte
	ServerKey  []byte
}

// Config for loading certificates
type Config struct {
	// File paths (for local development)
	CACertPath     string
	ServerCertPath string
	ServerKeyPath  string

	// SSM paths (for production)
	CACertSSM     string
	ServerCertSSM string
	ServerKeySSM  string
}

// Load loads certificates from either SSM or files
func Load(ctx context.Context, cfg Config) (*Certificates, error) {
	// Use SSM if paths are provided
	if cfg.CACertSSM != "" {
		return loadFromSSM(ctx, cfg)
	}

	// Otherwise use file paths
	return loadFromFiles(cfg)
}

// loadFromSSM loads certificates from AWS SSM Parameter Store
func loadFromSSM(ctx context.Context, cfg Config) (*Certificates, error) {
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := ssm.NewFromConfig(awsConfig)

	certs := &Certificates{}

	// Load CA certificate
	caCert, err := getParameter(ctx, client, cfg.CACertSSM)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert from SSM: %w", err)
	}
	certs.CACert = []byte(caCert)

	// Load server certificate
	serverCert, err := getParameter(ctx, client, cfg.ServerCertSSM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert from SSM: %w", err)
	}
	certs.ServerCert = []byte(serverCert)

	// Load server key
	serverKey, err := getParameter(ctx, client, cfg.ServerKeySSM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key from SSM: %w", err)
	}
	certs.ServerKey = []byte(serverKey)

	return certs, nil
}

// loadFromFiles loads certificates from file paths
func loadFromFiles(cfg Config) (*Certificates, error) {
	certs := &Certificates{}

	caCert, err := os.ReadFile(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	certs.CACert = caCert

	serverCert, err := os.ReadFile(cfg.ServerCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read server cert: %w", err)
	}
	certs.ServerCert = serverCert

	serverKey, err := os.ReadFile(cfg.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read server key: %w", err)
	}
	certs.ServerKey = serverKey

	return certs, nil
}

// getParameter fetches a parameter from SSM
func getParameter(ctx context.Context, client *ssm.Client, name string) (string, error) {
	output, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", err
	}
	if output.Parameter == nil || output.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s has no value", name)
	}
	return *output.Parameter.Value, nil
}

// TLSConfig creates a tls.Config from certificates
func (c *Certificates) TLSConfig() (*tls.Config, error) {
	// Load server certificate and key
	serverCert, err := tls.X509KeyPair(c.ServerCert, c.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	// Load CA certificate pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(c.CACert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Validate validates that certificate data is valid PEM
func (c *Certificates) Validate() error {
	// Validate CA cert
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(c.CACert) {
		return fmt.Errorf("invalid CA certificate PEM")
	}

	// Validate server cert/key pair
	_, err := tls.X509KeyPair(c.ServerCert, c.ServerKey)
	if err != nil {
		return fmt.Errorf("invalid server certificate/key: %w", err)
	}

	return nil
}
