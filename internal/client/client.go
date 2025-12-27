package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"golang.org/x/net/http2"
)

// Config holds common client configuration
type Config struct {
	ServerURL  string
	Timeout    time.Duration
	Debug      bool
	CACert     string // Path to CA certificate for server verification
	ClientCert string // Path to client certificate for mTLS
	ClientKey  string // Path to client private key for mTLS
}

// Clients holds the gRPC clients
type Clients struct {
	Job    jobv1connect.JobServiceClient
	Events jobv1connect.JobEventsServiceClient
}

// NewClients creates new gRPC clients with the given configuration
func NewClients(config Config, opts ...connect.ClientOption) (*Clients, error) {
	var transport http.RoundTripper = &http2.Transport{
		ReadIdleTimeout: 10 * time.Second,
		PingTimeout:     10 * time.Second,
	}

	// Configure mTLS if certificates are provided
	if config.CACert != "" || config.ClientCert != "" {
		tlsConfig, err := buildTLSConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}

		transport = &http2.Transport{
			TLSClientConfig: tlsConfig,
			ReadIdleTimeout: 10 * time.Second,
			PingTimeout:     10 * time.Second,
		}
	}

	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	return &Clients{
		Job:    jobv1connect.NewJobServiceClient(httpClient, config.ServerURL, opts...),
		Events: jobv1connect.NewJobEventsServiceClient(httpClient, config.ServerURL, opts...),
	}, nil
}

// buildTLSConfig creates a TLS configuration for mTLS
func buildTLSConfig(config Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate if provided
	if config.CACert != "" {
		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if provided
	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// DefaultConfig returns a default client configuration
func DefaultConfig() Config {
	return Config{
		ServerURL: "https://localhost:8080",
		Timeout:   5 * time.Minute,
		Debug:     false,
	}
}
