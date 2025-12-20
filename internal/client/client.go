package client

import (
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"golang.org/x/net/http2"
)

// Config holds common client configuration
type Config struct {
	ServerURL string
	Timeout   time.Duration
	Debug     bool
	Token     string
}

// Clients holds the gRPC clients
type Clients struct {
	Job    jobv1connect.JobServiceClient
	Events jobv1connect.JobEventsServiceClient
}

// NewClients creates new gRPC clients with the given configuration
func NewClients(config Config, opts ...connect.ClientOption) *Clients {
	var transport = http.DefaultTransport

	// Add auth header if token is provided
	if config.Token != "" {
		transport = &authTransport{
			token: config.Token,
			transport: &http2.Transport{
				ReadIdleTimeout: 10 * time.Second,
				PingTimeout:     10 * time.Second,
			},
		}
	}

	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	return &Clients{
		Job:    jobv1connect.NewJobServiceClient(httpClient, config.ServerURL, opts...),
		Events: jobv1connect.NewJobEventsServiceClient(httpClient, config.ServerURL, opts...),
	}
}

// authTransport adds Authorization header to requests
type authTransport struct {
	token     string
	transport http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}

// DefaultConfig returns a default client configuration
func DefaultConfig() Config {
	return Config{
		ServerURL: "https://localhost:8080",
		Timeout:   5 * time.Minute,
		Debug:     false,
	}
}
