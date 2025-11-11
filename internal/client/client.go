package client

import (
	"net/http"
	"time"

	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

// Config holds common client configuration
type Config struct {
	ServerURL string
	Timeout   time.Duration
	Debug     bool
}

// Clients holds the gRPC clients
type Clients struct {
	Job    jobv1connect.JobServiceClient
	Events jobv1connect.JobEventsServiceClient
}

// NewClients creates new gRPC clients with the given configuration
func NewClients(config Config) *Clients {
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	return &Clients{
		Job:    jobv1connect.NewJobServiceClient(httpClient, config.ServerURL),
		Events: jobv1connect.NewJobEventsServiceClient(httpClient, config.ServerURL),
	}
}

// DefaultConfig returns a default client configuration
func DefaultConfig() Config {
	return Config{
		ServerURL: "https://localhost:8080",
		Timeout:   5 * time.Minute,
		Debug:     false,
	}
}
