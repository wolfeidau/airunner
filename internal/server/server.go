package server

import (
	"net/http"
	"slices"

	"connectrpc.com/connect"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/store"
)

// Server wraps the HTTP server and job services
type Server struct {
	store            store.JobStore
	jobServer        *JobServer
	eventServer      *JobEventServer
	credentialServer *CredentialServiceServer
}

// NewServer creates a new server with the given store
func NewServer(store store.JobStore) *Server {
	return &Server{
		store:       store,
		jobServer:   NewJobServer(store),
		eventServer: NewJobEventServer(store),
	}
}

// WithCredentialService adds a credential service to the server.
func (s *Server) WithCredentialService(credentialServer *CredentialServiceServer) *Server {
	s.credentialServer = credentialServer
	return s
}

// Handler returns the HTTP handler for the server
func (s *Server) Handler(otelInterceptor ...connect.Interceptor) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint for load balancer
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Authz runs after the passed-in interceptors so denials are still logged and traced.
	jobInterceptors := append(slices.Clone(otelInterceptor), auth.NewJobAuthzInterceptor())

	// Register job service
	jobPath, jobHandler := jobv1connect.NewJobServiceHandler(
		s.jobServer,
		connect.WithInterceptors(jobInterceptors...),
	)
	mux.Handle(jobPath, jobHandler)

	// Register events service
	eventsPath, eventsHandler := jobv1connect.NewJobEventsServiceHandler(
		s.eventServer,
		connect.WithInterceptors(jobInterceptors...),
	)
	mux.Handle(eventsPath, eventsHandler)

	// Register credential service if available
	if s.credentialServer != nil {
		credPath, credHandler := principalv1connect.NewCredentialServiceHandler(
			s.credentialServer,
			connect.WithInterceptors(
				otelInterceptor...,
			),
		)
		mux.Handle(credPath, credHandler)
	}

	return mux
}
