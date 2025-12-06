package server

import (
	"net/http"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/store"
)

// Server wraps the HTTP server and job services
type Server struct {
	store       store.JobStore
	jobServer   *JobServer
	eventServer *JobEventServer
}

// NewServer creates a new server with the given store
func NewServer(store store.JobStore) *Server {
	return &Server{
		store:       store,
		jobServer:   NewJobServer(store),
		eventServer: NewJobEventServer(store),
	}
}

// Handler returns the HTTP handler for the server
func (s *Server) Handler(log zerolog.Logger) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint for load balancer
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Register job service
	jobPath, jobHandler := jobv1connect.NewJobServiceHandler(
		s.jobServer,
		connect.WithInterceptors(
			logger.NewConnectRequests(log),
		),
	)
	mux.Handle(jobPath, jobHandler)

	// Register events service
	eventsPath, eventsHandler := jobv1connect.NewJobEventsServiceHandler(
		s.eventServer,
		connect.WithInterceptors(
			logger.NewConnectRequests(log),
		),
	)
	mux.Handle(eventsPath, eventsHandler)

	return mux
}
