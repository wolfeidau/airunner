package server

import (
	"net/http"

	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
)

// Server wraps the HTTP server and job services
type Server struct {
	store      store.JobStore
	jobServer  *JobServer
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
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Register job service
	jobPath, jobHandler := jobv1connect.NewJobServiceHandler(s.jobServer)
	mux.Handle(jobPath, jobHandler)

	// Register events service
	eventsPath, eventsHandler := jobv1connect.NewJobEventsServiceHandler(s.eventServer)
	mux.Handle(eventsPath, eventsHandler)

	return mux
}
