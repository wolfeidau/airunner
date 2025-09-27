package commands

import (
	"context"
	"net/http"
	"os"
	"time"

	connectcors "connectrpc.com/cors"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/server"
)

type RPCServerCmd struct {
	Listen   string `help:"listen address" default:"localhost:8080"`
	Cert     string `help:"path to TLS cert file" default:"./.certs/cert.pem"`
	Key      string `help:"path to TLS key file" default:"./.certs/key.pem"`
	Hostname string `help:"hostname for TLS cert" default:"localhost:8080"`
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Caller().Logger()

	mux := http.NewServeMux()

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")
	log.Info().Str("listen", s.Listen).Msg("Listening for RPC connections")

	jobService := server.NewJobServer()

	mux.Handle(jobv1connect.NewJobServiceHandler(jobService))

	jobEventService := server.NewJobEventServer()

	mux.Handle(jobv1connect.NewJobEventsServiceHandler(jobEventService))

	server := &http.Server{
		Addr:              s.Listen,
		Handler:           withCORS(s.Hostname, mux),
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	return server.ListenAndServeTLS(s.Cert, s.Key)
}

// withCORS adds CORS support to a Connect HTTP handler.
func withCORS(hostname string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins: []string{hostname},
		AllowedMethods: connectcors.AllowedMethods(),
		AllowedHeaders: connectcors.AllowedHeaders(),
		ExposedHeaders: connectcors.ExposedHeaders(),
	})
	return middleware.Handler(h)
}
