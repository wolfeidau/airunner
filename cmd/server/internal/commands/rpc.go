package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	connectcors "connectrpc.com/cors"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
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

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")
	log.Info().Str("url", fmt.Sprintf("https://%s", s.Listen)).Msg("Listening for RPC connections")

	// Create and start the memory store
	memStore := store.NewMemoryJobStore()
	if err := memStore.Start(); err != nil {
		return err
	}
	defer func() {
		if err := memStore.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop memory store")
		}
	}()

	// Create server with store
	jobServer := server.NewServer(memStore)

	httpServer := &http.Server{
		Addr:              s.Listen,
		Handler:           withCORS(s.Hostname, jobServer.Handler()),
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	return httpServer.ListenAndServeTLS(s.Cert, s.Key)
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
