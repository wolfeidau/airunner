package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	connectcors "connectrpc.com/cors"
	"github.com/rs/cors"
	"github.com/rs/xid"
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
		Addr: s.Listen,
		Handler: withLogging(
			withCORS(
				s.Hostname, jobServer.Handler(),
			),
		),
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

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		// If Write is called without WriteHeader, assume 200 OK
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming responses
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		correlationID := xid.New().String()

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200
		}
		wrapped.Header().Add("X-Correlation-ID", correlationID)

		h.ServeHTTP(wrapped, r)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("user_agent", r.UserAgent()).
			Str("correlation_id", correlationID).
			Int("status", wrapped.statusCode).
			Dur("duration", time.Since(start)).
			Msg("Handled request")
	})
}
