package commands

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/authn"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/otelconnect"
	"github.com/rs/cors"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/autossl"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

type RPCServerCmd struct {
	Listen       string `help:"listen address" default:"localhost:8993"`
	Cert         string `help:"path to TLS cert file" default:""`
	Key          string `help:"path to TLS key file" default:""`
	Hostname     string `help:"hostname for TLS cert" default:"localhost:8993"`
	NoAuth       bool   `help:"disable JWT authentication (development only)" default:"false"`
	JWTPublicKey string `help:"PEM-encoded JWT public key" env:"JWT_PUBLIC_KEY"`
}

func (s *RPCServerCmd) Run(ctx context.Context, globals *Globals) error {
	log := logger.Setup(globals.Dev)

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")
	log.Info().Str("url", fmt.Sprintf("https://%s", s.Listen)).Msg("Listening for RPC connections")

	// Initialize OpenTelemetry (metrics and traces exported to Honeycomb via env vars)
	shutdown, err := telemetry.InitTelemetry(ctx, "airunner-server", globals.Version)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize telemetry, continuing without metrics")
		shutdown = func(ctx context.Context) error { return nil }
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown telemetry")
		}
	}()

	// setup OTEL
	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create OTEL interceptor: %w", err)
	}

	// Create and start the memory store
	memStore := store.NewMemoryJobStore()
	if err = memStore.Start(); err != nil {
		return err
	}
	defer func() {
		if err = memStore.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop memory store")
		}
	}()

	// Create server with store
	jobServer := server.NewServer(memStore)

	// Build handler chain: CORS -> Auth -> Connect handlers
	handler := jobServer.Handler(logger.NewConnectRequests(log), otelInterceptor)

	// Add JWT auth middleware unless disabled
	if !s.NoAuth {
		jwtAuthFunc, err := auth.NewJWTAuthFunc(s.JWTPublicKey)
		if err != nil {
			return fmt.Errorf("failed to initialize JWT auth: %w", err)
		}
		middleware := authn.NewMiddleware(jwtAuthFunc)
		handler = middleware.Wrap(handler)
		log.Info().Msg("JWT authentication enabled")
	} else {
		log.Warn().Msg("JWT authentication disabled")
	}

	// Add CORS
	handler = withCORS(s.Hostname, handler)

	httpServer := &http.Server{
		Addr:              s.Listen,
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 * 1024, // 8KiB
	}

	if s.Cert != "" && s.Key != "" {
		return httpServer.ListenAndServeTLS(s.Cert, s.Key)
	}

	cert, err := autossl.GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate ssl cert: %w", err)
	}

	// print the cert fingerprint
	fingerprint := sha256.Sum256(cert.Certificate[0])
	log.Info().
		Str("fingerprint", fmt.Sprintf("%x", fingerprint)).
		Msg("generated self-signed certificate")

	httpServer.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return httpServer.ListenAndServeTLS("", "")
}

// withCORS adds CORS support to a Connect HTTP handler.
func withCORS(hostname string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins: []string{hostname},
		AllowedMethods: connectcors.AllowedMethods(),
		AllowedHeaders: append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders: connectcors.ExposedHeaders(),
	})
	return middleware.Handler(h)
}
