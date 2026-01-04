package commands

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/otelconnect"
	"filippo.io/csrf"
	"github.com/rs/cors"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/assets"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/client"
	httpmiddleware "github.com/wolfeidau/airunner/internal/http"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/login"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
	postgresstore "github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"github.com/wolfeidau/airunner/internal/website/oidc"
)

type ServerCmd struct {
	// Server configuration
	Listen string `help:"HTTP server listen address" default:"0.0.0.0:443" env:"AIRUNNER_LISTEN"`
	Cert   string `help:"path to TLS cert file" default:"" env:"AIRUNNER_TLS_CERT"`
	Key    string `help:"path to TLS key file" default:"" env:"AIRUNNER_TLS_KEY"`

	// CORS configuration
	CORSOrigins []string `help:"allowed CORS origins for API requests" default:"https://localhost" env:"AIRUNNER_CORS_ORIGINS"`

	// GitHub OAuth configuration
	ClientID     string        `help:"GitHub client ID" default:"" env:"AIRUNNER_GITHUB_CLIENT_ID"`
	ClientSecret string        `help:"GitHub client secret" default:"" env:"AIRUNNER_GITHUB_CLIENT_SECRET"`
	CallbackURL  string        `help:"GitHub callback URL" default:"" env:"AIRUNNER_GITHUB_CALLBACK_URL"`
	SessionTTL   time.Duration `help:"session TTL" default:"168h" env:"AIRUNNER_SESSION_TTL"`

	// OIDC configuration
	BaseURL string `help:"website base URL for OIDC issuer" default:"https://localhost" env:"AIRUNNER_WEBSITE_BASE_URL"`

	// Development and operational modes
	NoAuth  bool `help:"disable authentication for API endpoints (development only)" default:"false" env:"AIRUNNER_NO_AUTH"`
	Tracing bool `help:"enable tracing" default:"false" env:"AIRUNNER_TRACING"`

	// Store configuration
	StoreType     string             `help:"store type (memory or postgres)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,postgres"`
	PostgresStore PostgresStoreFlags `embed:"" prefix:"postgres-"`
	Execution     ExecutionFlags     `embed:"" prefix:"execution-"`
}

type PostgresStoreFlags struct {
	// Connection Configuration
	ConnString string `help:"PostgreSQL connection string" env:"POSTGRES_CONNECTION_STRING"`

	// Store Configuration
	TokenSigningSecret string `help:"secret key for HMAC signing of task tokens" env:"AIRUNNER_POSTGRES_TOKEN_SECRET"`
	EventsTTLDays      int32  `help:"TTL in days for job events" default:"30"`

	// Connection Pool Configuration
	MaxConns        int32 `help:"maximum number of connections in pool" default:"20"`
	MinConns        int32 `help:"minimum number of connections in pool" default:"5"`
	MaxConnLifetime int32 `help:"maximum connection lifetime in seconds" default:"3600"`
	MaxConnIdleTime int32 `help:"maximum connection idle time in seconds" default:"1800"`

	// Migration Configuration
	AutoMigrate bool `help:"run database migrations on startup" default:"false" env:"AIRUNNER_POSTGRES_AUTO_MIGRATE"`
}

func (s *PostgresStoreFlags) Validate() error {
	if s.ConnString == "" {
		return errors.New("PostgreSQL connection string is required (--postgres-conn-string or POSTGRES_CONNECTION_STRING)")
	}
	if s.TokenSigningSecret == "" {
		return errors.New("token signing secret is required (--postgres-token-secret or AIRUNNER_POSTGRES_TOKEN_SECRET)")
	}
	if len(s.TokenSigningSecret) < 32 {
		return errors.New("token signing secret must be at least 32 bytes (256 bits) for HMAC-SHA256")
	}
	return nil
}

// ExecutionFlags configures event batching and execution behavior
type ExecutionFlags struct {
	BatchFlushInterval int32 `help:"flush interval in seconds for event batching" default:"2" env:"AIRUNNER_EXEC_BATCH_FLUSH_INTERVAL"`
	BatchMaxSize       int32 `help:"max batch size in events" default:"50" env:"AIRUNNER_EXEC_BATCH_MAX_SIZE"`
	BatchMaxBytes      int64 `help:"max batch size in bytes" default:"1048576" env:"AIRUNNER_EXEC_BATCH_MAX_BYTES"`
	PlaybackInterval   int32 `help:"playback interval in milliseconds for client replay" default:"50" env:"AIRUNNER_EXEC_PLAYBACK_INTERVAL"`
	HeartbeatInterval  int32 `help:"heartbeat interval in seconds" default:"30" env:"AIRUNNER_EXEC_HEARTBEAT_INTERVAL"`
}

func (c *ServerCmd) Run(globals *Globals) error {
	log := logger.Setup(globals.Debug)
	ctx := context.Background()

	log.Info().Str("version", globals.Version).Bool("debug", globals.Debug).Msg("Starting server")

	// Setup telemetry if enabled
	interceptors := []connect.Interceptor{logger.NewConnectRequests(log)}
	if c.Tracing {
		log.Info().Msg("Tracing is enabled")
		shutdown, err := telemetry.InitTelemetry(ctx, "airunner-server", globals.Version)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize telemetry, continuing without metrics")
			shutdown = func(ctx context.Context) error { return nil }
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdown(shutdownCtx); err != nil {
				log.Error().Err(err).Msg("Failed to shutdown telemetry")
			}
		}()
		otelInterceptor, err := otelconnect.NewInterceptor()
		if err != nil {
			return fmt.Errorf("failed to create OTEL interceptor: %w", err)
		}
		interceptors = append(interceptors, otelInterceptor)
	}

	// Create stores based on store type
	var (
		jobStore          store.JobStore
		principalStore    store.PrincipalStore
		organizationStore store.OrganizationStore
		sessionStore      store.SessionStore
		err               error
	)

	switch c.StoreType {
	case "postgres":
		// Create shared connection pool for all PostgreSQL stores
		poolCfg := &postgresstore.PoolConfig{
			ConnString:      c.PostgresStore.ConnString,
			MaxConns:        c.PostgresStore.MaxConns,
			MinConns:        c.PostgresStore.MinConns,
			MaxConnLifetime: c.PostgresStore.MaxConnLifetime,
			MaxConnIdleTime: c.PostgresStore.MaxConnIdleTime,
		}
		pool, err := postgresstore.NewPool(ctx, poolCfg)
		if err != nil {
			return fmt.Errorf("failed to create connection pool: %w", err)
		}

		// Run migrations if enabled
		if c.PostgresStore.AutoMigrate {
			if err := postgresstore.RunMigrations(ctx, pool); err != nil {
				pool.Close()
				return fmt.Errorf("failed to run migrations: %w", err)
			}
			log.Info().Msg("Database migrations completed")
		}

		// Create job store configuration
		jobStoreCfg := &postgresstore.JobStoreConfig{
			TokenSigningSecret: []byte(c.PostgresStore.TokenSigningSecret),
			DefaultExecutionConfig: &jobv1.ExecutionConfig{
				Batching: &jobv1.BatchingConfig{
					FlushIntervalSeconds:   c.Execution.BatchFlushInterval,
					MaxBatchSize:           c.Execution.BatchMaxSize,
					MaxBatchBytes:          c.Execution.BatchMaxBytes,
					PlaybackIntervalMillis: c.Execution.PlaybackInterval,
				},
				HeartbeatIntervalSeconds: c.Execution.HeartbeatInterval,
			},
			EventsTTLDays: c.PostgresStore.EventsTTLDays,
		}

		// Create job store with shared pool
		jobStore, err = postgresstore.NewJobStore(pool, jobStoreCfg)
		if err != nil {
			pool.Close()
			return fmt.Errorf("failed to create job store: %w", err)
		}

		// Create identity stores with shared pool
		principalStore = postgresstore.NewPrincipalStore(pool)
		organizationStore = postgresstore.NewOrganizationStore(pool)
		sessionStore = postgresstore.NewSessionStore(pool)

		log.Info().Msg("Using PostgreSQL stores with shared connection pool")

	default:
		// Default to memory stores
		memStore := memorystore.NewJobStore()
		if err = memStore.Start(); err != nil {
			return err
		}
		jobStore = memStore
		principalStore = memorystore.NewPrincipalStore()
		organizationStore = memorystore.NewOrganizationStore()
		sessionStore = memorystore.NewSessionStore()
		log.Info().Msg("Using in-memory job store")
		log.Info().Msg("Using in-memory identity stores")
	}

	// Start job store if it supports Start()
	if startable, ok := jobStore.(interface{ Start() error }); ok {
		if err = startable.Start(); err != nil {
			return err
		}
		defer func() {
			if stoppable, ok := jobStore.(interface{ Stop() error }); ok {
				if err = stoppable.Stop(); err != nil {
					log.Error().Err(err).Msg("Failed to stop job store")
				}
			}
		}()
	}

	// Build assets for UI
	pipeline, err := assets.New(assets.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to load assets pipeline: %w", err)
	}
	if err = pipeline.Build(); err != nil {
		return fmt.Errorf("failed to build js assets: %w", err)
	}

	mux := http.NewServeMux()

	// Serve static assets
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

	// Register home page
	mux.HandleFunc("/", pipeline.Handler("Index: home", "ui/pages/index.tsx", nil))

	// Initialize GitHub OAuth with stores
	stores := login.Stores{
		Sessions:      sessionStore,
		Principals:    principalStore,
		Organizations: organizationStore,
	}
	gh, err := login.NewGithub(c.ClientID, c.ClientSecret, c.CallbackURL, stores, c.SessionTTL)
	if err != nil {
		return fmt.Errorf("failed to initialize GitHub OAuth: %w", err)
	}

	// Initialize OIDC provider
	keyManager, err := oidc.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC key manager: %w", err)
	}

	oidcHandler := oidc.NewHandler(keyManager, principalStore, c.BaseURL)
	sessionAdapter := oidc.NewSessionAdapter(gh)

	// Register OIDC endpoints (public)
	mux.HandleFunc("/.well-known/openid-configuration", oidcHandler.DiscoveryHandler())
	mux.HandleFunc("/.well-known/jwks.json", oidcHandler.JWKSHandler())
	mux.HandleFunc("/auth/token", oidcHandler.TokenHandler(sessionAdapter, c.BaseURL))

	log.Info().
		Str("issuer", c.BaseURL).
		Str("kid", keyManager.Kid()).
		Msg("OIDC provider initialized")

	// Client IP middleware for audit logging
	clientIPMiddleware := httpmiddleware.ClientIPMiddleware()

	// Register OAuth routes (public)
	mux.Handle("/login", clientIPMiddleware(http.HandlerFunc(gh.LoginHandler)))
	mux.Handle("/github/callback", clientIPMiddleware(http.HandlerFunc(gh.CallbackHandler)))
	mux.Handle("/logout", clientIPMiddleware(http.HandlerFunc(gh.LogoutHandler)))

	// Dashboard page (requires session auth)
	authMiddleware := gh.RequireAuth("/")
	mux.HandleFunc("/dashboard",
		authMiddleware(pipeline.Handler("Dashboard", "ui/pages/dashboard.tsx", contextFn)))

	// Create session provider adapter for dual auth
	sessionProvider := &sessionProviderAdapter{gh: gh}

	// Create JWT verifier for dual auth
	var jwtVerifier *auth.JWTVerifier
	if !c.NoAuth {
		cachingClient := client.NewInMemoryCachingHTTPClient()
		publicKeyCache := auth.NewPublicKeyCache(principalStore, cachingClient)
		revocationChecker := auth.NewRevocationChecker(ctx, principalStore, 5*time.Minute)
		defer revocationChecker.Stop()

		jwtVerifier = auth.NewJWTVerifier(c.BaseURL, publicKeyCache, revocationChecker)
	}

	// Create dual auth middleware for API endpoints
	// Supports both JWT (CLI/workers) and session cookies (browser)
	var dualAuthMiddleware func(http.Handler) http.Handler
	if !c.NoAuth {
		dualAuthMiddleware = auth.DualAuthMiddleware(jwtVerifier, sessionProvider)
	} else {
		// No auth mode - skip authentication
		log.Warn().Msg("Authentication is disabled (--no-auth). This should only be used in development!")
		dualAuthMiddleware = func(next http.Handler) http.Handler { return next }
	}

	// Create services
	credentialService := server.NewCredentialServiceServer(principalStore, organizationStore)
	jobServer := server.NewServer(jobStore).WithCredentialService(credentialService)

	// Get Connect RPC handler for job services
	jobHandler := jobServer.Handler(interceptors...)

	// Register job services with dual auth (supports both JWT and session)
	// This allows both CLI (JWT) and browser (session) access
	mux.Handle("/job.v1.JobService/", dualAuthMiddleware(jobHandler))
	mux.Handle("/job.v1.JobEventsService/", dualAuthMiddleware(jobHandler))

	// Register CredentialService with dual auth
	credentialPath, credentialHandler := principalv1connect.NewCredentialServiceHandler(credentialService)
	mux.Handle(credentialPath, dualAuthMiddleware(credentialHandler))

	log.Info().Msg("Job services registered with dual auth (JWT + session)")
	log.Info().Str("path", credentialPath).Msg("CredentialService registered with dual auth")

	// CSRF protection for HTML pages (not applied to API routes)
	protection := csrf.New()

	// Create final handler with CORS support for API routes
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API routes get CORS, HTML routes get CSRF
		if isAPIRoute(r.URL.Path) {
			withCORS(c.CORSOrigins, mux).ServeHTTP(w, r)
		} else {
			protection.Handler(mux).ServeHTTP(w, r)
		}
	})

	// Validate TLS certificates
	if c.Cert == "" || c.Key == "" {
		return errors.New("TLS certificate and key are required (--cert and --key)")
	}
	if _, err := os.Stat(c.Cert); err != nil {
		return fmt.Errorf("TLS certificate not found at %s: %w", c.Cert, err)
	}
	if _, err := os.Stat(c.Key); err != nil {
		return fmt.Errorf("TLS key not found at %s: %w", c.Key, err)
	}

	log.Info().Str("addr", c.Listen).Bool("auth", !c.NoAuth).Msg("Starting HTTPS server")
	return configureHTTPServer(c.Listen, handler).ListenAndServeTLS(c.Cert, c.Key)
}

// isAPIRoute returns true if the path is an API route that needs CORS instead of CSRF
func isAPIRoute(path string) bool {
	return strings.HasPrefix(path, "/job.v1.") ||
		strings.HasPrefix(path, "/principal.v1.") ||
		strings.HasPrefix(path, "/.well-known/")
}

func contextFn(ctx context.Context) any {
	session, _ := login.SessionFromContext(ctx)
	return session
}

// sessionProviderAdapter adapts login.Github to auth.SessionProvider interface.
type sessionProviderAdapter struct {
	gh *login.Github
}

// GetSessionData implements auth.SessionProvider interface.
func (a *sessionProviderAdapter) GetSessionData(r *http.Request) (*auth.SessionData, error) {
	data, err := a.gh.GetSessionData(r)
	if err != nil {
		return nil, err
	}
	return &auth.SessionData{
		SessionID:   data.SessionID,
		PrincipalID: data.PrincipalID,
		OrgID:       data.OrgID,
		Roles:       data.Roles,
	}, nil
}

// withCORS adds CORS support to a Connect HTTP handler.
func withCORS(allowedOrigins []string, h http.Handler) http.Handler {
	middleware := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   connectcors.AllowedMethods(),
		AllowedHeaders:   append(connectcors.AllowedHeaders(), "Authorization"),
		ExposedHeaders:   connectcors.ExposedHeaders(),
		AllowCredentials: true, // Required for cookie-based authentication
	})
	return middleware.Handler(h)
}
