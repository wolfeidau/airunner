package commands

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"filippo.io/csrf"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfeidau/airunner/internal/assets"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/login"
	"github.com/wolfeidau/airunner/internal/store"
	memorystore "github.com/wolfeidau/airunner/internal/store/memory"
	postgresstore "github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/website/oidc"
)

type WebsiteCmd struct {
	Hostname      string                    `help:"hostname for CORS" default:"localhost"`
	Listen        string                    `help:"HTTP server listen address" default:"0.0.0.0:443" env:"AIRUNNER_LISTEN"`
	Cert          string                    `help:"path to TLS cert file" default:"" env:"AIRUNNER_TLS_CERT"`
	Key           string                    `help:"path to TLS key file" default:"" env:"AIRUNNER_TLS_KEY"`
	ClientID      string                    `help:"GitHub client ID" default:"" env:"AIRUNNER_GITHUB_CLIENT_ID"`
	ClientSecret  string                    `help:"GitHub client secret" default:"" env:"AIRUNNER_GITHUB_CLIENT_SECRET"`
	CallbackURL   string                    `help:"GitHub callback URL" default:"" env:"AIRUNNER_GITHUB_CALLBACK_URL"`
	SessionTTL    time.Duration             `help:"session TTL" default:"168h" env:"AIRUNNER_SESSION_TTL"`
	BaseURL       string                    `help:"website base URL for OIDC issuer" default:"https://localhost" env:"AIRUNNER_WEBSITE_BASE_URL"`
	APIBaseURL    string                    `help:"API base URL for JWT audience" default:"https://localhost:8993" env:"AIRUNNER_API_BASE_URL"`
	StoreType     string                    `help:"store type (memory or postgres)" default:"memory" env:"AIRUNNER_STORE_TYPE" enum:"memory,postgres"`
	PostgresStore WebsitePostgresStoreFlags `embed:"" prefix:"postgres-"`
}

type WebsitePostgresStoreFlags struct {
	ConnString      string `help:"PostgreSQL connection string" default:"" env:"POSTGRES_CONNECTION_STRING"`
	MaxConns        int32  `help:"maximum number of connections in pool" default:"10"`
	MinConns        int32  `help:"minimum number of connections in pool" default:"2"`
	MaxConnLifetime int32  `help:"maximum connection lifetime in seconds" default:"3600"`
	MaxConnIdleTime int32  `help:"maximum connection idle time in seconds" default:"1800"`
}

func (c *WebsiteCmd) Run(globals *Globals) error {
	log := logger.Setup(globals.Debug)

	log.Info().Str("version", globals.Version).Bool("debug", globals.Debug).Msg("Starting website server")

	// Build assets
	pipeline, err := assets.New(assets.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to load assets pipeline: %w", err)
	}

	if err = pipeline.Build(); err != nil {
		return fmt.Errorf("failed to build js assets: %w", err)
	}

	mux := http.NewServeMux()

	// add asset serving of public assets
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

	// Register home page
	mux.HandleFunc("/",
		pipeline.Handler("Index: home", "ui/pages/index.tsx", nil))

	// Create stores based on store type
	ctx := context.Background()
	var (
		principalStore    store.PrincipalStore
		organizationStore store.OrganizationStore
		sessionStore      store.SessionStore
	)

	switch c.StoreType {
	case "postgres":
		pool, err := createPostgresPool(ctx, c)
		if err != nil {
			return err
		}
		principalStore = postgresstore.NewPrincipalStore(pool)
		organizationStore = postgresstore.NewOrganizationStore(pool)
		sessionStore = postgresstore.NewSessionStore(pool)
		log.Info().Msg("Using PostgreSQL stores")
	default:
		// Default to memory stores
		principalStore = memorystore.NewPrincipalStore()
		organizationStore = memorystore.NewOrganizationStore()
		sessionStore = memorystore.NewSessionStore()
		log.Info().Msg("Using in-memory stores")
	}

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

	// Initialize OIDC provider (always enabled)
	keyManager, err := oidc.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC key manager: %w", err)
	}

	oidcHandler := oidc.NewHandler(keyManager, principalStore, c.BaseURL)
	sessionAdapter := oidc.NewSessionAdapter(gh)

	// Register OIDC endpoints
	mux.HandleFunc("/.well-known/openid-configuration", oidcHandler.DiscoveryHandler())
	mux.HandleFunc("/.well-known/jwks.json", oidcHandler.JWKSHandler())
	mux.HandleFunc("/auth/token", oidcHandler.TokenHandler(sessionAdapter, c.APIBaseURL))

	log.Info().
		Str("issuer", c.BaseURL).
		Str("audience", c.APIBaseURL).
		Str("kid", keyManager.Kid()).
		Msg("OIDC provider initialized")

	// Register routes
	mux.HandleFunc("/login", gh.LoginHandler)              // Public
	mux.HandleFunc("/github/callback", gh.CallbackHandler) // Public
	mux.HandleFunc("/logout", gh.LogoutHandler)            // Public

	// Wrap with authentication middleware
	authMiddleware := gh.RequireAuth("/") // Redirect to / on auth failure

	// Register dashboard page
	mux.HandleFunc("/dashboard",
		authMiddleware(pipeline.Handler("Dashboard", "ui/pages/dashboard.tsx", contextFn)))

	protection := csrf.New()
	handler := protection.Handler(mux)

	log.Info().Str("addr", c.Listen).Msg("Starting HTTPS server")

	return configureHTTPServer(c.Listen, handler).ListenAndServeTLS(c.Cert, c.Key)
}

func contextFn(ctx context.Context) any {
	session, _ := login.SessionFromContext(ctx)
	return session
}

// createPostgresPool creates a PostgreSQL connection pool.
func createPostgresPool(ctx context.Context, c *WebsiteCmd) (*pgxpool.Pool, error) {
	if c.PostgresStore.ConnString == "" {
		return nil, fmt.Errorf("PostgreSQL connection string is required (--postgres-conn-string or POSTGRES_CONNECTION_STRING)")
	}

	// Parse connection string and create pool
	poolConfig, err := pgxpool.ParseConfig(c.PostgresStore.ConnString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PostgreSQL connection string: %w", err)
	}

	// Configure connection pool
	poolConfig.MaxConns = c.PostgresStore.MaxConns
	poolConfig.MinConns = c.PostgresStore.MinConns
	poolConfig.MaxConnLifetime = time.Duration(c.PostgresStore.MaxConnLifetime) * time.Second
	poolConfig.MaxConnIdleTime = time.Duration(c.PostgresStore.MaxConnIdleTime) * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Test connection
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	return pool, nil
}
