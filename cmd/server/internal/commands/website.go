package commands

import (
	"context"
	"fmt"
	"net/http"

	"filippo.io/csrf"
	"github.com/wolfeidau/airunner/internal/assets"
	"github.com/wolfeidau/airunner/internal/logger"
	"github.com/wolfeidau/airunner/internal/login"
)

type WebsiteCmd struct {
	Hostname      string `help:"hostname for CORS" default:"localhost"`
	Listen        string `help:"HTTP server listen address" default:"0.0.0.0:443" env:"AIRUNNER_LISTEN"`
	Cert          string `help:"path to TLS cert file" default:"" env:"AIRUNNER_TLS_CERT"`
	Key           string `help:"path to TLS key file" default:"" env:"AIRUNNER_TLS_KEY"`
	ClientID      string `help:"GitHub client ID" default:"" env:"AIRUNNER_GITHUB_CLIENT_ID"`
	ClientSecret  string `help:"GitHub client secret" default:"" env:"AIRUNNER_GITHUB_CLIENT_SECRET"`
	CallbackURL   string `help:"GitHub callback URL" default:"" env:"AIRUNNER_GITHUB_CALLBACK_URL"`
	SessionSecret string `help:"session secret" default:"" env:"AIRUNNER_SESSION_SECRET"`
}

func (c *WebsiteCmd) Run(globals *Globals) error {
	log := logger.Setup(globals.Dev)

	log.Info().Str("version", globals.Version).Msg("Starting website server")

	// Build assets
	pipeline, err := assets.NewWithTemplateDir(assets.DefaultConfig(), "views/pages")
	if err != nil {
		return fmt.Errorf("failed to load templates: %w", err)
	}

	if err = pipeline.Build(); err != nil {
		return fmt.Errorf("failed to build js assets: %w", err)
	}

	mux := http.NewServeMux()

	// add asset serving of public assets
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

	// Register home page
	homeHandler, err := pipeline.Handler("index.html", "Index: home", "ui/pages/index.tsx", nil)
	if err != nil {
		return fmt.Errorf("failed to create home handler: %w", err)
	}
	mux.HandleFunc("/", homeHandler) // Public

	// Initialize GitHub OAuth with session secret
	sessionSecret := []byte(c.SessionSecret)
	gh := login.NewGithub(c.ClientID, c.ClientSecret, c.CallbackURL, sessionSecret)

	// Register routes
	mux.HandleFunc("/login", gh.LoginHandler)              // Public
	mux.HandleFunc("/github/callback", gh.CallbackHandler) // Public

	// Wrap with authentication middleware
	authMiddleware := gh.RequireAuth("/") // Redirect to / on auth failure

	// Register dashboard page
	dashboardHandler, err := pipeline.Handler(
		"dashboard.html", "Dashboard", "ui/pages/dashboard.tsx",
		func(ctx context.Context) any {
			session, _ := login.SessionFromContext(ctx)
			return session
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create dashboard handler: %w", err)
	}
	mux.HandleFunc("/dashboard", authMiddleware(dashboardHandler))

	protection := csrf.New()
	handler := protection.Handler(mux)

	log.Info().Str("addr", c.Listen).Msg("Starting HTTPS server")

	return configureHTTPServer(c.Listen, handler).ListenAndServeTLS(c.Cert, c.Key)
}
