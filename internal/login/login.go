package login

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	httpmiddleware "github.com/wolfeidau/airunner/internal/http"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	ErrInvalidSession = errors.New("invalid session")
	ErrExpiredSession = errors.New("session expired")
)

type contextKey string

const sessionContextKey contextKey = "session"

// Stores holds the storage dependencies for authentication.
type Stores struct {
	Sessions      store.SessionStore
	Principals    store.PrincipalStore
	Organizations store.OrganizationStore
}

type Github struct {
	config     *oauth2.Config
	stores     Stores
	sessionTTL time.Duration
}

func NewGithub(clientID, clientSecret, callbackURL string, stores Stores, sessionTTL time.Duration) (*Github, error) {
	if clientID == "" || clientSecret == "" || callbackURL == "" {
		return nil, fmt.Errorf("client ID, client secret, and callback URL are required")
	}

	if sessionTTL <= 0 {
		return nil, fmt.Errorf("session TTL must be greater than 0")
	}

	if stores.Sessions == nil || stores.Principals == nil || stores.Organizations == nil {
		return nil, fmt.Errorf("all stores (sessions, principals, organizations) are required")
	}

	return &Github{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		},
		stores:     stores,
		sessionTTL: sessionTTL,
	}, nil
}

// SessionData holds the authenticated user's session information.
// This is retrieved from the session store and added to the request context.
type SessionData struct {
	SessionID   uuid.UUID
	PrincipalID uuid.UUID
	OrgID       uuid.UUID
	Name        string // Display name from principal
	Email       string // Email from principal
	AvatarURL   string // Avatar URL from principal
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// GetSession extracts and validates the session from a request.
// The cookie contains only the session ID (UUIDv7), all data is fetched from the store.
func (g *Github) GetSession(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie("_session")
	if err != nil {
		return nil, ErrInvalidSession
	}

	// Parse session ID from cookie
	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		log.Debug().Err(err).Msg("Invalid session ID format in cookie")
		return nil, ErrInvalidSession
	}

	// Look up session in store
	session, err := g.stores.Sessions.Get(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, store.ErrSessionNotFound) {
			return nil, ErrInvalidSession
		}
		if errors.Is(err, store.ErrSessionExpired) {
			return nil, ErrExpiredSession
		}
		log.Error().Err(err).Msg("Failed to get session from store")
		return nil, ErrInvalidSession
	}

	// Get principal to populate display fields
	principal, err := g.stores.Principals.Get(r.Context(), session.PrincipalID)
	if err != nil {
		log.Error().Err(err).Str("principal_id", session.PrincipalID.String()).Msg("Failed to get principal for session")
		return nil, ErrInvalidSession
	}

	// Build session data with display fields from principal
	data := &SessionData{
		SessionID:   session.SessionID,
		PrincipalID: session.PrincipalID,
		OrgID:       session.OrgID,
		Name:        principal.Name,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   session.ExpiresAt,
	}
	if principal.Email != nil {
		data.Email = *principal.Email
	}
	if principal.AvatarURL != nil {
		data.AvatarURL = *principal.AvatarURL
	}

	return data, nil
}

// RequireAuth is a middleware that protects routes by requiring a valid session.
// If the session is invalid or expired, it redirects to the specified redirectURL with an error_code query parameter.
// On success, it adds the session data to the request context and calls the next handler.
func (g *Github) RequireAuth(redirectURL string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session, err := g.GetSession(r)
			if err != nil {
				// Determine error code based on error type
				errorCode := "invalid"
				if errors.Is(err, ErrExpiredSession) {
					errorCode = "expired"
					log.Debug().Str("path", r.URL.Path).Msg("Session expired, redirecting to login")
				} else {
					log.Debug().Str("path", r.URL.Path).Msg("Invalid session, redirecting to login")
				}

				// Redirect to the specified URL with error code
				http.Redirect(w, r, redirectURL+"?error_code="+errorCode, http.StatusFound)
				return
			}

			log.Debug().Str("user", session.Email).Str("path", r.URL.Path).Msg("Session validated, allowing access")

			// Add session to request context
			ctx := context.WithValue(r.Context(), sessionContextKey, session)
			next(w, r.WithContext(ctx))
		}
	}
}

// SessionFromContext extracts the session data from the request context.
// This should be called from handlers protected by RequireAuth middleware.
func SessionFromContext(ctx context.Context) (*SessionData, bool) {
	session, ok := ctx.Value(sessionContextKey).(*SessionData)
	return session, ok
}

func (g *Github) saveState(w http.ResponseWriter, r *http.Request) string {
	// generate random state
	state := rand.Text()

	cookie := &http.Cookie{
		Name:     "state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes - enough time for OAuth flow
	}
	http.SetCookie(w, cookie)

	return state
}

func (g *Github) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user already has a valid session
	session, err := g.GetSession(r)
	if err == nil && session != nil {
		// Valid session exists, redirect to dashboard
		log.Debug().Str("user", session.Email).Msg("User already authenticated, redirecting to dashboard")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// No valid session, proceed with OAuth flow
	log.Debug().Msg("Initiating GitHub OAuth flow")

	state := g.saveState(w, r)

	// redirect to github
	http.Redirect(w, r, g.config.AuthCodeURL(state), http.StatusFound)
}

func (g *Github) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("OAuth callback received")

	state := r.FormValue("state")
	code := r.FormValue("code")

	if state == "" || code == "" {
		log.Warn().Msg("OAuth callback missing state or code")
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("state")
	if err != nil {
		log.Warn().Err(err).Msg("OAuth callback missing state cookie")
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	if state != cookie.Value {
		log.Warn().Msg("OAuth callback state mismatch")
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	log.Debug().Msg("OAuth state validated successfully")

	// Clear the state cookie after validation
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// exchange code for token
	token, err := g.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to exchange OAuth code for token")
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	log.Debug().Msg("OAuth token exchange successful")

	// get user info
	userInfo, err := g.getUserInfo(r.Context(), token)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch user info from GitHub")
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	// Verify we got an email
	if userInfo.Email == "" {
		log.Warn().Msg("GitHub user info missing email address")
		http.Error(w, "Email address required", http.StatusBadRequest)
		return
	}

	log.Info().Str("user", userInfo.Email).Str("login", userInfo.Login).Msg("User authenticated successfully")

	// Get or create principal (and org on first login)
	ctx := r.Context()
	githubID := strconv.Itoa(userInfo.ID)

	principal, orgID, err := g.getOrCreatePrincipal(ctx, githubID, userInfo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get or create principal")
		http.Error(w, "Failed to create account", http.StatusInternalServerError)
		return
	}

	// Create session in store
	now := time.Now()
	sessionID, err := uuid.NewV7()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate session ID")
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	session := &models.Session{
		SessionID:   sessionID,
		PrincipalID: principal.PrincipalID,
		OrgID:       orgID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(g.sessionTTL),
		LastUsedAt:  now,
		UserAgent:   r.UserAgent(),
		IPAddress:   httpmiddleware.ClientIPFromContext(r.Context()),
	}

	if err := g.stores.Sessions.Create(ctx, session); err != nil {
		log.Error().Err(err).Msg("Failed to create session in store")
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	log.Debug().
		Str("session_id", sessionID.String()).
		Str("principal_id", principal.PrincipalID.String()).
		Msg("Session created")

	// Store only the session ID in the cookie
	sessionCookie := &http.Cookie{
		Name:     "_session",
		Value:    sessionID.String(),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(g.sessionTTL.Seconds()),
	}
	http.SetCookie(w, sessionCookie)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// getOrCreatePrincipal finds an existing principal by GitHub ID or creates a new one.
// On first login, it also creates a new organization using the GitHub username.
func (g *Github) getOrCreatePrincipal(ctx context.Context, githubID string, userInfo *UserInfo) (*models.Principal, uuid.UUID, error) {
	// Try to find existing principal
	principal, err := g.stores.Principals.GetByGitHubID(ctx, githubID)
	if err == nil {
		// Found existing principal - update with latest GitHub info
		principal.Name = userInfo.Name
		principal.Email = &userInfo.Email
		principal.AvatarURL = &userInfo.AvatarURL
		principal.GitHubLogin = &userInfo.Login

		if err = g.stores.Principals.Update(ctx, principal); err != nil {
			log.Warn().Err(err).Msg("Failed to update principal with latest GitHub info")
			// Non-fatal - continue with existing data
		}

		// Update last used timestamp
		if err = g.stores.Principals.UpdateLastUsed(ctx, principal.PrincipalID); err != nil {
			log.Warn().Err(err).Msg("Failed to update last used timestamp")
		}

		return principal, principal.OrgID, nil
	}

	if !errors.Is(err, store.ErrPrincipalNotFound) {
		return nil, uuid.Nil, fmt.Errorf("failed to lookup principal: %w", err)
	}

	// First login - create new org and principal
	log.Info().
		Str("github_id", githubID).
		Str("login", userInfo.Login).
		Msg("First login - creating organization and principal")

	now := time.Now()

	// Create organization using GitHub username
	orgID, err := uuid.NewV7()
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to generate org ID: %w", err)
	}

	principalID, err := uuid.NewV7()
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to generate principal ID: %w", err)
	}

	// Create org first (with placeholder owner, will update after principal creation)
	org := &models.Organization{
		OrgID:            orgID,
		Name:             userInfo.Login, // Use GitHub username as org name
		OwnerPrincipalID: principalID,    // Set owner to the principal we're about to create
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := g.stores.Organizations.Create(ctx, org); err != nil {
		return nil, uuid.Nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Create principal
	principal = &models.Principal{
		PrincipalID: principalID,
		OrgID:       orgID,
		Type:        models.PrincipalTypeUser,
		Name:        userInfo.Name,
		GitHubID:    &githubID,
		GitHubLogin: &userInfo.Login,
		Email:       &userInfo.Email,
		AvatarURL:   &userInfo.AvatarURL,
		Roles:       []string{"admin", "user"}, // First user is admin
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := g.stores.Principals.Create(ctx, principal); err != nil {
		// Try to clean up the org we just created
		_ = g.stores.Organizations.Delete(ctx, orgID)
		return nil, uuid.Nil, fmt.Errorf("failed to create principal: %w", err)
	}

	log.Info().
		Str("org_id", orgID.String()).
		Str("org_name", org.Name).
		Str("principal_id", principalID.String()).
		Msg("Created new organization and principal")

	return principal, orgID, nil
}

// LogoutHandler handles user logout by deleting the session from the store and clearing the cookie.
func (g *Github) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Try to get session ID from cookie to delete from store
	if cookie, err := r.Cookie("_session"); err == nil {
		if sessionID, err := uuid.Parse(cookie.Value); err == nil {
			if err := g.stores.Sessions.Delete(r.Context(), sessionID); err != nil {
				log.Warn().Err(err).Str("session_id", sessionID.String()).Msg("Failed to delete session from store")
			} else {
				log.Info().Str("session_id", sessionID.String()).Msg("Session deleted")
			}
		}
	}

	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete the cookie
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func (g *Github) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return g.config.Exchange(ctx, code)
}

func (g *Github) getUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	// Add timeout to prevent hanging on slow GitHub API
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	// Validate HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// If email is not available from /user endpoint, fetch from /user/emails
	if userInfo.Email == "" {
		emails, err := g.getUserEmails(ctx, token)
		if err != nil {
			return nil, err
		}
		// Get the primary email
		for _, email := range emails {
			if email.Primary {
				userInfo.Email = email.Email
				break
			}
		}
	}

	return &userInfo, nil
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (g *Github) getUserEmails(ctx context.Context, token *oauth2.Token) ([]githubEmail, error) {
	// Add timeout to prevent hanging on slow GitHub API
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user emails: %w", err)
	}
	defer resp.Body.Close()

	// Validate HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d for emails endpoint", resp.StatusCode)
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, fmt.Errorf("failed to decode user emails: %w", err)
	}

	return emails, nil
}

type UserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"` // GitHub username
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"` // GitHub avatar URL
}
