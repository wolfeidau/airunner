package login

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	ErrInvalidSession = errors.New("invalid session")
	ErrExpiredSession = errors.New("session expired")
)

type contextKey string

const sessionContextKey contextKey = "session"

type Github struct {
	config        *oauth2.Config
	sessionSecret []byte
}

func NewGithub(clientID, clientSecret, callbackURL string, sessionSecret []byte) *Github {
	return &Github{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		},
		sessionSecret: sessionSecret,
	}
}

// SessionData holds the authenticated user's session information
type SessionData struct {
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// createSessionToken creates an HMAC-signed session token
func (g *Github) createSessionToken(email, name string, ttl time.Duration) (string, error) {
	session := SessionData{
		Email:     email,
		Name:      name,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}

	// JSON encode the session data
	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session: %w", err)
	}

	// Base64 encode the data
	encoded := base64.URLEncoding.EncodeToString(data)

	// Create HMAC signature
	mac := hmac.New(sha256.New, g.sessionSecret)
	mac.Write([]byte(encoded))
	signature := mac.Sum(nil)

	// Return encoded_data.hex(signature)
	return encoded + "." + base64.URLEncoding.EncodeToString(signature), nil
}

// validateSessionToken validates and extracts the session data from an HMAC-signed token
func (g *Github) validateSessionToken(token string) (*SessionData, error) {
	// Split token into data and signature
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidSession
	}

	encoded := parts[0]
	receivedSig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidSession
	}

	// Verify HMAC signature using constant-time comparison
	mac := hmac.New(sha256.New, g.sessionSecret)
	mac.Write([]byte(encoded))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(receivedSig, expectedSig) {
		return nil, ErrInvalidSession
	}

	// Decode the data
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidSession
	}

	// Unmarshal session data
	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, ErrInvalidSession
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrExpiredSession
	}

	return &session, nil
}

// GetSession extracts and validates the session from a request
func (g *Github) GetSession(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie("_session")
	if err != nil {
		return nil, ErrInvalidSession
	}

	return g.validateSessionToken(cookie.Value)
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
				}

				// Redirect to the specified URL with error code
				http.Redirect(w, r, redirectURL+"?error_code="+errorCode, http.StatusFound)
				return
			}

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
	}
	http.SetCookie(w, cookie)

	return state
}

func (g *Github) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state := g.saveState(w, r)

	// redirect to github
	http.Redirect(w, r, g.config.AuthCodeURL(state), http.StatusFound)
}

func (g *Github) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")

	if state == "" || code == "" {
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	if state != cookie.Value {
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

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
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	// get user info
	userInfo, err := g.getUserInfo(r.Context(), token)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	// Verify we got an email
	if userInfo.Email == "" {
		http.Error(w, "Email address required", http.StatusBadRequest)
		return
	}

	// Create HMAC-signed session token
	sessionTTL := 7 * 24 * time.Hour // 7 days
	sessionToken, err := g.createSessionToken(userInfo.Email, userInfo.Name, sessionTTL)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Store the signed token in a session cookie
	session := &http.Cookie{
		Name:     "_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	}
	http.SetCookie(w, session)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (g *Github) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return g.config.Exchange(ctx, code)
}

func (g *Github) getUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
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
	client := g.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, err
	}

	return emails, nil
}

type UserInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}
