package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testSessionSecret = []byte("test-secret-key-min-32bytes-long")

func TestGithub_saveState(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	state := gh.saveState(w, r)

	// Verify state is not empty
	require.NotEmpty(t, state, "state should not be empty")

	// Verify state has reasonable length (crypto/rand.Text() should generate a reasonably long string)
	require.Greater(t, len(state), 10, "state should be a reasonably long random string")

	// Verify cookie was set
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1, "should set exactly one cookie")

	cookie := cookies[0]
	require.Equal(t, "state", cookie.Name)
	require.Equal(t, state, cookie.Value)
	require.True(t, cookie.HttpOnly, "cookie should be HttpOnly")
	require.True(t, cookie.Secure, "cookie should be Secure")
}

func TestGithub_saveState_randomness(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	// Generate multiple states and verify they're different
	states := make(map[string]bool)
	for range 10 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		state := gh.saveState(w, r)
		states[state] = true
	}

	// All states should be unique
	require.Len(t, states, 10, "all generated states should be unique")
}

func TestGithub_LoginHandler(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)

	gh.LoginHandler(w, r)

	// Should redirect to GitHub
	require.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	require.Contains(t, location, "github.com/login/oauth/authorize")
	require.Contains(t, location, "client_id=test-client-id")
	require.Contains(t, location, "scope=user%3Aemail")

	// Should set state cookie
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "state", cookies[0].Name)
}

func TestGithub_CallbackHandler_invalidRequest(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name  string
		state string
		code  string
	}{
		{"missing state", "", "some-code"},
		{"missing code", "some-state", ""},
		{"missing both", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/callback?state="+tt.state+"&code="+tt.code, nil)

			gh.CallbackHandler(w, r)

			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), "Authentication failed")
		})
	}
}

func TestGithub_CallbackHandler_missingStateCookie(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/callback?state=some-state&code=some-code", nil)

	gh.CallbackHandler(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Authentication failed")
}

func TestGithub_CallbackHandler_stateMismatch(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/callback?state=wrong-state&code=some-code", nil)
	r.AddCookie(&http.Cookie{
		Name:  "state",
		Value: "correct-state",
	})

	gh.CallbackHandler(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Authentication failed")
}

func TestNewGithub(t *testing.T) {
	clientID := "test-client-id"
	clientSecret := "test-secret"
	callbackURL := "http://localhost/callback"

	sessionTTL := 24 * time.Hour
	gh, err := NewGithub(clientID, clientSecret, callbackURL, testSessionSecret, sessionTTL)
	require.NoError(t, err)

	require.NotNil(t, gh)
	require.NotNil(t, gh.config)
	require.Equal(t, clientID, gh.config.ClientID)
	require.Equal(t, clientSecret, gh.config.ClientSecret)
	require.Equal(t, callbackURL, gh.config.RedirectURL)
	require.Equal(t, []string{"user:email"}, gh.config.Scopes)
	require.Equal(t, testSessionSecret, gh.sessionSecret)
	require.Equal(t, sessionTTL, gh.sessionTTL)
}

func TestGithub_createSessionToken(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := 1 * time.Hour

	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Token should contain two parts separated by a dot
	parts := len(token) > 0
	require.True(t, parts)
	require.Contains(t, token, ".")
}

func TestGithub_validateSessionToken(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := 1 * time.Hour

	// Create a valid token
	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	// Validate it
	session, err := gh.validateSessionToken(token)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.Equal(t, email, session.Email)
	require.Equal(t, name, session.Name)
	require.False(t, session.IssuedAt.IsZero())
	require.False(t, session.ExpiresAt.IsZero())
}

func TestGithub_validateSessionToken_tampered(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := 1 * time.Hour

	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	// Tamper with the token
	tamperedToken := token + "x"

	// Should fail validation
	session, err := gh.validateSessionToken(tamperedToken)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrInvalidSession, err)
}

func TestGithub_validateSessionToken_wrongSecret(t *testing.T) {
	gh1, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)
	gh2, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", []byte("different-secret-key-min-32bytes"), 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := 1 * time.Hour

	// Create token with gh1
	token, err := gh1.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	// Try to validate with gh2 (different secret)
	session, err := gh2.validateSessionToken(token)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrInvalidSession, err)
}

func TestGithub_validateSessionToken_expired(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := -1 * time.Hour // Already expired

	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	// Should fail due to expiration
	session, err := gh.validateSessionToken(token)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrExpiredSession, err)
}

func TestGithub_GetSession(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := 1 * time.Hour

	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	// Create a request with the session cookie
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: token,
	})

	// Get session from request
	session, err := gh.GetSession(r)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.Equal(t, email, session.Email)
	require.Equal(t, name, session.Name)
}

func TestGithub_GetSession_noCookie(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Should fail when no cookie present
	session, err := gh.GetSession(r)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrInvalidSession, err)
}

func TestGithub_RequireAuth_validSession(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := 1 * time.Hour

	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	// Create a protected handler
	var handlerCalled bool
	var sessionInContext *SessionData
	protectedHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Capture session from context for verification
		session, ok := SessionFromContext(r.Context())
		if !ok {
			http.Error(w, "no session in context", http.StatusInternalServerError)
			return
		}
		sessionInContext = session

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}

	// Wrap with RequireAuth middleware
	middleware := gh.RequireAuth("/")
	handler := middleware(protectedHandler)

	// Create request with valid session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: token,
	})

	handler(w, r)

	// Should call the handler
	require.True(t, handlerCalled, "protected handler should be called")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "success", w.Body.String())

	// Verify session was in context
	require.NotNil(t, sessionInContext)
	require.Equal(t, email, sessionInContext.Email)
	require.Equal(t, name, sessionInContext.Name)
}

func TestGithub_RequireAuth_invalidSession(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	handlerCalled := false
	protectedHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}

	middleware := gh.RequireAuth("/")
	handler := middleware(protectedHandler)

	// Create request with invalid session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: "invalid-token",
	})

	handler(w, r)

	// Should redirect and not call handler
	require.False(t, handlerCalled, "protected handler should not be called")
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?error_code=invalid", w.Header().Get("Location"))
}

func TestGithub_RequireAuth_noSession(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	handlerCalled := false
	protectedHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}

	middleware := gh.RequireAuth("/login")
	handler := middleware(protectedHandler)

	// Create request without session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)

	handler(w, r)

	// Should redirect and not call handler
	require.False(t, handlerCalled, "protected handler should not be called")
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/login?error_code=invalid", w.Header().Get("Location"))
}

func TestGithub_RequireAuth_expiredSession(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	email := "test@example.com"
	name := "Test User"
	ttl := -1 * time.Hour // Already expired

	token, err := gh.createSessionToken(email, name, ttl)
	require.NoError(t, err)

	handlerCalled := false
	protectedHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}

	middleware := gh.RequireAuth("/")
	handler := middleware(protectedHandler)

	// Create request with expired session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: token,
	})

	handler(w, r)

	// Should redirect with expired error code
	require.False(t, handlerCalled, "protected handler should not be called")
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?error_code=expired", w.Header().Get("Location"))
}

func TestSessionFromContext_notPresent(t *testing.T) {
	ctx := context.Background()

	session, ok := SessionFromContext(ctx)
	require.False(t, ok, "session should not be present")
	require.Nil(t, session)
}

func TestGithub_LogoutHandler(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	// Create a valid session token
	email := "test@example.com"
	name := "Test User"
	token, err := gh.createSessionToken(email, name, 1*time.Hour)
	require.NoError(t, err)

	// Create request with session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: token,
	})

	// Call logout handler
	gh.LogoutHandler(w, r)

	// Should redirect to home page
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/", w.Header().Get("Location"))

	// Should clear the session cookie
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "_session", cookies[0].Name)
	require.Empty(t, cookies[0].Value)
	require.Equal(t, -1, cookies[0].MaxAge)
}

func TestGithub_LogoutHandler_noSession(t *testing.T) {
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", testSessionSecret, 24*time.Hour)
	require.NoError(t, err)

	// Create request without session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)

	// Call logout handler
	gh.LogoutHandler(w, r)

	// Should still redirect to home page
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/", w.Header().Get("Location"))

	// Should still set the delete cookie (defensive)
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "_session", cookies[0].Name)
	require.Equal(t, -1, cookies[0].MaxAge)
}
