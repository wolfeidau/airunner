package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store/memory"
)

// createTestStores creates memory stores for testing
func createTestStores() Stores {
	return Stores{
		Sessions:      memory.NewSessionStore(),
		Principals:    memory.NewPrincipalStore(),
		Organizations: memory.NewOrganizationStore(),
	}
}

// createTestSession creates a test session in the stores and returns the session ID
func createTestSession(t *testing.T, stores Stores, principalName, email string) uuid.UUID {
	ctx := context.Background()
	now := time.Now()

	// Create org
	orgID, err := uuid.NewV7()
	require.NoError(t, err)

	principalID, err := uuid.NewV7()
	require.NoError(t, err)

	org := &models.Organization{
		OrgID:            orgID,
		Name:             "test-org",
		OwnerPrincipalID: principalID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	err = stores.Organizations.Create(ctx, org)
	require.NoError(t, err)

	// Create principal
	principal := &models.Principal{
		PrincipalID: principalID,
		OrgID:       orgID,
		Type:        models.PrincipalTypeUser,
		Name:        principalName,
		Email:       &email,
		Roles:       []string{"user"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = stores.Principals.Create(ctx, principal)
	require.NoError(t, err)

	// Create session
	sessionID, err := uuid.NewV7()
	require.NoError(t, err)

	session := &models.Session{
		SessionID:   sessionID,
		PrincipalID: principalID,
		OrgID:       orgID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(1 * time.Hour),
		LastUsedAt:  now,
	}
	err = stores.Sessions.Create(ctx, session)
	require.NoError(t, err)

	return sessionID
}

// createExpiredTestSession creates an expired session for testing
func createExpiredTestSession(t *testing.T, stores Stores) uuid.UUID {
	ctx := context.Background()
	now := time.Now()

	// Create org
	orgID, err := uuid.NewV7()
	require.NoError(t, err)

	principalID, err := uuid.NewV7()
	require.NoError(t, err)

	org := &models.Organization{
		OrgID:            orgID,
		Name:             "test-org",
		OwnerPrincipalID: principalID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	err = stores.Organizations.Create(ctx, org)
	require.NoError(t, err)

	// Create principal
	principal := &models.Principal{
		PrincipalID: principalID,
		OrgID:       orgID,
		Type:        models.PrincipalTypeUser,
		Name:        "Test User",
		Roles:       []string{"user"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err = stores.Principals.Create(ctx, principal)
	require.NoError(t, err)

	// Create expired session
	sessionID, err := uuid.NewV7()
	require.NoError(t, err)

	session := &models.Session{
		SessionID:   sessionID,
		PrincipalID: principalID,
		OrgID:       orgID,
		CreatedAt:   now.Add(-2 * time.Hour),
		ExpiresAt:   now.Add(-1 * time.Hour), // Expired
		LastUsedAt:  now.Add(-2 * time.Hour),
	}
	err = stores.Sessions.Create(ctx, session)
	require.NoError(t, err)

	return sessionID
}

func TestNewGithub(t *testing.T) {
	stores := createTestStores()

	gh, err := NewGithub("test-client-id", "test-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	require.NotNil(t, gh)
	require.NotNil(t, gh.config)
	require.Equal(t, "test-client-id", gh.config.ClientID)
	require.Equal(t, "test-secret", gh.config.ClientSecret)
	require.Equal(t, "http://localhost/callback", gh.config.RedirectURL)
	require.Equal(t, []string{"user:email"}, gh.config.Scopes)
	require.Equal(t, 24*time.Hour, gh.sessionTTL)
}

func TestNewGithub_MissingStores(t *testing.T) {
	_, err := NewGithub("test-client-id", "test-secret", "http://localhost/callback", Stores{}, 24*time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "all stores")
}

func TestNewGithub_MissingCredentials(t *testing.T) {
	stores := createTestStores()

	_, err := NewGithub("", "test-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "client ID")
}

func TestGithub_saveState(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	state := gh.saveState(w, r)

	// Verify state is not empty
	require.NotEmpty(t, state)
	require.Greater(t, len(state), 10)

	// Verify cookie was set
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	cookie := cookies[0]
	require.Equal(t, "state", cookie.Name)
	require.Equal(t, state, cookie.Value)
	require.True(t, cookie.HttpOnly)
	require.True(t, cookie.Secure)
}

func TestGithub_saveState_randomness(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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
	require.Len(t, states, 10)
}

func TestGithub_LoginHandler(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/callback?state=some-state&code=some-code", nil)

	gh.CallbackHandler(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "Authentication failed")
}

func TestGithub_CallbackHandler_stateMismatch(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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

func TestGithub_GetSession(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	// Create a test session
	sessionID := createTestSession(t, stores, "Test User", "test@example.com")

	// Create request with session cookie
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: sessionID.String(),
	})

	// Get session from request
	session, err := gh.GetSession(r)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.Equal(t, sessionID, session.SessionID)
	require.Equal(t, "Test User", session.Name)
	require.Equal(t, "test@example.com", session.Email)
}

func TestGithub_GetSession_noCookie(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	session, err := gh.GetSession(r)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrInvalidSession, err)
}

func TestGithub_GetSession_invalidSessionID(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: "not-a-uuid",
	})

	session, err := gh.GetSession(r)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrInvalidSession, err)
}

func TestGithub_GetSession_sessionNotFound(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	// Use a valid UUID that doesn't exist in the store
	nonExistentID, _ := uuid.NewV7()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: nonExistentID.String(),
	})

	session, err := gh.GetSession(r)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrInvalidSession, err)
}

func TestGithub_GetSession_expired(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	// Create an expired session
	sessionID := createExpiredTestSession(t, stores)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: sessionID.String(),
	})

	session, err := gh.GetSession(r)
	require.Error(t, err)
	require.Nil(t, session)
	require.Equal(t, ErrExpiredSession, err)
}

func TestGithub_RequireAuth_validSession(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	sessionID := createTestSession(t, stores, "Test User", "test@example.com")

	// Create a protected handler
	var handlerCalled bool
	var sessionInContext *SessionData
	protectedHandler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

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
		Value: sessionID.String(),
	})

	handler(w, r)

	// Should call the handler
	require.True(t, handlerCalled)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "success", w.Body.String())

	// Verify session was in context
	require.NotNil(t, sessionInContext)
	require.Equal(t, sessionID, sessionInContext.SessionID)
	require.Equal(t, "Test User", sessionInContext.Name)
}

func TestGithub_RequireAuth_invalidSession(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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
		Value: "invalid-session-id",
	})

	handler(w, r)

	// Should redirect and not call handler
	require.False(t, handlerCalled)
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?error_code=invalid", w.Header().Get("Location"))
}

func TestGithub_RequireAuth_noSession(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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
	require.False(t, handlerCalled)
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/login?error_code=invalid", w.Header().Get("Location"))
}

func TestGithub_RequireAuth_expiredSession(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	sessionID := createExpiredTestSession(t, stores)

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
		Value: sessionID.String(),
	})

	handler(w, r)

	// Should redirect with expired error code
	require.False(t, handlerCalled)
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "/?error_code=expired", w.Header().Get("Location"))
}

func TestSessionFromContext_notPresent(t *testing.T) {
	ctx := context.Background()

	session, ok := SessionFromContext(ctx)
	require.False(t, ok)
	require.Nil(t, session)
}

func TestGithub_LogoutHandler(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	// Create a valid session
	sessionID := createTestSession(t, stores, "Test User", "test@example.com")

	// Create request with session cookie
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_session",
		Value: sessionID.String(),
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

	// Session should be deleted from store
	_, err = stores.Sessions.Get(context.Background(), sessionID)
	require.Error(t, err)
}

func TestGithub_LogoutHandler_noSession(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
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

func TestGithub_getOrCreatePrincipal_newUser(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	githubID := "12345"
	userInfo := &UserInfo{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		Name:      "Test User",
		AvatarURL: "https://github.com/avatars/12345",
	}

	principal, orgID, err := gh.getOrCreatePrincipal(ctx, githubID, userInfo)
	require.NoError(t, err)
	require.NotNil(t, principal)
	require.NotEqual(t, uuid.Nil, orgID)

	// Verify principal was created correctly
	require.Equal(t, "Test User", principal.Name)
	require.Equal(t, &githubID, principal.GitHubID)
	require.Equal(t, &userInfo.Login, principal.GitHubLogin)
	require.Equal(t, &userInfo.Email, principal.Email)
	require.Contains(t, principal.Roles, "admin") // First user is admin

	// Verify org was created with GitHub username
	org, err := stores.Organizations.Get(ctx, orgID)
	require.NoError(t, err)
	require.Equal(t, "testuser", org.Name)
	require.Equal(t, principal.PrincipalID, org.OwnerPrincipalID)
}

func TestGithub_getOrCreatePrincipal_existingUser(t *testing.T) {
	stores := createTestStores()
	gh, err := NewGithub("test-client-id", "test-client-secret", "http://localhost/callback", stores, 24*time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	githubID := "12345"
	userInfo := &UserInfo{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		Name:      "Test User",
		AvatarURL: "https://github.com/avatars/12345",
	}

	// First call creates the principal
	principal1, orgID1, err := gh.getOrCreatePrincipal(ctx, githubID, userInfo)
	require.NoError(t, err)

	// Update user info
	userInfo.Name = "Updated Name"
	userInfo.Email = "updated@example.com"

	// Second call should find existing principal and update it
	principal2, orgID2, err := gh.getOrCreatePrincipal(ctx, githubID, userInfo)
	require.NoError(t, err)

	// Should be the same principal
	require.Equal(t, principal1.PrincipalID, principal2.PrincipalID)
	require.Equal(t, orgID1, orgID2)

	// Should have updated info
	require.Equal(t, "Updated Name", principal2.Name)
	require.Equal(t, "updated@example.com", *principal2.Email)
}
