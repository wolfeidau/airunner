//go:build integration

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	principalv1connect "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/server"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/website/oidc"
)

// createPool creates a PostgreSQL connection pool
func createPool(t *testing.T, ctx context.Context, connString string) *pgxpool.Pool {
	poolConfig, err := pgxpool.ParseConfig(connString)
	require.NoError(t, err)

	poolConfig.MaxConns = 5
	poolConfig.MinConns = 1

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	require.NoError(t, err)

	return pool
}

// setupPostgresForAuth sets up a PostgreSQL container with migrations
func setupPostgresForAuth(t *testing.T, ctx context.Context) (string, func()) {
	req := testcontainers.ContainerRequest{
		Image:        "postgres:18-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	connString := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())

	// Run migrations using JobStore
	jobStoreCfg := &postgres.JobStoreConfig{
		ConnString:         connString,
		TokenSigningSecret: []byte("test-secret-key-min-32-bytes-long"),
		AutoMigrate:        true,
	}

	jobStore, err := postgres.NewJobStore(ctx, jobStoreCfg)
	require.NoError(t, err)
	jobStore.Stop()

	cleanup := func() {
		_ = container.Terminate(ctx)
	}

	return connString, cleanup
}

// createTestOrgAndPrincipal creates a test organization and user principal
func createTestOrgAndPrincipal(t *testing.T, ctx context.Context, connString string) (uuid.UUID, uuid.UUID) {
	pool := createPool(t, ctx, connString)
	defer pool.Close()

	orgStore := postgres.NewOrganizationStore(pool)
	principalStore := postgres.NewPrincipalStore(pool)

	// Create organization
	orgID, err := uuid.NewV7()
	require.NoError(t, err)

	placeholderPrincipalID, err := uuid.NewV7()
	require.NoError(t, err)

	org := &models.Organization{
		OrgID:            orgID,
		Name:             "Test Organization",
		OwnerPrincipalID: placeholderPrincipalID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	err = orgStore.Create(ctx, org)
	require.NoError(t, err)

	// Create user principal
	principalID, err := uuid.NewV7()
	require.NoError(t, err)

	githubID := "test-github-123"
	principal := &models.Principal{
		PrincipalID: principalID,
		OrgID:       orgID,
		Type:        "user",
		Name:        "Test User",
		GitHubID:    &githubID,
		Roles:       []string{"admin", "user"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = principalStore.Create(ctx, principal)
	require.NoError(t, err)

	// Update organization owner
	org.OwnerPrincipalID = principalID
	err = orgStore.Update(ctx, org)
	require.NoError(t, err)

	return orgID, principalID
}

func TestIntegration_OIDCDiscovery(t *testing.T) {
	ctx := context.Background()
	connString, cleanup := setupPostgresForAuth(t, ctx)
	defer cleanup()

	pool := createPool(t, ctx, connString)
	defer pool.Close()

	principalStore := postgres.NewPrincipalStore(pool)

	keyManager, err := oidc.NewKeyManager()
	require.NoError(t, err)

	baseURL := "https://test.airunner.dev"
	handler := oidc.NewHandler(keyManager, principalStore, baseURL)

	t.Run("discovery endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()

		handler.DiscoveryHandler()(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var config map[string]any
		err := json.NewDecoder(w.Body).Decode(&config)
		require.NoError(t, err)

		require.Equal(t, baseURL, config["issuer"])
		require.Equal(t, baseURL+"/.well-known/jwks.json", config["jwks_uri"])
		require.Equal(t, baseURL+"/auth/token", config["token_endpoint"])

		t.Logf("✅ OIDC discovery successful")
	})
}

func TestIntegration_JWKS(t *testing.T) {
	ctx := context.Background()
	connString, cleanup := setupPostgresForAuth(t, ctx)
	defer cleanup()

	pool := createPool(t, ctx, connString)
	defer pool.Close()

	principalStore := postgres.NewPrincipalStore(pool)

	keyManager, err := oidc.NewKeyManager()
	require.NoError(t, err)

	baseURL := "https://test.airunner.dev"
	handler := oidc.NewHandler(keyManager, principalStore, baseURL)

	t.Run("jwks endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		handler.JWKSHandler()(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var jwks map[string]any
		err := json.NewDecoder(w.Body).Decode(&jwks)
		require.NoError(t, err)

		keys, ok := jwks["keys"].([]any)
		require.True(t, ok)
		require.Len(t, keys, 1)

		key := keys[0].(map[string]any)
		require.Equal(t, "EC", key["kty"])
		require.Equal(t, "sig", key["use"])
		require.Equal(t, "P-256", key["crv"])
		require.Equal(t, keyManager.Kid(), key["kid"])
		require.NotEmpty(t, key["x"])
		require.NotEmpty(t, key["y"])

		t.Logf("✅ JWKS endpoint successful - kid: %s", key["kid"])
	})
}

func TestIntegration_TokenIssuance(t *testing.T) {
	ctx := context.Background()
	connString, cleanup := setupPostgresForAuth(t, ctx)
	defer cleanup()

	orgID, principalID := createTestOrgAndPrincipal(t, ctx, connString)

	pool := createPool(t, ctx, connString)
	defer pool.Close()

	principalStore := postgres.NewPrincipalStore(pool)

	keyManager, err := oidc.NewKeyManager()
	require.NoError(t, err)

	baseURL := "https://test.airunner.dev"
	apiBaseURL := "https://api.airunner.dev"
	handler := oidc.NewHandler(keyManager, principalStore, baseURL)

	mockSession := &oidc.Session{PrincipalID: principalID}
	sessionManager := &mockSessionManager{session: mockSession}

	t.Run("token endpoint with valid session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		w := httptest.NewRecorder()

		handler.TokenHandler(sessionManager, apiBaseURL)(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response["access_token"])
		require.Equal(t, "Bearer", response["token_type"])
		require.Equal(t, "3600", response["expires_in"])

		t.Logf("✅ Token issued - Org: %s, Principal: %s", orgID, principalID)
	})

	t.Run("token endpoint without session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
		w := httptest.NewRecorder()

		noSessionManager := &mockSessionManager{session: nil}
		handler.TokenHandler(noSessionManager, apiBaseURL)(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)

		t.Logf("✅ Correctly rejected request without session")
	})
}

func TestIntegration_JWTVerification(t *testing.T) {
	ctx := context.Background()
	connString, cleanup := setupPostgresForAuth(t, ctx)
	defer cleanup()

	orgID, principalID := createTestOrgAndPrincipal(t, ctx, connString)

	pool := createPool(t, ctx, connString)
	defer pool.Close()

	principalStore := postgres.NewPrincipalStore(pool)

	// Create OIDC key manager
	keyManager, err := oidc.NewKeyManager()
	require.NoError(t, err)

	// Create test server FIRST to get the URL
	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	// NOW create OIDC handler with actual test server URL
	oidcHandler := oidc.NewHandler(keyManager, principalStore, testServer.URL)

	// Register OIDC endpoints
	mux.HandleFunc("/.well-known/jwks.json", oidcHandler.JWKSHandler())

	// Issue JWT with test server URL as issuer
	mockSession := &oidc.Session{PrincipalID: principalID}
	sessionManager := &mockSessionManager{session: mockSession}

	tokenReq := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	tokenW := httptest.NewRecorder()
	oidcHandler.TokenHandler(sessionManager, testServer.URL)(tokenW, tokenReq)

	var tokenResponse map[string]string
	err = json.NewDecoder(tokenW.Body).Decode(&tokenResponse)
	require.NoError(t, err)

	jwtToken := tokenResponse["access_token"]

	// Create JWT middleware
	httpClient := &http.Client{Timeout: 5 * time.Second}
	publicKeyCache := NewPublicKeyCache(principalStore, httpClient)

	principalServiceServer := server.NewPrincipalServiceServer(principalStore)
	principalServiceMux := http.NewServeMux()
	path, svcHandler := principalv1connect.NewPrincipalServiceHandler(principalServiceServer)
	principalServiceMux.Handle(path, svcHandler)
	principalServiceTestServer := httptest.NewServer(principalServiceMux)
	defer principalServiceTestServer.Close()

	principalClient := principalv1connect.NewPrincipalServiceClient(httpClient, principalServiceTestServer.URL)
	revocationChecker := NewRevocationChecker(ctx, principalClient, 1*time.Minute)
	defer revocationChecker.Stop()

	// Create JWT verifier with test server URL
	jwtVerifier := NewJWTVerifier(testServer.URL, publicKeyCache, revocationChecker)
	jwtMiddleware := jwtVerifier.Middleware()

	// Test protected endpoint
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFromContext(r.Context())
		require.NotNil(t, principal)

		response := map[string]any{
			"principal_id": principal.PrincipalID.String(),
			"org_id":       principal.OrgID.String(),
			"roles":        principal.Roles,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	handler := jwtMiddleware(protectedHandler)

	t.Run("valid JWT authentication", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err)

		require.Equal(t, principalID.String(), response["principal_id"])
		require.Equal(t, orgID.String(), response["org_id"])

		t.Logf("✅ JWT verification successful")
	})

	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)

		t.Logf("✅ Correctly rejected missing auth header")
	})

	t.Run("invalid JWT token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)

		t.Logf("✅ Correctly rejected invalid JWT")
	})
}

func TestIntegration_EndToEndFlow(t *testing.T) {
	ctx := context.Background()
	connString, cleanup := setupPostgresForAuth(t, ctx)
	defer cleanup()

	orgID, principalID := createTestOrgAndPrincipal(t, ctx, connString)

	pool := createPool(t, ctx, connString)
	defer pool.Close()

	principalStore := postgres.NewPrincipalStore(pool)

	// Setup OIDC provider (website)
	keyManager, err := oidc.NewKeyManager()
	require.NoError(t, err)

	// Create a temporary mux and server to get the URL
	websiteMux := http.NewServeMux()
	websiteServer := httptest.NewServer(websiteMux)
	defer websiteServer.Close()

	// NOW create the OIDC handler with the actual test server URL
	oidcHandler := oidc.NewHandler(keyManager, principalStore, websiteServer.URL)

	// Register OIDC endpoints
	websiteMux.HandleFunc("/.well-known/openid-configuration", oidcHandler.DiscoveryHandler())
	websiteMux.HandleFunc("/.well-known/jwks.json", oidcHandler.JWKSHandler())

	mockSession := &oidc.Session{PrincipalID: principalID}
	sessionManager := &mockSessionManager{session: mockSession}
	websiteMux.HandleFunc("/auth/token", oidcHandler.TokenHandler(sessionManager, websiteServer.URL))

	// Get JWT from website
	tokenReq, err := http.NewRequest(http.MethodPost, websiteServer.URL+"/auth/token", nil)
	require.NoError(t, err)

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)

	var tokenResponse map[string]string
	err = json.Unmarshal(tokenBody, &tokenResponse)
	require.NoError(t, err)

	jwt := tokenResponse["access_token"]
	require.NotEmpty(t, jwt)

	// Setup API server with JWT middleware
	httpClient := &http.Client{Timeout: 5 * time.Second}
	publicKeyCache := NewPublicKeyCache(principalStore, httpClient)

	principalServiceServer := server.NewPrincipalServiceServer(principalStore)
	principalServiceMux := http.NewServeMux()
	path, svcHandler := principalv1connect.NewPrincipalServiceHandler(principalServiceServer)
	principalServiceMux.Handle(path, svcHandler)
	principalServiceTestServer := httptest.NewServer(principalServiceMux)
	defer principalServiceTestServer.Close()

	principalClient := principalv1connect.NewPrincipalServiceClient(httpClient, principalServiceTestServer.URL)
	revocationChecker := NewRevocationChecker(ctx, principalClient, 1*time.Minute)
	defer revocationChecker.Stop()

	// Create JWT verifier and set website URL to match the test server
	jwtVerifier := NewJWTVerifier("", publicKeyCache, revocationChecker)
	jwtVerifier.SetWebsiteURL(websiteServer.URL)
	jwtMiddleware := jwtVerifier.Middleware()

	// API handler
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFromContext(r.Context())
		require.NotNil(t, principal)

		response := map[string]any{
			"message":      "API request successful",
			"principal_id": principal.PrincipalID.String(),
			"org_id":       principal.OrgID.String(),
			"roles":        principal.Roles,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	apiServer := httptest.NewServer(jwtMiddleware(apiHandler))
	defer apiServer.Close()

	// Make authenticated API request
	apiReq, err := http.NewRequest(http.MethodGet, apiServer.URL+"/api/test", nil)
	require.NoError(t, err)
	apiReq.Header.Set("Authorization", "Bearer "+jwt)

	apiResp, err := http.DefaultClient.Do(apiReq)
	require.NoError(t, err)
	defer apiResp.Body.Close()

	require.Equal(t, http.StatusOK, apiResp.StatusCode)

	apiBody, err := io.ReadAll(apiResp.Body)
	require.NoError(t, err)

	var apiResponse map[string]any
	err = json.Unmarshal(apiBody, &apiResponse)
	require.NoError(t, err)

	require.Equal(t, "API request successful", apiResponse["message"])
	require.Equal(t, principalID.String(), apiResponse["principal_id"])
	require.Equal(t, orgID.String(), apiResponse["org_id"])

	t.Logf("✅ End-to-end flow successful!")
	t.Logf("   Org: %s", orgID)
	t.Logf("   Principal: %s", principalID)
	t.Logf("   JWT verified and principal extracted")
}

// mockSessionManager implements oidc.SessionManager for testing
type mockSessionManager struct {
	session *oidc.Session
}

func (m *mockSessionManager) GetSession(r *http.Request) *oidc.Session {
	return m.session
}
