package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractClientIP_xForwardedFor(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "single IP",
			header:   "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "multiple IPs (take first)",
			header:   "203.0.113.1, 198.51.100.1",
			expected: "203.0.113.1",
		},
		{
			name:     "multiple IPs no spaces",
			header:   "203.0.113.1,198.51.100.1",
			expected: "203.0.113.1",
		},
		{
			name:     "multiple IPs with extra spaces",
			header:   "203.0.113.1  ,  198.51.100.1",
			expected: "203.0.113.1  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("X-Forwarded-For", tt.header)

			ip := ExtractClientIP(r)
			require.Equal(t, tt.expected, ip)
		})
	}
}

func TestExtractClientIP_xRealIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Real-IP", "192.168.1.100")

	ip := ExtractClientIP(r)
	require.Equal(t, "192.168.1.100", ip)
}

func TestExtractClientIP_xForwardedForTakesPreference(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")
	r.Header.Set("X-Real-IP", "192.168.1.100")

	ip := ExtractClientIP(r)
	// X-Forwarded-For should take precedence
	require.Equal(t, "203.0.113.1", ip)
}

func TestExtractClientIP_remoteAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{
			name:       "IPv4 with port",
			remoteAddr: "192.168.1.1:54321",
			expected:   "192.168.1.1",
		},
		{
			name:       "IPv6 with port",
			remoteAddr: "[2001:db8::1]:54321",
			expected:   "[2001:db8::1]",
		},
		{
			name:       "no port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr

			ip := ExtractClientIP(r)
			require.Equal(t, tt.expected, ip)
		})
	}
}

func TestClientIPMiddleware(t *testing.T) {
	middleware := ClientIPMiddleware()

	var capturedIP string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP = ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.1")

	handler.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "203.0.113.1", capturedIP)
}

func TestClientIPFromContext_missing(t *testing.T) {
	ctx := context.Background()

	ip := ClientIPFromContext(ctx)
	require.Empty(t, ip)
}
