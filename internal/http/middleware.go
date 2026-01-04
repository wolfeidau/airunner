package http

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const clientIPContextKey contextKey = "client_ip"

// ExtractClientIP extracts the client IP address from the request.
// Checks X-Forwarded-For header first (for proxied requests), then X-Real-IP, finally RemoteAddr.
func ExtractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list (comma-separated)
		if before, _, ok := strings.Cut(xff, ","); ok {
			return before
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr, stripping port
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// ClientIPFromContext extracts the client IP from the request context.
// This should be called from handlers wrapped by ClientIPMiddleware.
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPContextKey).(string)
	return ip
}

// ClientIPMiddleware is a middleware that extracts and stores the client IP in the request context.
// This allows the IP to be used in session creation and audit logging.
func ClientIPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ExtractClientIP(r)
			ctx := context.WithValue(r.Context(), clientIPContextKey, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
