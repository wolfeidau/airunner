package client

import (
	"net/http"

	"github.com/gregjones/httpcache"
	"github.com/gregjones/httpcache/diskcache"
)

// NewCachingHTTPClient creates an HTTP client with disk-based caching.
// This is used for Connect RPC clients that call cacheable endpoints
// (e.g., PrincipalService.GetPublicKey with Cache-Control headers).
func NewCachingHTTPClient(cacheDir string) *http.Client {
	if cacheDir == "" {
		// Use in-memory cache if no cache directory specified
		return &http.Client{
			Transport: httpcache.NewTransport(httpcache.NewMemoryCache()),
		}
	}

	// Use disk-based cache for persistence across restarts
	cache := diskcache.New(cacheDir)
	transport := httpcache.NewTransport(cache)

	return &http.Client{
		Transport: transport,
	}
}

// NewInMemoryCachingHTTPClient creates an HTTP client with in-memory caching only.
// Suitable for testing or when disk caching is not desired.
func NewInMemoryCachingHTTPClient() *http.Client {
	return &http.Client{
		Transport: httpcache.NewTransport(httpcache.NewMemoryCache()),
	}
}
