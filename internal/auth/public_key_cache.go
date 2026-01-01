package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/wolfeidau/airunner/internal/store"
)

// PublicKeyCacheImpl implements PublicKeyCache with HTTP caching for JWKS
// and database caching for worker public keys.
type PublicKeyCacheImpl struct {
	principalStore store.PrincipalStore
	httpClient     *http.Client

	// JWKS cache (website keys)
	jwksMu    sync.RWMutex
	jwksCache map[string]*cachedJWKS

	// Worker key cache
	workerKeyMu    sync.RWMutex
	workerKeyCache map[string]*cachedWorkerKey
}

type cachedJWKS struct {
	keys      map[string]*ecdsa.PublicKey // kid → public key
	expiresAt time.Time
}

type cachedWorkerKey struct {
	publicKey *ecdsa.PublicKey
	expiresAt time.Time
}

// NewPublicKeyCache creates a new public key cache.
func NewPublicKeyCache(principalStore store.PrincipalStore, httpClient *http.Client) *PublicKeyCacheImpl {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &PublicKeyCacheImpl{
		principalStore: principalStore,
		httpClient:     httpClient,
		jwksCache:      make(map[string]*cachedJWKS),
		workerKeyCache: make(map[string]*cachedWorkerKey),
	}
}

// GetWebsiteKey fetches the website's public key by kid from the JWKS endpoint.
// Results are cached for 1 hour to reduce HTTP requests.
func (c *PublicKeyCacheImpl) GetWebsiteKey(ctx context.Context, jwksURL, kid string) (*ecdsa.PublicKey, error) {
	// Check cache first
	c.jwksMu.RLock()
	cached, ok := c.jwksCache[jwksURL]
	c.jwksMu.RUnlock()

	if ok && time.Now().Before(cached.expiresAt) {
		if key, ok := cached.keys[kid]; ok {
			log.Debug().Str("kid", kid).Msg("JWKS cache hit")
			return key, nil
		}
	}

	// Cache miss or expired - fetch from JWKS endpoint
	log.Debug().Str("jwks_url", jwksURL).Msg("Fetching JWKS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed: %s", resp.Status)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Parse JWKs and cache
	keys := make(map[string]*ecdsa.PublicKey)
	for _, jwk := range jwks.Keys {
		key, err := parseJWK(jwk)
		if err != nil {
			log.Warn().Err(err).Interface("jwk", jwk).Msg("Failed to parse JWK")
			continue
		}

		kidStr, ok := jwk["kid"].(string)
		if !ok {
			log.Warn().Msg("JWK missing kid")
			continue
		}

		keys[kidStr] = key
	}

	c.jwksMu.Lock()
	c.jwksCache[jwksURL] = &cachedJWKS{
		keys:      keys,
		expiresAt: time.Now().Add(1 * time.Hour),
	}
	c.jwksMu.Unlock()

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid not found in JWKS: %s", kid)
	}

	log.Info().Str("kid", kid).Int("total_keys", len(keys)).Msg("Cached JWKS")
	return key, nil
}

// GetWorkerKey fetches a worker's public key by fingerprint from the cache or database.
// Results are cached for 5 minutes since worker keys rarely change.
func (c *PublicKeyCacheImpl) GetWorkerKey(ctx context.Context, fingerprint string) (*ecdsa.PublicKey, error) {
	// Check cache first
	c.workerKeyMu.RLock()
	cached, ok := c.workerKeyCache[fingerprint]
	c.workerKeyMu.RUnlock()

	if ok && time.Now().Before(cached.expiresAt) {
		log.Debug().Str("fingerprint", fingerprint).Msg("Worker key cache hit")
		return cached.publicKey, nil
	}

	// Cache miss or expired - fetch from database
	log.Debug().Str("fingerprint", fingerprint).Msg("Fetching worker key from database")

	principal, err := c.principalStore.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	publicKey, err := ParsePublicKeyPEM(principal.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Cache for 5 minutes
	c.workerKeyMu.Lock()
	c.workerKeyCache[fingerprint] = &cachedWorkerKey{
		publicKey: publicKey,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	c.workerKeyMu.Unlock()

	log.Info().Str("fingerprint", fingerprint).Msg("Cached worker key")
	return publicKey, nil
}

// parseJWK parses a JWK (JSON Web Key) into an ECDSA public key.
func parseJWK(jwk map[string]any) (*ecdsa.PublicKey, error) {
	kty, ok := jwk["kty"].(string)
	if !ok || kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %v", kty)
	}

	crv, ok := jwk["crv"].(string)
	if !ok || crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %v", crv)
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing y coordinate")
	}

	xBytes, err := decodeBase64URL(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := decodeBase64URL(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: getP256Curve(),
		X:     x,
		Y:     y,
	}, nil
}

// decodeBase64URL decodes a base64url-encoded string (without padding).
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Use base64.RawURLEncoding for decoding (handles both padded and unpadded)
	return base64.RawURLEncoding.DecodeString(s)
}

// getP256Curve returns the P-256 elliptic curve.
func getP256Curve() elliptic.Curve {
	return elliptic.P256()
}
