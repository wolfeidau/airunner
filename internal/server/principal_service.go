package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	principalv1 "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/store"
)

// Verify PrincipalServiceServer implements the handler interface
var _ principalv1connect.PrincipalServiceHandler = &PrincipalServiceServer{}

// PrincipalServiceServer implements the PrincipalService gRPC service.
// This service provides public key lookup and revocation information for API servers
// to verify worker JWTs. All endpoints are public (no authentication required).
type PrincipalServiceServer struct {
	principalStore store.PrincipalStore
}

// NewPrincipalServiceServer creates a new PrincipalService server.
func NewPrincipalServiceServer(principalStore store.PrincipalStore) *PrincipalServiceServer {
	return &PrincipalServiceServer{
		principalStore: principalStore,
	}
}

// GetPublicKey fetches a worker's public key by fingerprint.
// This RPC is idempotent and cacheable - responses include Cache-Control headers
// to enable HTTP caching on the client side.
func (s *PrincipalServiceServer) GetPublicKey(
	ctx context.Context,
	req *connect.Request[principalv1.GetPublicKeyRequest],
) (*connect.Response[principalv1.GetPublicKeyResponse], error) {
	fingerprint := req.Msg.Fingerprint
	if fingerprint == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fingerprint is required"))
	}

	log.Debug().
		Str("fingerprint", fingerprint).
		Msg("GetPublicKey request")

	// Fetch principal from database
	principal, err := s.principalStore.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		if errors.Is(err, store.ErrPrincipalNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("principal not found: %s", fingerprint))
		}
		log.Error().Err(err).Str("fingerprint", fingerprint).Msg("Failed to get principal")
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Build response
	resp := connect.NewResponse(&principalv1.GetPublicKeyResponse{
		Fingerprint:  principal.Fingerprint,
		PublicKeyPem: principal.PublicKey,
		OrgId:        principal.OrgID.String(),
	})

	// Add HTTP cache headers
	// Public keys rarely change, so we can cache aggressively
	resp.Header().Set("Cache-Control", "public, max-age=86400") // 24 hours
	resp.Header().Set("ETag", fmt.Sprintf(`"%s"`, principal.Fingerprint))

	log.Debug().
		Str("fingerprint", fingerprint).
		Str("org_id", principal.OrgID.String()).
		Msg("GetPublicKey success")

	return resp, nil
}

// ListRevokedPrincipals returns all currently revoked fingerprints.
// API servers poll this endpoint periodically (every 5 minutes) to maintain
// an in-memory revocation blocklist.
func (s *PrincipalServiceServer) ListRevokedPrincipals(
	ctx context.Context,
	req *connect.Request[principalv1.ListRevokedPrincipalsRequest],
) (*connect.Response[principalv1.ListRevokedPrincipalsResponse], error) {
	log.Debug().Msg("ListRevokedPrincipals request")

	// Fetch all revoked principals from database
	revoked, err := s.principalStore.ListRevoked(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list revoked principals")
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// Extract fingerprints from revoked principals
	fingerprints := make([]string, 0, len(revoked))
	for _, p := range revoked {
		if p.Fingerprint != "" {
			fingerprints = append(fingerprints, p.Fingerprint)
		}
	}

	resp := connect.NewResponse(&principalv1.ListRevokedPrincipalsResponse{
		Fingerprints: fingerprints,
	})

	// Shorter cache for revocation list (5 minutes)
	// This balances freshness with reducing database load
	resp.Header().Set("Cache-Control", "public, max-age=300")

	log.Debug().
		Int("count", len(fingerprints)).
		Msg("ListRevokedPrincipals success")

	return resp, nil
}
