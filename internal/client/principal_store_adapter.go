package client

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	principalv1 "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// PrincipalStoreAdapter adapts a PrincipalService RPC client to implement store.PrincipalStore.
// This allows the API server to use the RPC client for fetching worker public keys
// without direct database access.
//
// NOTE: Only GetByFingerprint is implemented - all other methods return errors.
// This adapter is specifically for JWT verification in the API server.
type PrincipalStoreAdapter struct {
	client principalv1connect.PrincipalServiceClient
}

// NewPrincipalStoreAdapter creates a new adapter that implements store.PrincipalStore.
func NewPrincipalStoreAdapter(client principalv1connect.PrincipalServiceClient) *PrincipalStoreAdapter {
	return &PrincipalStoreAdapter{
		client: client,
	}
}

// GetByFingerprint fetches a principal by fingerprint via the PrincipalService RPC.
func (a *PrincipalStoreAdapter) GetByFingerprint(ctx context.Context, fingerprint string) (*models.Principal, error) {
	req := connect.NewRequest(&principalv1.GetPublicKeyRequest{
		Fingerprint: fingerprint,
	})

	resp, err := a.client.GetPublicKey(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, store.ErrPrincipalNotFound
		}
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse UUID from string
	orgID, err := uuid.Parse(resp.Msg.OrgId)
	if err != nil {
		return nil, fmt.Errorf("invalid org_id: %w", err)
	}

	// Return minimal principal with public key
	return &models.Principal{
		Fingerprint: resp.Msg.Fingerprint,
		PublicKey:   resp.Msg.PublicKeyPem,
		OrgID:       orgID,
		Type:        "worker", // Assumed from fingerprint lookup
	}, nil
}

// Unimplemented methods (not needed for JWT verification)

func (a *PrincipalStoreAdapter) Create(ctx context.Context, principal *models.Principal) error {
	return errors.New("Create not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) Get(ctx context.Context, principalID uuid.UUID) (*models.Principal, error) {
	return nil, errors.New("Get not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) GetByGitHubID(ctx context.Context, githubID string) (*models.Principal, error) {
	return nil, errors.New("GetByGitHubID not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) Update(ctx context.Context, principal *models.Principal) error {
	return errors.New("Update not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) Delete(ctx context.Context, principalID uuid.UUID) error {
	return errors.New("Delete not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) ListByOrg(ctx context.Context, orgID uuid.UUID, principalType *string) ([]*models.Principal, error) {
	return nil, errors.New("ListByOrg not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) ListRevoked(ctx context.Context) ([]*models.Principal, error) {
	return nil, errors.New("ListRevoked not supported on RPC adapter")
}

func (a *PrincipalStoreAdapter) UpdateLastUsed(ctx context.Context, principalID uuid.UUID) error {
	return errors.New("UpdateLastUsed not supported on RPC adapter")
}
