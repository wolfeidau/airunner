package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/rs/zerolog/log"
	principalv1 "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
)

// Verify CredentialServiceServer implements the handler interface
var _ principalv1connect.CredentialServiceHandler = &CredentialServiceServer{}

// CredentialServiceServer implements the CredentialService gRPC service.
// This service provides credential management for the web UI.
// All endpoints require authentication (session-based or JWT).
type CredentialServiceServer struct {
	principalStore    store.PrincipalStore
	organizationStore store.OrganizationStore
}

// NewCredentialServiceServer creates a new CredentialService server.
func NewCredentialServiceServer(
	principalStore store.PrincipalStore,
	organizationStore store.OrganizationStore,
) *CredentialServiceServer {
	return &CredentialServiceServer{
		principalStore:    principalStore,
		organizationStore: organizationStore,
	}
}

// ImportCredential imports a worker credential from a PEM-encoded public key.
// Creates a new worker principal and stores the public key.
// Requires admin role.
func (s *CredentialServiceServer) ImportCredential(
	ctx context.Context,
	req *connect.Request[principalv1.ImportCredentialRequest],
) (*connect.Response[principalv1.ImportCredentialResponse], error) {
	// Get current user from context
	principal := auth.PrincipalFromContext(ctx)
	if principal == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Require admin role for importing credentials
	if !slices.Contains(principal.Roles, "admin") {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("admin role required"))
	}

	// Validate request
	if req.Msg.Name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("name is required"))
	}
	if req.Msg.PublicKeyPem == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("public_key_pem is required"))
	}

	// Parse and validate the public key
	publicKeyDER, err := parsePublicKeyPEM(req.Msg.PublicKeyPem)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to parse public key PEM")
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid public key PEM: "+err.Error()))
	}

	// Compute fingerprint (Base58-encoded SHA256 of DER)
	hash := sha256.Sum256(publicKeyDER)
	fingerprint := base58.Encode(hash[:])

	// Check if fingerprint already exists
	existing, err := s.principalStore.GetByFingerprint(ctx, fingerprint)
	if err == nil && existing != nil {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("credential with this public key already exists"))
	}
	if err != nil && !errors.Is(err, store.ErrPrincipalNotFound) {
		log.Error().Err(err).Msg("Failed to check for existing credential")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to check for existing credential"))
	}

	// Create principal
	principalID, err := uuid.NewV7()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate principal ID")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate principal ID"))
	}

	now := time.Now()
	newPrincipal := &models.Principal{
		PrincipalID:  principalID,
		OrgID:        principal.OrgID, // Use caller's org
		Type:         models.PrincipalTypeWorker,
		Name:         req.Msg.Name,
		PublicKey:    req.Msg.PublicKeyPem,
		PublicKeyDER: publicKeyDER,
		Fingerprint:  fingerprint,
		Roles:        []string{"worker"}, // Default role for workers
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.principalStore.Create(ctx, newPrincipal); err != nil {
		log.Error().Err(err).Msg("Failed to create principal")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create credential"))
	}

	log.Info().
		Str("principal_id", principalID.String()).
		Str("org_id", principal.OrgID.String()).
		Str("fingerprint", fingerprint).
		Str("name", req.Msg.Name).
		Msg("Imported credential")

	return connect.NewResponse(&principalv1.ImportCredentialResponse{
		PrincipalId: principalID.String(),
		OrgId:       principal.OrgID.String(),
		Roles:       newPrincipal.Roles,
		Fingerprint: fingerprint,
		Name:        newPrincipal.Name,
	}), nil
}

// ListCredentials returns all credentials (principals) for the current user's org.
// Optionally filters by principal type (user, worker, service).
func (s *CredentialServiceServer) ListCredentials(
	ctx context.Context,
	req *connect.Request[principalv1.ListCredentialsRequest],
) (*connect.Response[principalv1.ListCredentialsResponse], error) {
	// Get current user from context
	principal := auth.PrincipalFromContext(ctx)
	if principal == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// List principals for the caller's org
	var typeFilter *string
	if req.Msg.PrincipalType != "" {
		typeFilter = &req.Msg.PrincipalType
	}

	principals, err := s.principalStore.ListByOrg(ctx, principal.OrgID, typeFilter)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list principals")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to list credentials"))
	}

	// Convert to response format
	credentials := make([]*principalv1.Credential, 0, len(principals))
	for _, p := range principals {
		cred := &principalv1.Credential{
			PrincipalId: p.PrincipalID.String(),
			OrgId:       p.OrgID.String(),
			Type:        p.Type,
			Name:        p.Name,
			Fingerprint: p.Fingerprint,
			Roles:       p.Roles,
			CreatedAt:   p.CreatedAt.Format(time.RFC3339),
		}
		if p.LastUsedAt != nil {
			cred.LastUsedAt = p.LastUsedAt.Format(time.RFC3339)
		}
		credentials = append(credentials, cred)
	}

	log.Debug().
		Str("org_id", principal.OrgID.String()).
		Int("count", len(credentials)).
		Msg("ListCredentials success")

	return connect.NewResponse(&principalv1.ListCredentialsResponse{
		Credentials: credentials,
	}), nil
}

// RevokeCredential revokes a credential by principal ID.
// Soft-deletes the principal (sets deleted_at) and adds fingerprint to revocation list.
// Requires admin role.
func (s *CredentialServiceServer) RevokeCredential(
	ctx context.Context,
	req *connect.Request[principalv1.RevokeCredentialRequest],
) (*connect.Response[principalv1.RevokeCredentialResponse], error) {
	// Get current user from context
	currentPrincipal := auth.PrincipalFromContext(ctx)
	if currentPrincipal == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("not authenticated"))
	}

	// Require admin role for revoking credentials
	if !slices.Contains(currentPrincipal.Roles, "admin") {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("admin role required"))
	}

	// Validate request
	if req.Msg.PrincipalId == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("principal_id is required"))
	}

	principalID, err := uuid.Parse(req.Msg.PrincipalId)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid principal_id format"))
	}

	// Fetch the principal to verify ownership and prevent self-revocation
	targetPrincipal, err := s.principalStore.Get(ctx, principalID)
	if err != nil {
		if errors.Is(err, store.ErrPrincipalNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("credential not found"))
		}
		log.Error().Err(err).Msg("Failed to get principal")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to get credential"))
	}

	// Verify the principal belongs to the current user's org
	if targetPrincipal.OrgID != currentPrincipal.OrgID {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("credential belongs to different organization"))
	}

	// Prevent revoking yourself
	if targetPrincipal.PrincipalID == currentPrincipal.PrincipalID {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("cannot revoke your own credential"))
	}

	// Soft-delete the principal (sets deleted_at timestamp)
	if err := s.principalStore.Delete(ctx, principalID); err != nil {
		log.Error().Err(err).Msg("Failed to delete principal")
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to revoke credential"))
	}

	log.Info().
		Str("principal_id", req.Msg.PrincipalId).
		Str("fingerprint", targetPrincipal.Fingerprint).
		Str("revoked_by", currentPrincipal.PrincipalID.String()).
		Msg("Revoked credential")

	return connect.NewResponse(&principalv1.RevokeCredentialResponse{}), nil
}

// parsePublicKeyPEM parses a PEM-encoded ECDSA P-256 public key and returns the DER bytes.
func parsePublicKeyPEM(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("PEM block type must be 'PUBLIC KEY'")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse public key: " + err.Error())
	}

	// Verify it's an ECDSA key
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key must be ECDSA")
	}

	// Verify it's P-256 curve
	if ecdsaPub.Curve.Params().Name != "P-256" {
		return nil, errors.New("public key must use P-256 curve")
	}

	return block.Bytes, nil
}
