package server

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	principalv1 "github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/principal/v1/principalv1connect"
	"github.com/wolfeidau/airunner/internal/store"
)

// Verify CredentialServiceServer implements the handler interface
var _ principalv1connect.CredentialServiceHandler = &CredentialServiceServer{}

// CredentialServiceServer implements the CredentialService gRPC service.
// This service provides credential management for the web UI.
// All endpoints require authentication (session-based).
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

// ImportCredential imports a worker credential from a base58-encoded blob.
// The blob contains the public key and metadata.
// Creates a new worker principal and stores the public key.
func (s *CredentialServiceServer) ImportCredential(
	ctx context.Context,
	req *connect.Request[principalv1.ImportCredentialRequest],
) (*connect.Response[principalv1.ImportCredentialResponse], error) {
	blob := req.Msg.Blob
	if blob == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("blob is required"))
	}

	log.Debug().Msg("ImportCredential request")

	// TODO: Get current user from session/context
	// For MVP, we'll need to extract this from authentication middleware
	// For now, we'll return an error
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("authentication not yet implemented"))

	// TODO: Parse credential blob
	// The credential blob format needs to be defined. It should contain:
	// - Public key (PEM or DER format)
	// - Credential name
	// - Credential type (worker/service)
	//
	// Example parsing (to be implemented):
	// credentialData, err := parseCredentialBlob(blob)
	// if err != nil {
	//     return nil, connect.NewError(connect.CodeInvalidArgument, err)
	// }
	//
	// // Extract public key and compute fingerprint
	// publicKeyDER := credentialData.PublicKeyDER
	// publicKeyPEM := credentialData.PublicKeyPEM
	// hash := sha256.Sum256(publicKeyDER)
	// fingerprint := base58.Encode(hash[:])
	//
	// // Create principal
	// principalID := uuid.Must(uuid.NewV7())
	// principal := &models.Principal{
	//     PrincipalID:  principalID,
	//     OrgID:        currentUser.OrgID, // From session
	//     Type:         models.PrincipalTypeWorker,
	//     Name:         credentialData.Name,
	//     PublicKey:    publicKeyPEM,
	//     PublicKeyDER: publicKeyDER,
	//     Fingerprint:  fingerprint,
	//     Roles:        []string{"worker"}, // Default roles
	//     CreatedAt:    time.Now(),
	//     UpdatedAt:    time.Now(),
	// }
	//
	// if err := s.principalStore.Create(ctx, principal); err != nil {
	//     log.Error().Err(err).Msg("Failed to create principal")
	//     return nil, connect.NewError(connect.CodeInternal, err)
	// }
	//
	// log.Info().
	//     Str("principal_id", principalID.String()).
	//     Str("fingerprint", fingerprint).
	//     Msg("Imported credential")
	//
	// return connect.NewResponse(&principalv1.ImportCredentialResponse{
	//     PrincipalId: principalID.String(),
	//     OrgId:       principal.OrgID.String(),
	//     Roles:       principal.Roles,
	//     Fingerprint: fingerprint,
	//     Name:        principal.Name,
	// }), nil
}

// ListCredentials returns all credentials (principals) for the current user's org.
// Optionally filters by principal type (user, worker, service).
func (s *CredentialServiceServer) ListCredentials(
	ctx context.Context,
	req *connect.Request[principalv1.ListCredentialsRequest],
) (*connect.Response[principalv1.ListCredentialsResponse], error) {
	log.Debug().Str("type_filter", req.Msg.PrincipalType).Msg("ListCredentials request")

	// TODO: Get current user's org from session/context
	// For MVP, we'll need to extract this from authentication middleware
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("authentication not yet implemented"))

	// TODO: Implement after authentication is ready
	// Example implementation:
	//
	// var typeFilter *string
	// if req.Msg.PrincipalType != "" {
	//     typeFilter = &req.Msg.PrincipalType
	// }
	//
	// principals, err := s.principalStore.ListByOrg(ctx, currentUser.OrgID, typeFilter)
	// if err != nil {
	//     log.Error().Err(err).Msg("Failed to list principals")
	//     return nil, connect.NewError(connect.CodeInternal, err)
	// }
	//
	// credentials := make([]*principalv1.Credential, 0, len(principals))
	// for _, p := range principals {
	//     cred := &principalv1.Credential{
	//         PrincipalId: p.PrincipalID.String(),
	//         OrgId:       p.OrgID.String(),
	//         Type:        p.Type,
	//         Name:        p.Name,
	//         Fingerprint: p.Fingerprint,
	//         Roles:       p.Roles,
	//         CreatedAt:   p.CreatedAt.Format(time.RFC3339),
	//     }
	//     if p.LastUsedAt != nil {
	//         cred.LastUsedAt = p.LastUsedAt.Format(time.RFC3339)
	//     }
	//     credentials = append(credentials, cred)
	// }
	//
	// log.Debug().Int("count", len(credentials)).Msg("ListCredentials success")
	//
	// return connect.NewResponse(&principalv1.ListCredentialsResponse{
	//     Credentials: credentials,
	// }), nil
}

// RevokeCredential revokes a credential by principal ID.
// Soft-deletes the principal (sets deleted_at) and adds fingerprint to revocation list.
func (s *CredentialServiceServer) RevokeCredential(
	ctx context.Context,
	req *connect.Request[principalv1.RevokeCredentialRequest],
) (*connect.Response[principalv1.RevokeCredentialResponse], error) {
	principalIDStr := req.Msg.PrincipalId
	if principalIDStr == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("principal_id is required"))
	}

	_, err := uuid.Parse(principalIDStr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid principal_id format"))
	}

	log.Info().Str("principal_id", principalIDStr).Msg("RevokeCredential request")

	// TODO: Get current user from session/context and verify they own this principal
	// For MVP, we'll need to extract this from authentication middleware
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("authentication not yet implemented"))

	// TODO: Implement after authentication is ready
	// Example implementation:
	//
	// // Fetch the principal to verify ownership
	// principal, err := s.principalStore.Get(ctx, principalID)
	// if err != nil {
	//     if errors.Is(err, store.ErrPrincipalNotFound) {
	//         return nil, connect.NewError(connect.CodeNotFound, err)
	//     }
	//     log.Error().Err(err).Msg("Failed to get principal")
	//     return nil, connect.NewError(connect.CodeInternal, err)
	// }
	//
	// // Verify the principal belongs to the current user's org
	// if principal.OrgID != currentUser.OrgID {
	//     return nil, connect.NewError(connect.CodePermissionDenied, errors.New("principal belongs to different organization"))
	// }
	//
	// // Soft-delete the principal (sets deleted_at timestamp)
	// if err := s.principalStore.Delete(ctx, principalID); err != nil {
	//     log.Error().Err(err).Msg("Failed to delete principal")
	//     return nil, connect.NewError(connect.CodeInternal, err)
	// }
	//
	// log.Info().
	//     Str("principal_id", principalIDStr).
	//     Str("fingerprint", principal.Fingerprint).
	//     Msg("Revoked credential")
	//
	// return connect.NewResponse(&principalv1.RevokeCredentialResponse{}), nil
}

// TODO: The following helper functions will be implemented when
// credential blob parsing is finalized:
// - parseCredentialBlob: parses base58-encoded credential blob
// - computeFingerprint: computes SHA256 fingerprint of public key DER
// - encodePublicKeyPEM: encodes public key DER to PEM format
