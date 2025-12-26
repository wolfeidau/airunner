package auth

import (
	"context"
	"fmt"
	"slices"

	"connectrpc.com/connect"
	"github.com/wolfeidau/airunner/internal/store"
)

// Permission represents an authorized action
type Permission string

const (
	PermManagePrincipals Permission = "principals:manage"
	PermManageCerts      Permission = "certs:manage"
	PermJobsSubmit       Permission = "jobs:submit"
	PermJobsDequeue      Permission = "jobs:dequeue"
	PermJobsComplete     Permission = "jobs:complete"
	PermJobsList         Permission = "jobs:list"
	PermJobsCancel       Permission = "jobs:cancel"
	PermEventsPublish    Permission = "events:publish"
	PermEventsStream     Permission = "events:stream"
)

// RolePermissions maps principal types to allowed permissions
var RolePermissions = map[store.PrincipalType][]Permission{
	store.PrincipalTypeAdmin: {
		PermManagePrincipals,
		PermManageCerts,
		PermJobsSubmit,
		PermJobsDequeue,
		PermJobsComplete,
		PermJobsList,
		PermJobsCancel,
		PermEventsPublish,
		PermEventsStream,
	},
	store.PrincipalTypeWorker: {
		PermJobsDequeue,
		PermJobsComplete,
		PermJobsList,
		PermEventsPublish,
		PermEventsStream,
	},
	store.PrincipalTypeUser: {
		PermJobsSubmit,
		PermJobsList,
		PermJobsCancel,
		PermEventsStream,
	},
	store.PrincipalTypeService: {
		PermJobsSubmit,
		PermJobsDequeue,
		PermJobsComplete,
		PermJobsList,
		PermJobsCancel,
		PermEventsPublish,
		PermEventsStream,
	},
}

// HasPermission checks if a principal type has a specific permission
func HasPermission(principalType store.PrincipalType, perm Permission) bool {
	perms, ok := RolePermissions[principalType]
	if !ok {
		return false
	}
	return slices.Contains(perms, perm)
}

// RequirePermission checks authorization and returns an error if not authorized
func RequirePermission(ctx context.Context, perm Permission) error {
	info, ok := GetPrincipalInfo(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("not authenticated"))
	}

	if !HasPermission(info.Type, perm) {
		return connect.NewError(
			connect.CodePermissionDenied,
			fmt.Errorf("permission denied: %s requires %s", info.Type, perm),
		)
	}

	return nil
}

// MustRequirePermission panics if authorization fails (for use in tests)
func MustRequirePermission(ctx context.Context, perm Permission) {
	if err := RequirePermission(ctx, perm); err != nil {
		panic(err)
	}
}
