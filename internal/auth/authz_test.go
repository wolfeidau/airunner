package auth

import (
	"context"
	"testing"

	"connectrpc.com/authn"
	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/store"
)

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name           string
		principalType  store.PrincipalType
		permission     Permission
		expectedResult bool
	}{
		// Admin permissions
		{
			name:           "admin can manage principals",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermManagePrincipals,
			expectedResult: true,
		},
		{
			name:           "admin can manage certs",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermManageCerts,
			expectedResult: true,
		},
		{
			name:           "admin can submit jobs",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermJobsSubmit,
			expectedResult: true,
		},
		{
			name:           "admin can dequeue jobs",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermJobsDequeue,
			expectedResult: true,
		},
		{
			name:           "admin can complete jobs",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermJobsComplete,
			expectedResult: true,
		},
		{
			name:           "admin can list jobs",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermJobsList,
			expectedResult: true,
		},
		{
			name:           "admin can cancel jobs",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermJobsCancel,
			expectedResult: true,
		},
		{
			name:           "admin can publish events",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermEventsPublish,
			expectedResult: true,
		},
		{
			name:           "admin can stream events",
			principalType:  store.PrincipalTypeAdmin,
			permission:     PermEventsStream,
			expectedResult: true,
		},

		// Worker permissions
		{
			name:           "worker can dequeue jobs",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermJobsDequeue,
			expectedResult: true,
		},
		{
			name:           "worker can complete jobs",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermJobsComplete,
			expectedResult: true,
		},
		{
			name:           "worker can list jobs",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermJobsList,
			expectedResult: true,
		},
		{
			name:           "worker can publish events",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermEventsPublish,
			expectedResult: true,
		},
		{
			name:           "worker can stream events",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermEventsStream,
			expectedResult: true,
		},
		{
			name:           "worker cannot manage principals",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermManagePrincipals,
			expectedResult: false,
		},
		{
			name:           "worker cannot submit jobs",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermJobsSubmit,
			expectedResult: false,
		},
		{
			name:           "worker cannot manage certs",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermManageCerts,
			expectedResult: false,
		},
		{
			name:           "worker cannot cancel jobs",
			principalType:  store.PrincipalTypeWorker,
			permission:     PermJobsCancel,
			expectedResult: false,
		},

		// User permissions
		{
			name:           "user can submit jobs",
			principalType:  store.PrincipalTypeUser,
			permission:     PermJobsSubmit,
			expectedResult: true,
		},
		{
			name:           "user can list jobs",
			principalType:  store.PrincipalTypeUser,
			permission:     PermJobsList,
			expectedResult: true,
		},
		{
			name:           "user can cancel jobs",
			principalType:  store.PrincipalTypeUser,
			permission:     PermJobsCancel,
			expectedResult: true,
		},
		{
			name:           "user can stream events",
			principalType:  store.PrincipalTypeUser,
			permission:     PermEventsStream,
			expectedResult: true,
		},
		{
			name:           "user cannot dequeue jobs",
			principalType:  store.PrincipalTypeUser,
			permission:     PermJobsDequeue,
			expectedResult: false,
		},
		{
			name:           "user cannot complete jobs",
			principalType:  store.PrincipalTypeUser,
			permission:     PermJobsComplete,
			expectedResult: false,
		},
		{
			name:           "user cannot manage principals",
			principalType:  store.PrincipalTypeUser,
			permission:     PermManagePrincipals,
			expectedResult: false,
		},
		{
			name:           "user cannot publish events",
			principalType:  store.PrincipalTypeUser,
			permission:     PermEventsPublish,
			expectedResult: false,
		},

		// Service permissions
		{
			name:           "service can submit jobs",
			principalType:  store.PrincipalTypeService,
			permission:     PermJobsSubmit,
			expectedResult: true,
		},
		{
			name:           "service can dequeue jobs",
			principalType:  store.PrincipalTypeService,
			permission:     PermJobsDequeue,
			expectedResult: true,
		},
		{
			name:           "service can complete jobs",
			principalType:  store.PrincipalTypeService,
			permission:     PermJobsComplete,
			expectedResult: true,
		},
		{
			name:           "service can list jobs",
			principalType:  store.PrincipalTypeService,
			permission:     PermJobsList,
			expectedResult: true,
		},
		{
			name:           "service can cancel jobs",
			principalType:  store.PrincipalTypeService,
			permission:     PermJobsCancel,
			expectedResult: true,
		},
		{
			name:           "service can publish events",
			principalType:  store.PrincipalTypeService,
			permission:     PermEventsPublish,
			expectedResult: true,
		},
		{
			name:           "service can stream events",
			principalType:  store.PrincipalTypeService,
			permission:     PermEventsStream,
			expectedResult: true,
		},
		{
			name:           "service cannot manage principals",
			principalType:  store.PrincipalTypeService,
			permission:     PermManagePrincipals,
			expectedResult: false,
		},
		{
			name:           "service cannot manage certs",
			principalType:  store.PrincipalTypeService,
			permission:     PermManageCerts,
			expectedResult: false,
		},

		// Invalid principal type
		{
			name:           "invalid principal type has no permissions",
			principalType:  store.PrincipalType("invalid"),
			permission:     PermJobsSubmit,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPermission(tt.principalType, tt.permission)
			require.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestRequirePermission(t *testing.T) {
	t.Run("succeeds with proper permission", func(t *testing.T) {
		info := &PrincipalInfo{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
		}
		ctx := authn.SetInfo(context.Background(), info)

		err := RequirePermission(ctx, PermJobsSubmit)
		require.NoError(t, err)
	})

	t.Run("fails without required permission", func(t *testing.T) {
		info := &PrincipalInfo{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
		}
		ctx := authn.SetInfo(context.Background(), info)

		err := RequirePermission(ctx, PermManagePrincipals)
		require.Error(t, err)
	})

	t.Run("fails when not authenticated", func(t *testing.T) {
		ctx := context.Background()

		err := RequirePermission(ctx, PermJobsSubmit)
		require.Error(t, err)
	})

	t.Run("fails with wrong auth type in context", func(t *testing.T) {
		ctx := authn.SetInfo(context.Background(), "not a PrincipalInfo")

		err := RequirePermission(ctx, PermJobsSubmit)
		require.Error(t, err)
	})

	t.Run("admin always has permission", func(t *testing.T) {
		info := &PrincipalInfo{
			PrincipalID: "admin-user",
			Type:        store.PrincipalTypeAdmin,
		}
		ctx := authn.SetInfo(context.Background(), info)

		// Admin should have all permissions
		permissions := []Permission{
			PermManagePrincipals,
			PermManageCerts,
			PermJobsSubmit,
			PermJobsDequeue,
			PermJobsComplete,
			PermJobsList,
			PermJobsCancel,
			PermEventsPublish,
			PermEventsStream,
		}

		for _, perm := range permissions {
			err := RequirePermission(ctx, perm)
			require.NoError(t, err, "admin should have permission: %s", perm)
		}
	})

	t.Run("worker role restrictions", func(t *testing.T) {
		info := &PrincipalInfo{
			PrincipalID: "worker-123",
			Type:        store.PrincipalTypeWorker,
		}
		ctx := authn.SetInfo(context.Background(), info)

		// Worker should not have these permissions
		restrictedPerms := []Permission{
			PermManagePrincipals,
			PermManageCerts,
			PermJobsSubmit,
			PermJobsCancel,
		}

		for _, perm := range restrictedPerms {
			err := RequirePermission(ctx, perm)
			require.Error(t, err, "worker should not have permission: %s", perm)
		}
	})
}

func TestMustRequirePermission(t *testing.T) {
	t.Run("succeeds when permission granted", func(t *testing.T) {
		info := &PrincipalInfo{
			PrincipalID: "admin-user",
			Type:        store.PrincipalTypeAdmin,
		}
		ctx := authn.SetInfo(context.Background(), info)

		// Should not panic
		require.NotPanics(t, func() {
			MustRequirePermission(ctx, PermManagePrincipals)
		})
	})

	t.Run("panics when permission denied", func(t *testing.T) {
		info := &PrincipalInfo{
			PrincipalID: "user-123",
			Type:        store.PrincipalTypeUser,
		}
		ctx := authn.SetInfo(context.Background(), info)

		// Should panic
		require.Panics(t, func() {
			MustRequirePermission(ctx, PermManagePrincipals)
		})
	})

	t.Run("panics when not authenticated", func(t *testing.T) {
		ctx := context.Background()

		require.Panics(t, func() {
			MustRequirePermission(ctx, PermJobsSubmit)
		})
	})
}

func TestPermissionConstants(t *testing.T) {
	t.Run("all permissions defined", func(t *testing.T) {
		permissions := []Permission{
			PermManagePrincipals,
			PermManageCerts,
			PermJobsSubmit,
			PermJobsDequeue,
			PermJobsComplete,
			PermJobsList,
			PermJobsCancel,
			PermEventsPublish,
			PermEventsStream,
		}

		for _, perm := range permissions {
			require.NotEmpty(t, perm)
		}
	})

	t.Run("permission values are unique", func(t *testing.T) {
		permissions := []Permission{
			PermManagePrincipals,
			PermManageCerts,
			PermJobsSubmit,
			PermJobsDequeue,
			PermJobsComplete,
			PermJobsList,
			PermJobsCancel,
			PermEventsPublish,
			PermEventsStream,
		}

		seen := make(map[Permission]bool)
		for _, perm := range permissions {
			require.False(t, seen[perm], "permission %s is not unique", perm)
			seen[perm] = true
		}
	})
}
