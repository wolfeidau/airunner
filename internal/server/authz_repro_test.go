//go:build integration

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
)

func TestRepro_JobHandlersEnforceRoles(t *testing.T) {
	t.Skip("known bug: job handlers do not enforce roles; fixed in phase 3 of specs/job-lifecycle-tenancy-redesign-plan.md")
	tests := []struct {
		name  string
		roles []string
		call  func(ctx context.Context, c jobv1connect.JobServiceClient) error
	}{
		{
			name:  "user role cannot dequeue",
			roles: []string{"user"},
			call: func(ctx context.Context, c jobv1connect.JobServiceClient) error {
				stream, err := c.DequeueJob(ctx, connect.NewRequest(&jobv1.DequeueJobRequest{
					Queue:                    "authz-queue",
					MaxJobs:                  1,
					VisibilityTimeoutSeconds: 300,
				}))
				if err != nil {
					return err
				}
				defer stream.Close()
				for stream.Receive() {
				}
				return stream.Err()
			},
		},
		{
			name:  "worker role cannot enqueue",
			roles: []string{"worker"},
			call: func(ctx context.Context, c jobv1connect.JobServiceClient) error {
				_, err := c.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{
					RequestId: uuid.New().String(),
					Queue:     "authz-queue",
					JobParams: &jobv1.JobParams{Repository: "https://github.com/example/repo", Commit: "abc123", Branch: "main"},
				}))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stores := postgrestest.NewStores(t)
			fx := postgrestest.SeedOrg(t, stores)

			handler := NewServer(stores.Jobs).Handler()
			url := principalServer(t, handler, fx.User, tt.roles, "user")

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			err := tt.call(ctx, jobv1connect.NewJobServiceClient(http.DefaultClient, url))
			require.Error(t, err)
			require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
		})
	}
}
