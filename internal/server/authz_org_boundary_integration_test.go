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
	"github.com/wolfeidau/airunner/internal/models"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
)

// seedAdmin adds an admin principal to the fixture's organization.
func seedAdmin(t testing.TB, s *postgrestest.Stores, orgID uuid.UUID) store.Caller {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	now := time.Now()
	githubID := "gh-" + id.String()
	require.NoError(t, s.Principals.Create(context.Background(), &models.Principal{
		PrincipalID: id,
		OrgID:       orgID,
		Type:        "user",
		Name:        "test-admin",
		GitHubID:    &githubID,
		Roles:       []string{"admin"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}))
	return store.Caller{OrgID: orgID, PrincipalID: id}
}

func TestAdminCannotCrossOrgBoundary(t *testing.T) {
	stores := postgrestest.NewStores(t)
	orgA := postgrestest.SeedOrg(t, stores)
	orgB := postgrestest.SeedOrg(t, stores)
	adminA := seedAdmin(t, stores, orgA.Org)

	handler := NewServer(stores.Jobs).Handler()
	adminURL := principalServer(t, handler, adminA, []string{"admin"}, "user")
	userBURL := principalServer(t, handler, orgB.User, []string{"user"}, "user")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const queue = "boundary-queue"
	userB := jobv1connect.NewJobServiceClient(http.DefaultClient, userBURL)
	enq, err := userB.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{
		RequestId: uuid.New().String(),
		Queue:     queue,
		JobParams: &jobv1.JobParams{Repository: "https://github.com/example/repo", Commit: "abc123", Branch: "main"},
	}))
	require.NoError(t, err)
	jobBID := enq.Msg.JobId

	admin := jobv1connect.NewJobServiceClient(http.DefaultClient, adminURL)
	adminEvents := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, adminURL)

	t.Run("stream events of other org job is NotFound", func(t *testing.T) {
		stream, err := adminEvents.StreamJobEvents(ctx, connect.NewRequest(&jobv1.StreamJobEventsRequest{JobId: jobBID}))
		if err == nil {
			defer stream.Close()
			for stream.Receive() {
			}
			err = stream.Err()
		}
		require.Error(t, err)
		require.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	})

	t.Run("list never returns other org jobs", func(t *testing.T) {
		resp, err := admin.ListJobs(ctx, connect.NewRequest(&jobv1.ListJobsRequest{Queue: queue}))
		require.NoError(t, err)
		for _, j := range resp.Msg.Jobs {
			require.NotEqual(t, jobBID, j.JobId)
		}
		require.Empty(t, resp.Msg.Jobs)
	})

	t.Run("dequeue never returns other org jobs", func(t *testing.T) {
		dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
		defer dcancel()
		stream, err := admin.DequeueJob(dctx, connect.NewRequest(&jobv1.DequeueJobRequest{
			Queue:                    queue,
			MaxJobs:                  1,
			VisibilityTimeoutSeconds: 300,
		}))
		// Dequeue long-polls; with nothing visible the call ends with our deadline.
		if err == nil {
			defer stream.Close()
			for stream.Receive() {
				t.Fatalf("admin of org A dequeued job %s", stream.Msg().GetJob().GetJobId())
			}
			err = stream.Err()
		}
		if err != nil {
			require.Equal(t, connect.CodeDeadlineExceeded, connect.CodeOf(err))
		}
	})
}
