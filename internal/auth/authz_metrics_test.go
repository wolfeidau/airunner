package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/attribute"
)

func TestMetricsAuthzDenied(t *testing.T) {
	h := telemetrytest.New(t)
	opts := connect.WithInterceptors(NewJobAuthzInterceptor(h.Metrics))
	mux := http.NewServeMux()
	mux.Handle(jobv1connect.NewJobServiceHandler(jobv1connect.UnimplementedJobServiceHandler{}, opts))

	var principal *Principal
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal != nil {
			r = r.WithContext(WithPrincipal(r.Context(), principal))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	client := jobv1connect.NewJobServiceClient(http.DefaultClient, ts.URL)
	ctx := context.Background()

	// No principal: unauthenticated.
	_, err := client.ListJobs(ctx, connect.NewRequest(&jobv1.ListJobsRequest{}))
	require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	// Worker may not list jobs: forbidden.
	principal = &Principal{PrincipalID: uuid.New(), OrgID: uuid.New(), Roles: []string{RoleWorker}}
	_, err = client.ListJobs(ctx, connect.NewRequest(&jobv1.ListJobsRequest{}))
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// Allowed call reaches the handler and is not counted.
	principal = &Principal{PrincipalID: uuid.New(), OrgID: uuid.New(), Roles: []string{RoleUser}}
	_, err = client.ListJobs(ctx, connect.NewRequest(&jobv1.ListJobsRequest{}))
	require.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))

	proc := attribute.String("procedure", jobv1connect.JobServiceListJobsProcedure)
	require.EqualValues(t, 1, h.Sum(t, "authz.denied", proc, attribute.String("reason", "unauthenticated")))
	require.EqualValues(t, 1, h.Sum(t, "authz.denied", proc, attribute.String("reason", "forbidden")))
	require.EqualValues(t, 2, h.Sum(t, "authz.denied"))
}
