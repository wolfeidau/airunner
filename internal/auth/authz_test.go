package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

// procedureCalls invokes one procedure through a generated client and returns the resulting error.
var procedureCalls = map[string]func(ctx context.Context, jobs jobv1connect.JobServiceClient, events jobv1connect.JobEventsServiceClient) error{
	jobv1connect.JobServiceEnqueueJobProcedure: func(ctx context.Context, jobs jobv1connect.JobServiceClient, _ jobv1connect.JobEventsServiceClient) error {
		_, err := jobs.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{}))
		return err
	},
	jobv1connect.JobServiceListJobsProcedure: func(ctx context.Context, jobs jobv1connect.JobServiceClient, _ jobv1connect.JobEventsServiceClient) error {
		_, err := jobs.ListJobs(ctx, connect.NewRequest(&jobv1.ListJobsRequest{}))
		return err
	},
	jobv1connect.JobServiceCancelJobProcedure: func(ctx context.Context, jobs jobv1connect.JobServiceClient, _ jobv1connect.JobEventsServiceClient) error {
		_, err := jobs.CancelJob(ctx, connect.NewRequest(&jobv1.CancelJobRequest{}))
		return err
	},
	jobv1connect.JobServiceUpdateJobProcedure: func(ctx context.Context, jobs jobv1connect.JobServiceClient, _ jobv1connect.JobEventsServiceClient) error {
		_, err := jobs.UpdateJob(ctx, connect.NewRequest(&jobv1.UpdateJobRequest{}))
		return err
	},
	jobv1connect.JobServiceCompleteJobProcedure: func(ctx context.Context, jobs jobv1connect.JobServiceClient, _ jobv1connect.JobEventsServiceClient) error {
		_, err := jobs.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{}))
		return err
	},
	jobv1connect.JobServiceDequeueJobProcedure: func(ctx context.Context, jobs jobv1connect.JobServiceClient, _ jobv1connect.JobEventsServiceClient) error {
		stream, err := jobs.DequeueJob(ctx, connect.NewRequest(&jobv1.DequeueJobRequest{}))
		if err != nil {
			return err
		}
		defer stream.Close()
		for stream.Receive() {
		}
		return stream.Err()
	},
	jobv1connect.JobEventsServicePublishJobEventsProcedure: func(ctx context.Context, _ jobv1connect.JobServiceClient, events jobv1connect.JobEventsServiceClient) error {
		_, err := events.PublishJobEvents(ctx, connect.NewRequest(&jobv1.PublishJobEventsRequest{}))
		return err
	},
	jobv1connect.JobEventsServiceStreamJobEventsProcedure: func(ctx context.Context, _ jobv1connect.JobServiceClient, events jobv1connect.JobEventsServiceClient) error {
		stream, err := events.StreamJobEvents(ctx, connect.NewRequest(&jobv1.StreamJobEventsRequest{}))
		if err != nil {
			return err
		}
		defer stream.Close()
		for stream.Receive() {
		}
		return stream.Err()
	},
}

func newAuthzTestClients(t *testing.T, principal *Principal) (jobv1connect.JobServiceClient, jobv1connect.JobEventsServiceClient) {
	t.Helper()
	opts := connect.WithInterceptors(NewJobAuthzInterceptor())
	mux := http.NewServeMux()
	mux.Handle(jobv1connect.NewJobServiceHandler(jobv1connect.UnimplementedJobServiceHandler{}, opts))
	mux.Handle(jobv1connect.NewJobEventsServiceHandler(jobv1connect.UnimplementedJobEventsServiceHandler{}, opts))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal != nil {
			r = r.WithContext(WithPrincipal(r.Context(), principal))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return jobv1connect.NewJobServiceClient(http.DefaultClient, ts.URL),
		jobv1connect.NewJobEventsServiceClient(http.DefaultClient, ts.URL)
}

func TestJobAuthzInterceptor_Matrix(t *testing.T) {
	principals := []struct {
		name  string
		roles []string // nil principal when absent is handled by `none`
		none  bool
	}{
		{name: "none", none: true},
		{name: "user-only", roles: []string{RoleUser}},
		{name: "worker-only", roles: []string{RoleWorker}},
		{name: "admin-only", roles: []string{RoleAdmin}},
		{name: "empty-roles", roles: []string{}},
		{name: "user+worker", roles: []string{RoleUser, RoleWorker}},
	}

	require.Len(t, procedureCalls, len(jobProcedureRoles), "every mapped procedure needs a call")

	for procedure, allowed := range jobProcedureRoles {
		call, ok := procedureCalls[procedure]
		require.True(t, ok, "no call for %s", procedure)

		for _, p := range principals {
			t.Run(procedure+"/"+p.name, func(t *testing.T) {
				var principal *Principal
				if !p.none {
					principal = &Principal{PrincipalID: uuid.New(), OrgID: uuid.New(), Roles: p.roles}
				}
				jobs, events := newAuthzTestClients(t, principal)

				err := call(context.Background(), jobs, events)
				require.Error(t, err)

				switch {
				case p.none:
					require.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
				case hasAny(p.roles, allowed):
					require.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err), "allowed call must reach handler")
				default:
					require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
				}
			})
		}
	}
}

func hasAny(have, allowed []string) bool {
	for _, h := range have {
		for _, a := range allowed {
			if h == a {
				return true
			}
		}
	}
	return false
}

// Connect returns 404 for an unknown procedure before interceptors run, so the
// fail-closed branch is exercised directly on the interceptor with a fake Spec.
type fakeRequest struct {
	connect.AnyRequest
	spec connect.Spec
}

func (r fakeRequest) Spec() connect.Spec { return r.spec }

type fakeStreamConn struct {
	connect.StreamingHandlerConn
	spec connect.Spec
}

func (c fakeStreamConn) Spec() connect.Spec { return c.spec }

func TestJobAuthzInterceptor_UnknownProcedure(t *testing.T) {
	interceptor := NewJobAuthzInterceptor()
	admin := WithPrincipal(context.Background(), &Principal{PrincipalID: uuid.New(), OrgID: uuid.New(), Roles: []string{RoleAdmin}})

	tests := []struct {
		name      string
		ctx       context.Context
		procedure string
		want      connect.Code // 0 means pass through
	}{
		{"unknown job procedure, admin", admin, "/job.v1.JobService/Bogus", connect.CodePermissionDenied},
		{"unknown events procedure, admin", admin, "/job.v1.JobEventsService/Bogus", connect.CodePermissionDenied},
		{"unknown job procedure, no principal", context.Background(), "/job.v1.JobService/Bogus", connect.CodeUnauthenticated},
		{"other service passes through", context.Background(), "/principal.v1.CredentialService/Anything", 0},
	}

	for _, tt := range tests {
		t.Run("unary/"+tt.name, func(t *testing.T) {
			called := false
			next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
				called = true
				return nil, nil
			}
			_, err := interceptor.WrapUnary(next)(tt.ctx, fakeRequest{spec: connect.Spec{Procedure: tt.procedure}})
			if tt.want == 0 {
				require.NoError(t, err)
				require.True(t, called)
				return
			}
			require.Equal(t, tt.want, connect.CodeOf(err))
			require.False(t, called)
		})

		t.Run("stream/"+tt.name, func(t *testing.T) {
			called := false
			next := func(context.Context, connect.StreamingHandlerConn) error {
				called = true
				return nil
			}
			err := interceptor.WrapStreamingHandler(next)(tt.ctx, fakeStreamConn{spec: connect.Spec{Procedure: tt.procedure}})
			if tt.want == 0 {
				require.NoError(t, err)
				require.True(t, called)
				return
			}
			require.Equal(t, tt.want, connect.CodeOf(err))
			require.False(t, called)
		})
	}
}

func TestJobProcedureRoles_CoversGeneratedProcedures(t *testing.T) {
	services := jobv1.File_job_v1_job_proto.Services()
	var want []string
	for i := 0; i < services.Len(); i++ {
		svc := services.Get(i)
		methods := svc.Methods()
		for j := 0; j < methods.Len(); j++ {
			want = append(want, "/"+string(svc.FullName())+"/"+string(methods.Get(j).Name()))
		}
	}

	got := make([]string, 0, len(jobProcedureRoles))
	for p := range jobProcedureRoles {
		got = append(got, p)
	}
	sort.Strings(want)
	sort.Strings(got)
	require.Equal(t, want, got, "procedure map must match generated procedures exactly")
}
