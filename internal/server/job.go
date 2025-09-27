package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

var _ jobv1connect.JobServiceHandler = &JobServer{}

type JobServer struct{}

func NewJobServer() *JobServer {
	return &JobServer{}
}

func (s *JobServer) EnqueueJob(ctx context.Context, req *connect.Request[v1.EnqueueJobRequest]) (*connect.Response[v1.EnqueueJobResponse], error) {
	// TODO implement me
	panic("implement me")
}

func (s *JobServer) DequeueJob(ctx context.Context, req *connect.Request[v1.DequeueJobRequest], stream *connect.ServerStream[v1.DequeueJobResponse]) error {
	// TODO implement me
	panic("implement me")
}

func (s *JobServer) UpdateJob(context.Context, *connect.Request[v1.UpdateJobRequest]) (*connect.Response[v1.UpdateJobResponse], error) {
	// TODO implement me
	panic("implement me")
}

func (s *JobServer) CompleteJob(context.Context, *connect.Request[v1.CompleteJobRequest]) (*connect.Response[v1.CompleteJobResponse], error) {
	// TODO implement me
	panic("implement me")
}

func (s *JobServer) ListJobs(ctx context.Context, req *connect.Request[v1.ListJobsRequest]) (*connect.Response[v1.ListJobsResponse], error) {
	// TODO implement me
	panic("implement me")
}
