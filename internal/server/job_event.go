package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

type JobEventServer struct{}

func NewJobEventServer() *JobEventServer {
	return &JobEventServer{}
}

var _ jobv1connect.JobEventsServiceHandler = &JobEventServer{}

func (s *JobEventServer) StreamJobEvents(context.Context, *connect.Request[v1.StreamJobEventsRequest], *connect.ServerStream[v1.StreamJobEventsResponse]) error {
	// TODO implement me
	panic("implement me")
}

func (s *JobEventServer) PublishJobEvents(context.Context, *connect.ClientStream[v1.PublishJobEventsRequest]) (*connect.Response[v1.PublishJobEventsResponse], error) {
	// TODO implement me
	panic("implement me")
}
