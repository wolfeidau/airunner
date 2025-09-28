package server

import (
	"context"

	"connectrpc.com/connect"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
)

type JobEventServer struct {
	store store.JobStore
}

func NewJobEventServer(store store.JobStore) *JobEventServer {
	return &JobEventServer{
		store: store,
	}
}

var _ jobv1connect.JobEventsServiceHandler = &JobEventServer{}

func (s *JobEventServer) StreamJobEvents(ctx context.Context, req *connect.Request[v1.StreamJobEventsRequest], stream *connect.ServerStream[v1.StreamJobEventsResponse]) error {
	eventChan, err := s.store.StreamEvents(
		ctx,
		req.Msg.JobId,
		req.Msg.FromSequence,
		req.Msg.FromTimestamp,
		req.Msg.EventFilter,
	)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Stream events to client
	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				return nil // Channel closed
			}

			resp := &v1.StreamJobEventsResponse{
				Event: event,
			}
			if err := stream.Send(resp); err != nil {
				return connect.NewError(connect.CodeInternal, err)
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *JobEventServer) PublishJobEvents(ctx context.Context, stream *connect.ClientStream[v1.PublishJobEventsRequest]) (*connect.Response[v1.PublishJobEventsResponse], error) {
	for stream.Receive() {
		req := stream.Msg()

		// Publish events to store
		err := s.store.PublishEvents(ctx, req.TaskToken, req.Events)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	if err := stream.Err(); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&v1.PublishJobEventsResponse{}), nil
}
