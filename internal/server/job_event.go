package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
	"google.golang.org/protobuf/proto"
)

// Unary publish limits, checked before the store is called.
const (
	// maxPublishEvents is the maximum number of events in one PublishJobEvents request.
	maxPublishEvents = 50
	// maxPublishBytes is the maximum encoded size of one PublishJobEvents request (1 MiB).
	maxPublishBytes = 1 << 20
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
	caller, err := callerFromContext(ctx)
	if err != nil {
		return err
	}

	eventChan, err := s.store.StreamEvents(
		ctx,
		caller,
		req.Msg.JobId,
		req.Msg.Attempt,
		req.Msg.FromSequence,
		req.Msg.FromTimestamp,
		req.Msg.EventFilter,
	)
	if err != nil {
		return toConnectError(err)
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
				return toConnectError(err)
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *JobEventServer) PublishJobEvents(ctx context.Context, req *connect.Request[v1.PublishJobEventsRequest]) (*connect.Response[v1.PublishJobEventsResponse], error) {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if len(req.Msg.Events) > maxPublishEvents {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("too many events: %d exceeds limit of %d", len(req.Msg.Events), maxPublishEvents))
	}
	if size := proto.Size(req.Msg); size > maxPublishBytes {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("request size %d bytes exceeds limit of %d", size, maxPublishBytes))
	}

	result, err := s.store.PublishEvents(ctx, caller, req.Msg.TaskToken, req.Msg.Events)
	if err != nil {
		return nil, toConnectError(err)
	}

	return connect.NewResponse(&v1.PublishJobEventsResponse{
		Attempt:                     result.Attempt,
		AcknowledgedThroughSequence: result.AcknowledgedThroughSequence,
	}), nil
}
