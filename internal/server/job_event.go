package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	v1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"go.opentelemetry.io/otel/metric"
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
	store   store.JobStore
	metrics *telemetry.Metrics

	// sendTimeout bounds how long one stream.Send may block; 0 disables.
	sendTimeout time.Duration
	noDeadline  sync.Once
}

func NewJobEventServer(store store.JobStore) *JobEventServer {
	return &JobEventServer{
		store:   store,
		metrics: telemetry.NoopMetrics(),
	}
}

var _ jobv1connect.JobEventsServiceHandler = &JobEventServer{}

func (s *JobEventServer) StreamJobEvents(ctx context.Context, req *connect.Request[v1.StreamJobEventsRequest], stream *connect.ServerStream[v1.StreamJobEventsResponse]) error {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return err
	}

	sender := &deadlineSender{
		set:     writeDeadlineFromContext(ctx),
		timeout: s.sendTimeout,
		onUnsupported: func() {
			s.noDeadline.Do(func() {
				log.Debug().Msg("response writer does not support write deadlines; stream send timeout disabled")
			})
		},
	}
	stalled := false

	err = s.store.StreamEvents(ctx, caller, store.StreamRequest{
		JobID:         req.Msg.JobId,
		Attempt:       req.Msg.Attempt,
		FromSequence:  req.Msg.FromSequence,
		FromTimestamp: req.Msg.FromTimestamp,
		EventFilter:   req.Msg.EventFilter,
	}, func(r *store.StreamResponse) error {
		st, sendErr := sender.do(func() error {
			return stream.Send(&v1.StreamJobEventsResponse{
				Event:           r.Event,
				ResolvedAttempt: r.Attempt,
				JobState:        r.JobState,
				AttemptClosed:   r.AttemptClosed,
			})
		})
		stalled = st
		return sendErr
	})
	if err != nil {
		if stalled {
			s.metrics.StreamsStalled.Add(ctx, 1)
			return connect.NewError(connect.CodeDeadlineExceeded,
				fmt.Errorf("stream send made no progress for %s", s.sendTimeout))
		}
		return toConnectError(err)
	}
	return nil
}

// countTooLarge records a publish rejected by the handler before reaching the store.
func (s *JobEventServer) countTooLarge(ctx context.Context) {
	s.metrics.EventsPublishRejected.Add(ctx, 1,
		metric.WithAttributes(telemetry.AttrReason.String(telemetry.ReasonTooLarge)))
}

func (s *JobEventServer) PublishJobEvents(ctx context.Context, req *connect.Request[v1.PublishJobEventsRequest]) (*connect.Response[v1.PublishJobEventsResponse], error) {
	caller, err := callerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if len(req.Msg.Events) > maxPublishEvents {
		s.countTooLarge(ctx)
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("too many events: %d exceeds limit of %d", len(req.Msg.Events), maxPublishEvents))
	}
	if size := proto.Size(req.Msg); size > maxPublishBytes {
		s.countTooLarge(ctx)
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
