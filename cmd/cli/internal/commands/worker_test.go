package commands

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"github.com/wolfeidau/airunner/internal/worker/lease"
	"github.com/wolfeidau/airunner/internal/worker/wal"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestClassifyPublishError(t *testing.T) {
	cases := map[connect.Code]error{
		connect.CodeFailedPrecondition: wal.ErrLeaseLost,
		connect.CodeInvalidArgument:    wal.ErrPermanent,
		connect.CodeAlreadyExists:      wal.ErrPermanent,
		connect.CodeResourceExhausted:  wal.ErrPermanent,
	}
	for code, want := range cases {
		err := classifyPublishError(connect.NewError(code, errors.New("boom")))
		require.ErrorIs(t, err, want, code.String())
		require.Equal(t, code, connect.CodeOf(err), "original error stays reachable")
	}

	for _, code := range []connect.Code{connect.CodeUnavailable, connect.CodeInternal, connect.CodeDeadlineExceeded, connect.CodeUnauthenticated} {
		err := classifyPublishError(connect.NewError(code, errors.New("boom")))
		require.NotErrorIs(t, err, wal.ErrPermanent, code.String())
		require.NotErrorIs(t, err, wal.ErrLeaseLost, code.String())
	}
}

type fakeJobService struct {
	jobv1connect.JobServiceClient
	update func() (*connect.Response[jobv1.UpdateJobResponse], error)
	got    *jobv1.UpdateJobRequest
}

func (f *fakeJobService) UpdateJob(_ context.Context, req *connect.Request[jobv1.UpdateJobRequest]) (*connect.Response[jobv1.UpdateJobResponse], error) {
	f.got = req.Msg
	return f.update()
}

func TestNewRenewFunc(t *testing.T) {
	t.Run("returns the accepted duration", func(t *testing.T) {
		svc := &fakeJobService{update: func() (*connect.Response[jobv1.UpdateJobResponse], error) {
			return connect.NewResponse(&jobv1.UpdateJobResponse{VisibilityTimeoutSeconds: 60}), nil
		}}
		renew := newRenewFunc(&client.Clients{Job: svc}, "tok")
		accepted, err := renew(context.Background(), 90*time.Second)
		require.NoError(t, err)
		require.Equal(t, 60*time.Second, accepted)
		require.Equal(t, "tok", svc.got.TaskToken)
		require.Equal(t, int32(90), svc.got.VisibilityTimeoutSeconds)
	})

	t.Run("FailedPrecondition is lease lost", func(t *testing.T) {
		svc := &fakeJobService{update: func() (*connect.Response[jobv1.UpdateJobResponse], error) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("stale"))
		}}
		_, err := newRenewFunc(&client.Clients{Job: svc}, "tok")(context.Background(), time.Minute)
		require.ErrorIs(t, err, lease.ErrLost)
	})

	t.Run("other errors stay transient", func(t *testing.T) {
		svc := &fakeJobService{update: func() (*connect.Response[jobv1.UpdateJobResponse], error) {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
		}}
		_, err := newRenewFunc(&client.Clients{Job: svc}, "tok")(context.Background(), time.Minute)
		require.Error(t, err)
		require.NotErrorIs(t, err, lease.ErrLost)
	})
}

type fakeEventsService struct {
	jobv1connect.JobEventsServiceClient
	publish func() (*connect.Response[jobv1.PublishJobEventsResponse], error)
}

func (f *fakeEventsService) PublishJobEvents(context.Context, *connect.Request[jobv1.PublishJobEventsRequest]) (*connect.Response[jobv1.PublishJobEventsResponse], error) {
	return f.publish()
}

func TestGrpcEventSenderSend(t *testing.T) {
	events := &fakeEventsService{publish: func() (*connect.Response[jobv1.PublishJobEventsResponse], error) {
		return connect.NewResponse(&jobv1.PublishJobEventsResponse{Attempt: 2, AcknowledgedThroughSequence: 7}), nil
	}}
	s := &grpcEventSender{clients: &client.Clients{Events: events}, taskToken: "tok"}
	ack, err := s.Send(context.Background(), []*jobv1.JobEvent{{Sequence: 7}})
	require.NoError(t, err)
	require.Equal(t, wal.Ack{Attempt: 2, Through: 7}, ack)

	events.publish = func() (*connect.Response[jobv1.PublishJobEventsResponse], error) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad"))
	}
	_, err = s.Send(context.Background(), nil)
	require.ErrorIs(t, err, wal.ErrPermanent)
}

func TestAbandonRecordsReason(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	m, err := telemetry.NewWorkerMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	require.NoError(t, err)

	for _, reason := range []string{abandonLeaseLost, abandonLeaseLost, abandonFlushTimeout, abandonOther} {
		r := &jobRun{job: &jobv1.Job{JobId: "j"}, wal: &fakeWAL{}, metrics: m}
		r.abandon(reason, "test")
	}

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, mm := range sm.Metrics {
			if mm.Name != "worker.jobs.abandoned" {
				continue
			}
			for _, dp := range mm.Data.(metricdata.Sum[int64]).DataPoints {
				v, _ := dp.Attributes.Value("reason")
				got[v.AsString()] += dp.Value
			}
		}
	}
	require.Equal(t, map[string]int64{"lease_lost": 2, "flush_timeout": 1, "other": 1}, got)
}

// fakeWAL implements wal.WAL for abandon tests; only Pending and Discard are used.
type fakeWAL struct{ wal.WAL }

func (*fakeWAL) Pending() int       { return 0 }
func (*fakeWAL) Discard(bool) error { return nil }
