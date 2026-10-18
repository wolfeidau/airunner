//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
	"github.com/wolfeidau/airunner/internal/telemetry/telemetrytest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	stallEventBytes = 100 << 10
	// 16 MiB comfortably exceeds the 4 MiB HTTP/2 stream window plus socket buffers.
	stallEventCount = 160
)

// newStallFixture serves the event service over HTTP/2 TLS with a 1s send timeout and
// seeds a job with stallEventCount large output events.
func newStallFixture(t *testing.T) (*httptest.Server, *telemetrytest.Harness, string) {
	t.Helper()
	stores := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, stores)
	h := telemetrytest.New(t)

	handler := NewServer(stores.Jobs).WithMetrics(h.Metrics).WithStreamSendTimeout(time.Second).Handler()
	principal := &auth.Principal{PrincipalID: fx.User.PrincipalID, OrgID: fx.User.OrgID, Roles: []string{"user"}, Type: "user"}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)

	ctx := context.Background()
	enq, err := stores.Jobs.EnqueueJob(ctx, fx.User, &jobv1.EnqueueJobRequest{
		RequestId: "stall",
		Queue:     "q",
		JobParams: &jobv1.JobParams{Repository: "https://github.com/test/stall", Command: "echo"},
	})
	require.NoError(t, err)
	jobs, err := stores.Jobs.DequeueJobs(ctx, fx.Worker, "q", 1, 60)
	require.NoError(t, err)
	require.Len(t, jobs, 1)

	payload := []byte(strings.Repeat("x", stallEventBytes))
	const perPublish = 10 // ~1 MiB, the unary publish limit
	for seq := int64(1); seq <= stallEventCount; seq += perPublish {
		batch := make([]*jobv1.JobEvent, 0, perPublish)
		for i := seq; i < seq+perPublish; i++ {
			batch = append(batch, &jobv1.JobEvent{
				Attempt:   1,
				Sequence:  i,
				Timestamp: timestamppb.Now(),
				EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
				EventData: &jobv1.JobEvent_OutputBatch{OutputBatch: &jobv1.OutputBatchEvent{
					StartSequence: i,
					EndSequence:   i,
					Outputs:       []*jobv1.OutputItem{{Output: payload}},
				}},
			})
		}
		_, err := stores.Jobs.PublishEvents(ctx, fx.Worker, jobs[0].TaskToken, batch)
		require.NoError(t, err)
	}
	return ts, h, enq.JobId
}

func TestStreamStalledReaderDeadline(t *testing.T) {
	ts, h, jobID := newStallFixture(t)

	msg, err := proto.Marshal(&jobv1.StreamJobEventsRequest{JobId: jobID})
	require.NoError(t, err)
	env := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(env[1:], uint32(len(msg)))
	env = append(env, msg...)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/job.v1.JobEventsService/StreamJobEvents", bytes.NewReader(env))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/connect+proto")
	req.Header.Set("Connect-Protocol-Version", "1")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	require.Equal(t, 2, resp.ProtoMajor)
	// Read headers only; never read the body.

	require.Eventually(t, func() bool {
		return h.Sum(t, "streams.stalled") == 1
	}, 10*time.Second, 100*time.Millisecond, "server did not report the stalled stream")

	require.NoError(t, resp.Body.Close())
}

func TestStreamNormalReaderNotStalled(t *testing.T) {
	ts, h, jobID := newStallFixture(t)

	client := jobv1connect.NewJobEventsServiceClient(ts.Client(), ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := client.StreamJobEvents(ctx, connect.NewRequest(&jobv1.StreamJobEventsRequest{JobId: jobID}))
	require.NoError(t, err)
	defer stream.Close()

	// The job is still running, so the stream stays open; read until every event arrived.
	seen := 0
	for seen < stallEventCount && stream.Receive() {
		if stream.Msg().Event != nil {
			seen++
		}
	}
	require.NoError(t, stream.Err())
	require.Equal(t, stallEventCount, seen)
	require.Equal(t, int64(0), h.Sum(t, "streams.stalled"))
}
