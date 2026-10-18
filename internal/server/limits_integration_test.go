//go:build integration

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPublishLimitsAndVisibilityRange(t *testing.T) {
	_, _, urls := newPostgresServers(t)
	user := jobv1connect.NewJobServiceClient(http.DefaultClient, urls.User)
	worker := jobv1connect.NewJobServiceClient(http.DefaultClient, urls.Worker)
	events := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, urls.Worker)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := user.EnqueueJob(ctx, connect.NewRequest(&jobv1.EnqueueJobRequest{
		RequestId: uuid.New().String(),
		Queue:     "limits",
		JobParams: &jobv1.JobParams{Repository: "https://github.com/example/repo", Commit: "abc123", Branch: "main"},
	}))
	require.NoError(t, err)

	stream, err := worker.DequeueJob(ctx, connect.NewRequest(&jobv1.DequeueJobRequest{Queue: "limits", MaxJobs: 1}))
	require.NoError(t, err)
	defer stream.Close()
	require.True(t, stream.Receive(), "stream error: %v", stream.Err())
	token := stream.Msg().TaskToken

	heartbeat := func(seq int64) *jobv1.JobEvent {
		return &jobv1.JobEvent{
			Attempt:   1,
			Sequence:  seq,
			Timestamp: timestamppb.Now(),
			EventType: jobv1.EventType_EVENT_TYPE_HEARTBEAT,
			EventData: &jobv1.JobEvent_Heartbeat{Heartbeat: &jobv1.HeartbeatEvent{ProcessAlive: true}},
		}
	}

	t.Run("51 events ResourceExhausted", func(t *testing.T) {
		batch := make([]*jobv1.JobEvent, 0, 51)
		for i := int64(1); i <= 51; i++ {
			batch = append(batch, heartbeat(i))
		}
		_, err := events.PublishJobEvents(ctx, connect.NewRequest(&jobv1.PublishJobEventsRequest{TaskToken: token, Events: batch}))
		require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	})

	t.Run("over 1 MiB ResourceExhausted", func(t *testing.T) {
		ev := &jobv1.JobEvent{
			Attempt:   1,
			Sequence:  1,
			Timestamp: timestamppb.Now(),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
			EventData: &jobv1.JobEvent_OutputBatch{OutputBatch: &jobv1.OutputBatchEvent{
				StartSequence: 1,
				EndSequence:   1,
				Outputs:       []*jobv1.OutputItem{{Output: []byte(strings.Repeat("x", 1<<20+1))}},
			}},
		}
		_, err := events.PublishJobEvents(ctx, connect.NewRequest(&jobv1.PublishJobEventsRequest{TaskToken: token, Events: []*jobv1.JobEvent{ev}}))
		require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
	})

	for _, secs := range []int32{10, 4000} {
		t.Run("UpdateJob out of range", func(t *testing.T) {
			_, err := worker.UpdateJob(ctx, connect.NewRequest(&jobv1.UpdateJobRequest{TaskToken: token, VisibilityTimeoutSeconds: secs}))
			require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		})

		t.Run("DequeueJob out of range", func(t *testing.T) {
			s, err := worker.DequeueJob(ctx, connect.NewRequest(&jobv1.DequeueJobRequest{Queue: "limits", MaxJobs: 1, VisibilityTimeoutSeconds: secs}))
			require.NoError(t, err)
			defer s.Close()
			require.False(t, s.Receive())
			require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(s.Err()))
		})
	}
}
