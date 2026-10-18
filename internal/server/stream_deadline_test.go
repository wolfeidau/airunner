package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"github.com/wolfeidau/airunner/internal/auth"
	"github.com/wolfeidau/airunner/internal/store"
)

// eventStreamer is a JobStore whose StreamEvents sends a fixed number of events.
type eventStreamer struct {
	store.JobStore
	n int
}

func (e *eventStreamer) StreamEvents(_ context.Context, _ store.Caller, _ store.StreamRequest, send func(*store.StreamResponse) error) error {
	for i := 1; i <= e.n; i++ {
		if err := send(&store.StreamResponse{Event: &jobv1.JobEvent{Sequence: int64(i)}}); err != nil {
			return err
		}
	}
	return nil
}

// noDeadlineWriter hides Unwrap, so http.ResponseController reports ErrNotSupported.
type noDeadlineWriter struct{ w http.ResponseWriter }

func (n noDeadlineWriter) Header() http.Header         { return n.w.Header() }
func (n noDeadlineWriter) Write(b []byte) (int, error) { return n.w.Write(b) }
func (n noDeadlineWriter) WriteHeader(c int)           { n.w.WriteHeader(c) }
func (n noDeadlineWriter) Flush()                      { n.w.(http.Flusher).Flush() }

func TestStreamWithoutDeadlineSupport(t *testing.T) {
	srv := NewServer(&eventStreamer{n: 5}).WithStreamSendTimeout(time.Second)
	handler := srv.Handler()
	principal := &auth.Principal{PrincipalID: uuid.New(), OrgID: uuid.New(), Roles: []string{"user"}, Type: "user"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(noDeadlineWriter{w}, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	}))
	t.Cleanup(ts.Close)

	client := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, ts.URL)
	stream, err := client.StreamJobEvents(context.Background(), connect.NewRequest(&jobv1.StreamJobEventsRequest{JobId: "j"}))
	require.NoError(t, err)
	defer stream.Close()

	got := 0
	for stream.Receive() {
		got++
	}
	require.NoError(t, stream.Err())
	require.Equal(t, 5, got)
}
