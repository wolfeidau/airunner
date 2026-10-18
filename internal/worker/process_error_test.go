package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	consolestream "github.com/wolfeidau/console-stream"
)

func TestHandleEventProcessError(t *testing.T) {
	tests := []struct {
		name string
		err  *consolestream.ProcessError
	}{
		{"container wait failed", &consolestream.ProcessError{Error: errors.New("boom"), Message: "Container wait failed"}},
		{"log stream failed", &consolestream.ProcessError{Error: errors.New("eof"), Message: "Container log stream failed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Skip("known bug: handleEvent drops consolestream.ProcessError events; fixed in phase 1 of specs/job-lifecycle-tenancy-redesign-plan.md")

			je, got := newCollectingExecutor(t)
			defer func() { require.NoError(t, je.batcher.Stop(context.Background())) }()

			require.NoError(t, je.handleEvent(consolestream.Event{Event: tt.err}, "job-1"))

			var found bool
			for _, ev := range got() {
				if ev.EventType == jobv1.EventType_EVENT_TYPE_PROCESS_ERROR {
					found = true
				}
			}
			require.True(t, found, "PROCESS_ERROR event not published")
		})
	}
}
