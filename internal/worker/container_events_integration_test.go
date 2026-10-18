//go:build integration

package worker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestContainerEventsRemoveAfterProcessEnd(t *testing.T) {
	je, got := newCollectingExecutor(t)

	job := &jobv1.Job{
		JobId: "job-1",
		JobParams: &jobv1.JobParams{
			Command: "sh",
			Args:    []string{"-c", "echo hello"},
			Container: &jobv1.ContainerConfig{
				Enabled: true,
				Image:   "alpine:3.19.0",
			},
		},
	}

	require.NoError(t, je.Execute(context.Background(), job))

	endIdx, removeIdx := -1, -1
	for i, ev := range got() {
		switch ev.EventType {
		case jobv1.EventType_EVENT_TYPE_PROCESS_END:
			endIdx = i
		case jobv1.EventType_EVENT_TYPE_CONTAINER_REMOVE:
			removeIdx = i
		}
	}
	require.GreaterOrEqual(t, endIdx, 0, "PROCESS_END event not published")
	require.GreaterOrEqual(t, removeIdx, 0, "CONTAINER_REMOVE event not published")
	require.Greater(t, removeIdx, endIdx, "CONTAINER_REMOVE must follow PROCESS_END")
}
