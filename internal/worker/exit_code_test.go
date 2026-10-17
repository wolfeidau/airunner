package worker

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestExecuteExitCode(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{"non-zero exit", 3},
		{"zero exit", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			je, got := newCollectingExecutor(t)

			job := &jobv1.Job{
				JobId: "job-1",
				JobParams: &jobv1.JobParams{
					Command:     "sh",
					Args:        []string{"-c", fmt.Sprintf("exit %d", tt.code)},
					ProcessType: jobv1.ProcessType_PROCESS_TYPE_PIPE,
				},
			}

			err := je.Execute(context.Background(), job)
			if tt.code == 0 {
				require.NoError(t, err)
			} else {
				var exitErr *ExitError
				require.ErrorAs(t, err, &exitErr)
				require.Equal(t, tt.code, exitErr.Code)
			}

			var found bool
			for _, ev := range got() {
				if ev.EventType == jobv1.EventType_EVENT_TYPE_PROCESS_END {
					found = true
					require.Equal(t, int32(tt.code), ev.GetProcessEnd().ExitCode)
				}
			}
			require.True(t, found, "PROCESS_END event not published")
		})
	}
}
