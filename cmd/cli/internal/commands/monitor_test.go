package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestFormatStatus(t *testing.T) {
	tests := []struct {
		name    string
		attempt int32
		state   jobv1.JobState
		want    string
	}{
		{"running", 2, jobv1.JobState_JOB_STATE_RUNNING, "Attempt 2, state RUNNING"},
		{"first attempt", 1, jobv1.JobState_JOB_STATE_RUNNING, "Attempt 1, state RUNNING"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, formatStatus(tt.attempt, tt.state))
		})
	}
}

func TestClosingNotice(t *testing.T) {
	tests := []struct {
		name          string
		closed, ended bool
		want          string
	}{
		{"open stream", false, false, ""},
		{"closed after process end", true, true, ""},
		{"closed without process end", true, false, "Attempt 3 closed without a process end event (job state RUNNING)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, closingNotice(tt.closed, tt.ended, 3, jobv1.JobState_JOB_STATE_RUNNING))
		})
	}
}
