package commands

import jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"

type Globals struct {
	Debug   bool
	Version string
}

func jobStateToString(state jobv1.JobState) string {
	switch state {
	case jobv1.JobState_JOB_STATE_SCHEDULED:
		return "SCHEDULED"
	case jobv1.JobState_JOB_STATE_RUNNING:
		return "RUNNING"
	case jobv1.JobState_JOB_STATE_COMPLETED:
		return "COMPLETED"
	case jobv1.JobState_JOB_STATE_FAILED:
		return "FAILED"
	case jobv1.JobState_JOB_STATE_CANCELLED:
		return "CANCELLED"
	default:
		return "UNKNOWN"
	}
}
