package commands

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestCancelOutcome(t *testing.T) {
	msg, err := cancelOutcome("j1", jobv1.JobState_JOB_STATE_CANCELLED, nil)
	require.NoError(t, err)
	require.Equal(t, "Job j1 cancelled", msg)

	_, err = cancelOutcome("j1", jobv1.JobState_JOB_STATE_RUNNING, nil)
	require.Error(t, err)

	_, err = cancelOutcome("j1", 0, connect.NewError(connect.CodeFailedPrecondition, errors.New("job is completed")))
	require.ErrorContains(t, err, "job j1 has already finished")
	require.ErrorContains(t, err, "job is completed")

	_, err = cancelOutcome("j1", 0, connect.NewError(connect.CodeNotFound, errors.New("nope")))
	require.ErrorContains(t, err, "job j1 not found")

	_, err = cancelOutcome("j1", 0, connect.NewError(connect.CodeInternal, errors.New("boom")))
	require.ErrorContains(t, err, "failed to cancel job j1")
}
