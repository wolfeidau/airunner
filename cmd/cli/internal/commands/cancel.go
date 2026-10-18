package commands

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
	"github.com/wolfeidau/airunner/internal/client"
)

// CancelCmd cancels a scheduled or running job. Cancel is idempotent: the RPC returns
// CANCELLED both for a fresh cancel and for a job that was already cancelled, so both
// print the same message.
type CancelCmd struct {
	Server     string        `help:"Server URL" default:"https://localhost"`
	Credential string        `help:"Credential name (uses default if not specified)"`
	Timeout    time.Duration `help:"Request timeout" default:"30s"`
	JobID      string        `arg:"" help:"Job ID to cancel"`
}

func (c *CancelCmd) Run(ctx context.Context, globals *Globals) error {
	store, err := credentials.NewStore("")
	if err != nil {
		return fmt.Errorf("failed to initialize credentials: %w", err)
	}

	authInterceptor, err := credentials.NewAuthInterceptor(store, c.Credential, c.Server)
	if err != nil {
		return err
	}

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	clients, err := client.NewClients(client.Config{
		ServerURL: c.Server,
		Timeout:   c.Timeout,
		Debug:     globals.Debug,
	},
		connect.WithInterceptors(authInterceptor),
		connect.WithInterceptors(otelInterceptor),
	)
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

	resp, err := clients.Job.CancelJob(ctx, connect.NewRequest(&jobv1.CancelJobRequest{JobId: c.JobID}))
	var state jobv1.JobState
	if err == nil {
		state = resp.Msg.State
	}
	msg, err := cancelOutcome(c.JobID, state, err)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

// cancelOutcome maps the CancelJob result to a user message or error.
func cancelOutcome(jobID string, state jobv1.JobState, err error) (string, error) {
	if err != nil {
		switch connect.CodeOf(err) {
		case connect.CodeFailedPrecondition:
			return "", fmt.Errorf("job %s has already finished: %w", jobID, err)
		case connect.CodeNotFound:
			return "", fmt.Errorf("job %s not found: %w", jobID, err)
		default:
			return "", fmt.Errorf("failed to cancel job %s: %w", jobID, err)
		}
	}
	if state != jobv1.JobState_JOB_STATE_CANCELLED {
		return "", fmt.Errorf("unexpected state %s after cancelling job %s", state, jobID)
	}
	return fmt.Sprintf("Job %s cancelled", jobID), nil
}
