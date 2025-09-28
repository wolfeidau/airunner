package commands

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
)

type SubmitCmd struct {
	Server     string            `help:"Server URL" default:"https://localhost:8080"`
	Queue      string            `help:"Queue name" default:"default"`
	Repository string            `arg:"" help:"Repository URL to process"`
	Commit     string            `help:"Commit hash or identifier" default:"main"`
	Branch     string            `help:"Branch name" default:"main"`
	Owner      string            `help:"Job owner" default:""`
	Env        map[string]string `help:"Environment variables"`
	Metadata   map[string]string `help:"Additional metadata"`
	List       bool              `help:"List jobs after submission" default:"true"`
}

func (s *SubmitCmd) Run(ctx context.Context, globals *Globals) error {
	fmt.Printf("Submitting job for repository %s to server %s\n", s.Repository, s.Server)

	// Create clients
	config := client.Config{
		ServerURL: s.Server,
		Timeout:   30 * time.Second,
		Debug:     globals.Debug,
	}
	clients := client.NewClients(config)

	// Submit job
	jobID, err := s.submitJob(ctx, clients)
	if err != nil {
		return fmt.Errorf("failed to submit job: %w", err)
	}

	fmt.Printf("Job submitted successfully with ID: %s\n", jobID)

	// List jobs to show it was queued
	if s.List {
		if err := s.listJobs(ctx, clients); err != nil {
			fmt.Printf("Failed to list jobs: %v\n", err)
		}
	}

	return nil
}

func (s *SubmitCmd) submitJob(ctx context.Context, clients *client.Clients) (string, error) {
	// Set default environment if none provided
	env := s.Env
	if env == nil {
		env = map[string]string{
			"BUILD_TYPE": "release",
			"NODE_ENV":   "production",
		}
	}

	// Set default metadata if none provided
	metadata := s.Metadata
	if metadata == nil {
		metadata = map[string]string{
			"submitter": "airunner-agent",
			"priority":  "normal",
		}
	}

	// Set default owner if not provided
	owner := s.Owner
	if owner == "" {
		owner = "airunner-user"
	}

	req := &jobv1.EnqueueJobRequest{
		RequestId: uuid.New().String(), // Idempotency token
		Queue:     s.Queue,
		JobParams: &jobv1.JobParams{
			Repository:  s.Repository,
			Commit:      s.Commit,
			Branch:      s.Branch,
			Environment: env,
			Metadata:    metadata,
			Owner:       owner,
		},
	}

	resp, err := clients.Job.EnqueueJob(ctx, connect.NewRequest(req))
	if err != nil {
		return "", fmt.Errorf("failed to enqueue job: %w", err)
	}

	return resp.Msg.JobId, nil
}

func (s *SubmitCmd) listJobs(ctx context.Context, clients *client.Clients) error {
	req := &jobv1.ListJobsRequest{
		Queue:    s.Queue,
		State:    jobv1.JobState_JOB_STATE_UNSPECIFIED, // All states
		Page:     1,
		PageSize: 10,
	}

	resp, err := clients.Job.ListJobs(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to list jobs: %w", err)
	}

	fmt.Printf("\nCurrent jobs in queue '%s':\n", s.Queue)
	fmt.Printf("%-36s %-15s %-30s %-20s\n", "Job ID", "State", "Repository", "Created At")
	fmt.Println("────────────────────────────────────────────────────────────────────────────────────────────────────")

	for _, job := range resp.Msg.Jobs {
		state := jobStateToString(job.State)
		createdAt := job.CreatedAt.AsTime().Format("2006-01-02 15:04:05")
		repo := job.JobParams.Repository
		if len(repo) > 30 {
			repo = repo[:27] + "..."
		}
		fmt.Printf("%-36s %-15s %-30s %-20s\n",
			job.JobId,
			state,
			repo,
			createdAt)
	}

	fmt.Printf("\nTotal jobs: %d\n", len(resp.Msg.Jobs))
	return nil
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
