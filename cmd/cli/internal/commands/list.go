package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
)

type ListCmd struct {
	Server   string `help:"Server URL" default:"https://localhost"`
	Queue    string `help:"Queue name to filter by" default:""`
	State    string `help:"Job state to filter by (scheduled, running, completed, failed, cancelled)" default:""`
	Page     int32  `help:"Page number" default:"1"`
	PageSize int32  `help:"Number of jobs per page" default:"20"`
	Watch    bool   `help:"Watch for changes (refresh every 5 seconds)" default:"false"`
}

func (l *ListCmd) Run(ctx context.Context, globals *Globals) error {
	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	// Create clients
	config := client.Config{
		ServerURL: l.Server,
		Timeout:   30 * time.Second,
		Debug:     globals.Debug,
	}
	clients, err := client.NewClients(config, connect.WithInterceptors(otelInterceptor))
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

	if l.Watch {
		return l.watchJobs(ctx, clients)
	}

	return l.listJobs(ctx, clients)
}

func (l *ListCmd) listJobs(ctx context.Context, clients *client.Clients) error {
	// Convert string state to enum
	state := l.stringToJobState(l.State)

	req := &jobv1.ListJobsRequest{
		Queue:    l.Queue,
		State:    state,
		Page:     l.Page,
		PageSize: l.PageSize,
	}

	resp, err := clients.Job.ListJobs(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to list jobs: %w", err)
	}

	l.printJobs(resp.Msg.Jobs, resp.Msg.LastPage)
	return nil
}

func (l *ListCmd) watchJobs(ctx context.Context, clients *client.Clients) error {
	fmt.Println("Watching jobs (press Ctrl+C to stop)...")
	fmt.Println()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Print initial state
	if err := l.listJobs(ctx, clients); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Clear screen and print updated jobs
			fmt.Print("\033[2J\033[H") // Clear screen and move cursor to top
			fmt.Printf("Jobs (updated at %s)\n", time.Now().Format("15:04:05"))
			fmt.Println()

			if err := l.listJobs(ctx, clients); err != nil {
				fmt.Printf("Error updating job list: %v\n", err)
			}
		}
	}
}

func (l *ListCmd) printJobs(jobs []*jobv1.Job, lastPage int32) {
	queueFilter := l.Queue
	if queueFilter == "" {
		queueFilter = "all"
	}

	stateFilter := "all"
	if l.State != "" {
		stateFilter = l.State
	}

	fmt.Printf("Jobs (queue: %s, state: %s, page: %d/%d):\n",
		queueFilter, stateFilter, l.Page, lastPage)

	if len(jobs) == 0 {
		fmt.Println("No jobs found.")
		return
	}

	// Print header
	fmt.Printf("%-36s %-12s %-15s %-25s %-20s %-20s\n",
		"Job ID", "Queue", "State", "Repository", "Owner", "Created At")
	fmt.Println(strings.Repeat("─", 130))

	// Print jobs
	for _, job := range jobs {
		state := jobStateToString(job.State)
		createdAt := job.CreatedAt.AsTime().Format("2006-01-02 15:04:05")

		// Truncate long repository names
		repo := job.JobParams.Repository
		if len(repo) > 25 {
			repo = repo[:22] + "..."
		}

		// Get queue from job metadata or use "unknown"
		queue := "unknown"
		if queueMeta, exists := job.JobParams.Metadata["queue"]; exists {
			queue = queueMeta
		}

		// Truncate long owner names
		owner := job.JobParams.Owner
		if len(owner) > 20 {
			owner = owner[:17] + "..."
		}

		fmt.Printf("%-36s %-12s %-15s %-25s %-20s %-20s\n",
			job.JobId,
			queue,
			state,
			repo,
			owner,
			createdAt)
	}

	fmt.Printf("\nTotal jobs on this page: %d\n", len(jobs))

	if lastPage > 1 {
		fmt.Printf("Pages: %d/%d\n", l.Page, lastPage)
		if l.Page < lastPage {
			fmt.Printf("Use --page=%d to see next page\n", l.Page+1)
		}
	}
}

func (l *ListCmd) stringToJobState(state string) jobv1.JobState {
	switch strings.ToLower(state) {
	case "scheduled":
		return jobv1.JobState_JOB_STATE_SCHEDULED
	case "running":
		return jobv1.JobState_JOB_STATE_RUNNING
	case "completed":
		return jobv1.JobState_JOB_STATE_COMPLETED
	case "failed":
		return jobv1.JobState_JOB_STATE_FAILED
	case "cancelled":
		return jobv1.JobState_JOB_STATE_CANCELLED
	default:
		return jobv1.JobState_JOB_STATE_UNSPECIFIED // All states
	}
}
