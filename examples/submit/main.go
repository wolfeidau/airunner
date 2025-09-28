package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("Usage: submit <server-url> <repository-url>")
	}

	serverURL := os.Args[1]
	repository := os.Args[2]

	log.Printf("Submitting job for repository %s to server %s", repository, serverURL)

	// Create client
	client := jobv1connect.NewJobServiceClient(http.DefaultClient, serverURL)

	// Submit job
	jobID, err := submitJob(context.Background(), client, repository)
	if err != nil {
		log.Fatalf("Failed to submit job: %v", err)
	}

	log.Printf("Job submitted successfully with ID: %s", jobID)

	// List jobs to show it was queued
	if err := listJobs(context.Background(), client); err != nil {
		log.Printf("Failed to list jobs: %v", err)
	}
}

func submitJob(ctx context.Context, client jobv1connect.JobServiceClient, repository string) (string, error) {
	req := &jobv1.EnqueueJobRequest{
		RequestId: uuid.New().String(), // Idempotency token
		Queue:     "default",
		JobParams: &jobv1.JobParams{
			Repository: repository,
			Commit:     "main",
			Branch:     "main",
			Environment: map[string]string{
				"BUILD_TYPE": "release",
				"NODE_ENV":   "production",
			},
			Metadata: map[string]string{
				"submitter": "example-client",
				"priority":  "normal",
			},
			Owner: "example-user",
		},
	}

	resp, err := client.EnqueueJob(ctx, connect.NewRequest(req))
	if err != nil {
		return "", fmt.Errorf("failed to enqueue job: %w", err)
	}

	return resp.Msg.JobId, nil
}

func listJobs(ctx context.Context, client jobv1connect.JobServiceClient) error {
	req := &jobv1.ListJobsRequest{
		Queue:    "default",
		State:    jobv1.JobState_JOB_STATE_UNSPECIFIED, // All states
		Page:     1,
		PageSize: 10,
	}

	resp, err := client.ListJobs(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to list jobs: %w", err)
	}

	fmt.Printf("\nCurrent jobs in queue:\n")
	fmt.Printf("%-36s %-15s %-30s %-20s\n", "Job ID", "State", "Repository", "Created At")
	fmt.Println(strings.Repeat("-", 100))

	for _, job := range resp.Msg.Jobs {
		state := strings.TrimPrefix(job.State.String(), "JOB_STATE_")
		createdAt := job.CreatedAt.AsTime().Format("2006-01-02 15:04:05")
		fmt.Printf("%-36s %-15s %-30s %-20s\n",
			job.JobId,
			state,
			job.JobParams.Repository,
			createdAt)
	}

	fmt.Printf("\nTotal jobs: %d\n", len(resp.Msg.Jobs))
	return nil
}