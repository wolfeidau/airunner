package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/worker"
)

type WorkerCmd struct {
	Server  string `help:"Server URL" default:"https://localhost:8080"`
	Queue   string `help:"Queue name to process" default:"default"`
	Timeout int    `help:"Visibility timeout in seconds" default:"300"`
}

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Info().Str("queue", w.Queue).Str("server", w.Server).Msg("Worker starting")

	// Create clients
	config := client.Config{
		ServerURL: w.Server,
		Timeout:   30 * time.Second,
		Debug:     globals.Debug,
	}
	clients := client.NewClients(config)

	// Start worker loop
	for {
		if globals.Debug {
			log.Debug().Msg("Looking for jobs...")
		}

		if err := w.processJob(ctx, clients); err != nil {
			log.Error().Err(err).Msg("Error processing job")
			time.Sleep(5 * time.Second)
			continue
		}

		// Brief pause before next poll
		time.Sleep(1 * time.Second)
	}
}

func (w *WorkerCmd) processJob(ctx context.Context, clients *client.Clients) error {
	// Dequeue a job
	var timeoutSeconds int32 = 300 // default
	if w.Timeout > 0 && w.Timeout <= 2147483647 {
		timeoutSeconds = int32(w.Timeout)
	}
	req := &jobv1.DequeueJobRequest{
		Queue:                    w.Queue,
		MaxJobs:                  1,
		VisibilityTimeoutSeconds: timeoutSeconds,
	}

	stream, err := clients.Job.DequeueJob(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to dequeue job: %w", err)
	}
	defer stream.Close()

	// Wait for a job
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return fmt.Errorf("stream error: %w", err)
		}
		return nil // No jobs available
	}

	job := stream.Msg().Job
	taskToken := stream.Msg().TaskToken

	log.Info().Str("job_id", job.JobId).Str("repository", job.JobParams.Repository).Msg("Job dequeued")

	if job.JobParams.Command == "" {
		log.Printf("Error: No command specified for job %s", job.JobId)
		return errors.New("no command specified")
	}

	eventStream := clients.Events.PublishJobEvents(ctx)

	executor := worker.NewJobExecutor(eventStream, taskToken)

	if err := executor.Execute(ctx, job); err != nil {
		return fmt.Errorf("failed to complete job: %w", err)
	}

	if _, err := eventStream.CloseAndReceive(); err != nil {
		return fmt.Errorf("failed to close event stream: %w", err)
	}

	log.Info().Str("job_id", job.JobId).Msg("Job completed successfully")

	return nil
}
