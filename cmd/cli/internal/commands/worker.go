package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/worker"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type WorkerCmd struct {
	Server            string        `help:"Server URL" default:"https://localhost:8993"`
	Queue             string        `help:"Queue name to process" default:"default"`
	ClientTimeout     time.Duration `help:"Client timeout in seconds" default:"5m"`
	VisibilityTimeout int32         `help:"Visibility timeout in seconds" default:"300"`
}

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Caller().Logger()

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")

	log.Info().Str("queue", w.Queue).Str("server", w.Server).Msg("Worker starting")

	// Create clients
	config := client.Config{
		ServerURL: w.Server,
		Timeout:   w.ClientTimeout,
		Debug:     globals.Debug,
	}
	clients := client.NewClients(config)

	bkoffStrategy := backoff.NewExponentialBackOff()
	bkoffStrategy.InitialInterval = 1 * time.Second
	bkoffStrategy.MaxInterval = 10 * time.Second
	bkoffStrategy.Multiplier = 1.5
	bkoffStrategy.RandomizationFactor = 0.5

	// Start worker loop
	for {
		if globals.Debug {
			log.Debug().Msg("Looking for jobs...")
		}

		jobFound, err := w.processJob(ctx, clients)
		if err != nil {
			log.Error().Err(err).Msg("Error processing job")
			time.Sleep(5 * time.Second)
			continue
		}

		if jobFound {
			// Reset backoff when we found and processed a job
			bkoffStrategy.Reset()
			// Brief pause before next poll
			time.Sleep(1 * time.Second)
		} else {
			// No job found, use exponential backoff
			time.Sleep(bkoffStrategy.NextBackOff())
		}
	}
}

func (w *WorkerCmd) processJob(ctx context.Context, clients *client.Clients) (bool, error) {
	// Dequeue a job
	req := &jobv1.DequeueJobRequest{
		Queue:                    w.Queue,
		MaxJobs:                  1,
		VisibilityTimeoutSeconds: w.VisibilityTimeout,
	}

	stream, err := clients.Job.DequeueJob(ctx, connect.NewRequest(req))
	if err != nil {
		return false, fmt.Errorf("failed to dequeue job: %w", err)
	}
	defer stream.Close()

	// Wait for a job
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return false, fmt.Errorf("stream error: %w", err)
		}
		return false, nil // No jobs available
	}

	job := stream.Msg().Job
	taskToken := stream.Msg().TaskToken

	log.Info().Str("job_id", job.JobId).Str("repository", job.JobParams.Repository).Msg("Job dequeued")

	if job.JobParams.Command == "" {
		log.Error().Str("job_id", job.JobId).Msg("No command specified for job")
		return true, errors.New("no command specified")
	}

	eventStream := clients.Events.PublishJobEvents(ctx)

	executor := worker.NewJobExecutor(eventStream, taskToken)

	go w.extendVisibilityTimeout(ctx, clients, taskToken)

	// Execute the job and capture result
	var jobResult *jobv1.JobResult
	executeErr := executor.Execute(ctx, job)

	// Close event stream first
	if _, err := eventStream.CloseAndReceive(); err != nil {
		log.Error().Err(err).Msg("Failed to close event stream")
	}

	// Build job result based on execution outcome
	if executeErr != nil {
		log.Error().Err(executeErr).Str("job_id", job.JobId).Msg("Job execution failed")
		jobResult = &jobv1.JobResult{
			JobId:        job.JobId,
			Success:      false,
			ExitCode:     1,
			ErrorMessage: executeErr.Error(),
			StartedAt:    job.UpdatedAt, // Job was marked RUNNING when dequeued
			CompletedAt:  timestamppb.Now(),
		}
	} else {
		log.Info().Str("job_id", job.JobId).Msg("Job executed successfully")
		jobResult = &jobv1.JobResult{
			JobId:       job.JobId,
			Success:     true,
			ExitCode:    0,
			StartedAt:   job.UpdatedAt,
			CompletedAt: timestamppb.Now(),
		}
	}

	// Complete the job with the result
	completeReq := &jobv1.CompleteJobRequest{
		TaskToken: taskToken,
		JobResult: jobResult,
	}

	if _, err := clients.Job.CompleteJob(ctx, connect.NewRequest(completeReq)); err != nil {
		return true, fmt.Errorf("failed to complete job: %w", err)
	}

	log.Info().Str("job_id", job.JobId).Bool("success", jobResult.Success).Msg("Job completed")

	return true, nil
}

func (w *WorkerCmd) extendVisibilityTimeout(ctx context.Context, clients *client.Clients, taskToken string) {
	// Extend timeout every 60 seconds (well before the default 300s timeout)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Job completed or context cancelled
			return
		case <-ticker.C:
			// Extend visibility timeout by the configured timeout value
			req := &jobv1.UpdateJobRequest{
				Queue:                    w.Queue,
				TaskToken:                taskToken,
				VisibilityTimeoutSeconds: w.VisibilityTimeout,
			}

			if _, err := clients.Job.UpdateJob(ctx, connect.NewRequest(req)); err != nil {
				log.Error().Err(err).Msg("Failed to extend visibility timeout")
				// Continue trying - don't exit the goroutine
			} else {
				log.Debug().Msg("Extended visibility timeout")
			}
		}
	}
}
