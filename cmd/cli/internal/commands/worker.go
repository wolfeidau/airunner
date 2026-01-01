package commands

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/cenkalti/backoff/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/worker"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// addJitter adds random jitter to a duration to prevent thundering herd.
// Returns a duration between base*(1-jitterFactor) and base*(1+jitterFactor).
// For jitterFactor=0.25, returns a value between 75% and 125% of base.
func addJitter(base time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 {
		return base
	}
	// Calculate jitter range: base * (1 - jitterFactor) to base * (1 + jitterFactor)
	min := float64(base) * (1.0 - jitterFactor)
	max := float64(base) * (1.0 + jitterFactor)
	//nolint:gosec // G404: Using math/rand for timing jitter is safe and appropriate
	jittered := min + rand.Float64()*(max-min)
	return time.Duration(jittered)
}

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

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	config := client.Config{
		ServerURL: w.Server,
		Timeout:   w.ClientTimeout,
		Debug:     globals.Debug,
	}
	clients, err := client.NewClients(config, connect.WithInterceptors(otelInterceptor))
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

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
			if isDeadlineExceeded(err) {
				continue
			}
			log.Error().Err(err).Stack().Msg("Error processing job")
			// Sleep with jitter after error to prevent thundering herd on retry
			time.Sleep(addJitter(5*time.Second, 0.25))
			continue
		}

		if jobFound {
			// Reset backoff when we found and processed a job
			bkoffStrategy.Reset()
			// Brief pause with jitter before next poll to prevent thundering herd
			time.Sleep(addJitter(1*time.Second, 0.25))
		} else {
			// No job found, use exponential backoff (already has randomization)
			time.Sleep(bkoffStrategy.NextBackOff())
		}
	}
}

func (w *WorkerCmd) processJob(ctx context.Context, clients *client.Clients) (bool, error) {
	// Create a context for dequeue without the client timeout
	dequeueCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Dequeue a job
	req := &jobv1.DequeueJobRequest{
		Queue:                    w.Queue,
		MaxJobs:                  1,
		VisibilityTimeoutSeconds: w.VisibilityTimeout,
	}

	stream, err := clients.Job.DequeueJob(dequeueCtx, connect.NewRequest(req))
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

	// Create event batcher with job's ExecutionConfig
	batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		return eventStream.Send(&jobv1.PublishJobEventsRequest{
			TaskToken: taskToken,
			Events:    []*jobv1.JobEvent{event},
		})
	})

	executor := worker.NewJobExecutor(eventStream, taskToken, batcher)

	// Create a separate context for timeout extension so we can cancel it when the job completes
	timeoutCtx, cancelTimeout := context.WithCancel(ctx)
	defer cancelTimeout()

	go w.extendVisibilityTimeout(timeoutCtx, clients, taskToken)

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

func isDeadlineExceeded(err error) bool {
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return connErr.Code() == connect.CodeDeadlineExceeded
	}
	return false
}
