package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/cenkalti/backoff/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/worker"
	"github.com/wolfeidau/airunner/internal/worker/wal"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type WorkerCmd struct {
	Server            string        `help:"Server URL" default:"https://localhost"`
	Queue             string        `help:"Queue name to process" default:"default"`
	Credential        string        `help:"Credential name (uses default if not specified)"`
	ClientTimeout     time.Duration `help:"Client timeout in seconds" default:"5m"`
	VisibilityTimeout int32         `help:"Visibility timeout in seconds" default:"300"`
}

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Caller().Logger()

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")

	log.Info().Str("queue", w.Queue).Str("server", w.Server).Msg("Worker starting")

	// Initialize credential store and auth interceptor
	store, err := credentials.NewStore("")
	if err != nil {
		return fmt.Errorf("failed to initialize credentials: %w", err)
	}

	authInterceptor, err := credentials.NewAuthInterceptor(store, w.Credential, w.Server)
	if err != nil {
		return err
	}

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	config := client.Config{
		ServerURL: w.Server,
		Timeout:   w.ClientTimeout,
		Debug:     globals.Debug,
	}
	clients, err := client.NewClients(config,
		connect.WithInterceptors(authInterceptor),
		connect.WithInterceptors(otelInterceptor),
	)
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

	// Create WAL for durable event persistence
	jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId)
	if err != nil {
		return true, fmt.Errorf("failed to create WAL: %w", err)
	}
	defer func() {
		if err := jobWAL.Stop(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to stop WAL")
		}
	}()

	// Wrap gRPC stream as EventSender for WAL with reconnection support
	sender := &grpcEventSender{
		clients:   clients,
		stream:    eventStream,
		taskToken: taskToken,
	}

	// Start async sender for WAL
	if err := jobWAL.Start(ctx, sender); err != nil {
		return true, fmt.Errorf("failed to start WAL sender: %w", err)
	}

	// Create event batcher with WAL callback
	// EventBatcher writes to WAL with fsync (synchronous)
	// Async sender will retry sending to server until success
	batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		return jobWAL.Append(ctx, event)
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

	// CRITICAL: Flush WAL before completing job to ensure zero data loss
	// This blocks until all events are sent or context times out
	// Create a context with timeout for the flush (use remaining visibility timeout)
	flushCtx, flushCancel := context.WithTimeout(ctx, time.Duration(w.VisibilityTimeout)*time.Second)
	defer flushCancel()

	flushErr := jobWAL.Flush(flushCtx)
	if flushErr != nil {
		log.Error().Err(flushErr).Str("job_id", job.JobId).Msg("Failed to flush WAL events")
		// If we can't flush events, the job must FAIL
		// This ensures we don't lose events by marking job as completed
		executeErr = fmt.Errorf("failed to flush WAL events: %w", flushErr)
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

// grpcEventSender wraps a Connect RPC stream as an EventSender for the WAL
// It handles automatic reconnection when the stream is closed
type grpcEventSender struct {
	clients   *client.Clients
	stream    *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse]
	taskToken string
	mu        sync.Mutex
}

// Send implements wal.EventSender
// If the stream is closed (EOF), it will recreate the stream and retry
func (s *grpcEventSender) Send(ctx context.Context, events []*jobv1.JobEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.stream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: s.taskToken,
		Events:    events,
	})

	// If we get EOF, the stream is dead - recreate it and retry
	if err != nil && (errors.Is(err, io.EOF) || isStreamClosed(err)) {
		log.Warn().Err(err).Msg("Event stream closed, reconnecting...")

		// Recreate the stream
		newStream := s.clients.Events.PublishJobEvents(ctx)
		s.stream = newStream

		// Retry send on new stream
		err = s.stream.Send(&jobv1.PublishJobEventsRequest{
			TaskToken: s.taskToken,
			Events:    events,
		})

		if err == nil {
			log.Info().Msg("Successfully reconnected event stream")
		}
	}

	return err
}

// isStreamClosed checks if error indicates a closed stream
func isStreamClosed(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		// Check for common gRPC stream closed errors
		(errStr != "" && (errors.Is(err, io.EOF) ||
			errors.Is(err, io.ErrUnexpectedEOF) ||
			// Connect RPC errors
			strings.Contains(errStr, "EOF") ||
			strings.Contains(errStr, "stream") && strings.Contains(errStr, "closed") ||
			strings.Contains(errStr, "connection") && strings.Contains(errStr, "closed")))
}
