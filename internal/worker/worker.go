package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/util"
	consolestream "github.com/wolfeidau/console-stream"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type JobExecutor struct {
	eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse]
	taskToken   string
	pid         int32 // Process ID from ProcessStart event
	batcher     *EventBatcher
}

// NewJobExecutor creates a JobExecutor with event batching support
// The batcher is required for unified sequence numbering
func NewJobExecutor(eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse], taskToken string, batcher *EventBatcher) *JobExecutor {
	return &JobExecutor{
		eventStream: eventStream,
		taskToken:   taskToken,
		batcher:     batcher,
	}
}

func (je *JobExecutor) Execute(ctx context.Context, job *jobv1.Job) error {
	log.Info().Str("job_id", job.JobId).Msg("Starting job execution")

	// Ensure batcher is stopped and flushes any remaining events
	defer func() {
		if je.batcher != nil {
			if err := je.batcher.Stop(ctx); err != nil {
				log.Error().Err(err).Msg("Failed to stop event batcher")
			}
		}
	}()

	// Determine flush interval from ExecutionConfig
	flushInterval := 100 * time.Millisecond // Default: 100ms
	if job.ExecutionConfig != nil && job.ExecutionConfig.OutputFlushIntervalMillis > 0 {
		flushInterval = time.Duration(job.ExecutionConfig.OutputFlushIntervalMillis) * time.Millisecond
		log.Debug().
			Dur("flush_interval", flushInterval).
			Msg("Using configured output flush interval")
	} else {
		log.Debug().
			Dur("flush_interval", flushInterval).
			Msg("Using default output flush interval")
	}

	// Create console-stream process options
	opts := []consolestream.ProcessOption{
		consolestream.WithEnvMap(job.JobParams.Environment),
		consolestream.WithFlushInterval(flushInterval),
	}

	// Set process type
	switch job.JobParams.ProcessType {
	case jobv1.ProcessType_PROCESS_TYPE_PTY:
		opts = append(opts, consolestream.WithPTYMode())
	case jobv1.ProcessType_PROCESS_TYPE_PIPE:
		opts = append(opts, consolestream.WithPipeMode())
	default:
		opts = append(opts, consolestream.WithPTYMode()) // Default to PTY
	}

	// Set working directory if specified
	if job.JobParams.WorkingDirectory != "" {
		// Note: console-stream doesn't have a direct working directory option
		// We would need to handle this by changing directory or modifying the command
		log.Info().Str("dir", job.JobParams.WorkingDirectory).Msg("Changing working directory")

		opts = append(opts, consolestream.WithWorkingDir(job.JobParams.WorkingDirectory))
	}

	// Create the process
	process := consolestream.NewProcess(job.JobParams.Command, job.JobParams.Args, opts...)

	// Execute and stream the process
	for event, err := range process.ExecuteAndStream(ctx) {
		if err != nil {
			return je.handleStreamError(err, job.JobId)
		}

		// Delegate event handling to testable helper method
		if err := je.handleEvent(event, job.JobId); err != nil {
			log.Error().Err(err).Str("job_id", job.JobId).Msg("Failed to handle event")
			return fmt.Errorf("event handling failed: %w", err)
		}

		// ProcessEnd returns nil from handleEvent, but we need to exit the loop
		if _, ok := event.Event.(*consolestream.ProcessEnd); ok {
			return nil
		}
	}

	return errors.New("failed job execution") // Should not reach here normally
}

// handleEvent dispatches individual events to appropriate handlers
// This method is easily unit testable with concrete event types
func (je *JobExecutor) handleEvent(event consolestream.Event, jobID string) error {
	switch e := event.Event.(type) {
	case *consolestream.ProcessStart:
		return je.publishProcessStartEvent(e)

	case *consolestream.OutputData:
		// Buffer output through batcher for batching and unified sequencing
		if err := je.batcher.AddOutput(context.Background(), e.Data, 0); err != nil {
			log.Error().Err(err).Str("job_id", jobID).Msg("Failed to buffer output event")
			// Continue - output events are best-effort
		}
		return nil

	case *consolestream.ProcessEnd:
		// Flush any buffered outputs before ProcessEnd
		if err := je.batcher.Flush(context.Background()); err != nil {
			log.Error().Err(err).Msg("Failed to flush batch before process end event")
		}
		return je.publishProcessEndEvent(e)

	case *consolestream.HeartbeatEvent:
		// Drop heartbeat events for now - they're sent every flush interval
		// and we don't currently need them. May implement in the future.
		return nil

	default:
		// Handle other unexpected event types
		log.Info().Str("event", event.String()).Msg("Received unhandled event")
		return nil
	}
}

// handleStreamError handles errors from the event stream
// Flushes buffered events and publishes an error event
func (je *JobExecutor) handleStreamError(err error, jobID string) error {
	log.Error().Err(err).Str("job_id", jobID).Msg("Job execution failed")

	// Flush any buffered outputs first
	if flushErr := je.batcher.Flush(context.Background()); flushErr != nil {
		log.Error().Err(flushErr).Msg("Failed to flush batch before error event")
	}

	// Attempt to publish error event - if this fails, log but continue to return original error
	if publishErr := je.publishErrorEvent(err.Error()); publishErr != nil {
		log.Error().Err(publishErr).Msg("Failed to publish error event after job failure")
	}

	return fmt.Errorf("job execution failed: %w", err)
}

func (je *JobExecutor) publishProcessStartEvent(event *consolestream.ProcessStart) error {
	// Store PID for use in ProcessEnd event
	je.pid = util.AsInt32(event.PID)

	startEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
		EventData: &jobv1.JobEvent_ProcessStart{
			ProcessStart: &jobv1.ProcessStartEvent{
				Pid:       je.pid,
				StartedAt: timestamppb.Now(),
			},
		},
	}

	// Route through batcher for unified sequence numbering
	if err := je.batcher.AddEvent(context.Background(), startEvent); err != nil {
		log.Error().Err(err).Msg("Failed to add process start event to batcher")
		return fmt.Errorf("failed to publish process start event: %w", err)
	}

	return nil
}

// publishOutputEvent is deprecated - outputs should be buffered through EventBatcher.AddOutput()
// which will batch them into OUTPUT_BATCH events for efficiency

func (je *JobExecutor) publishProcessEndEvent(event *consolestream.ProcessEnd) error {
	endEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
		EventData: &jobv1.JobEvent_ProcessEnd{
			ProcessEnd: &jobv1.ProcessEndEvent{
				Pid:         je.pid, // Use stored PID from ProcessStart
				ExitCode:    util.AsInt32(event.ExitCode),
				RunDuration: durationpb.New(event.Duration),
			},
		},
	}

	// Route through batcher for unified sequence numbering
	if err := je.batcher.AddEvent(context.Background(), endEvent); err != nil {
		log.Error().Err(err).Msg("Failed to add process end event to batcher")
		return fmt.Errorf("failed to publish process end event: %w", err)
	}

	return nil
}

func (je *JobExecutor) publishErrorEvent(errorMessage string) error {
	errorEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_ERROR,
		EventData: &jobv1.JobEvent_ProcessError{
			ProcessError: &jobv1.ProcessErrorEvent{
				ErrorMessage: errorMessage,
			},
		},
	}

	// Route through batcher for unified sequence numbering
	if err := je.batcher.AddEvent(context.Background(), errorEvent); err != nil {
		log.Error().Err(err).Msg("Failed to add error event to batcher")
		return fmt.Errorf("failed to publish error event: %w", err)
	}

	return nil
}
