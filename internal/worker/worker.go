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
	sequence    int64
	pid         int32 // Process ID from ProcessStart event
	batcher     *EventBatcher
}

func NewJobExecutor(eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse], taskToken string) *JobExecutor {
	return &JobExecutor{
		eventStream: eventStream,
		taskToken:   taskToken,
		sequence:    1, // Start sequence at 1
	}
}

// NewJobExecutorWithBatcher creates a JobExecutor with event batching support
// The batcher will be initialized with the job's ExecutionConfig
func NewJobExecutorWithBatcher(eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse], taskToken string, batcher *EventBatcher) *JobExecutor {
	return &JobExecutor{
		eventStream: eventStream,
		taskToken:   taskToken,
		sequence:    1, // Start sequence at 1
		batcher:     batcher,
	}
}

func (je *JobExecutor) Execute(ctx context.Context, job *jobv1.Job) error {
	log.Info().Str("job_id", job.JobId).Msg("Starting job execution")

	// Ensure batcher is stopped and flushes any remaining events
	defer func() {
		if je.batcher != nil {
			if err := je.batcher.Stop(); err != nil {
				log.Error().Err(err).Msg("Failed to stop event batcher")
			}
		}
	}()

	// Create console-stream process options
	opts := []consolestream.ProcessOption{
		consolestream.WithEnvMap(job.JobParams.Environment),
		consolestream.WithFlushInterval(3 * time.Second),
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
	}

	// Create the process
	process := consolestream.NewProcess(job.JobParams.Command, job.JobParams.Args, opts...)

	// Execute and stream the process
	for event, err := range process.ExecuteAndStream(ctx) {
		if err != nil {
			log.Error().Err(err).Str("job_id", job.JobId).Msg("Job execution failed")

			// Flush any buffered outputs first
			if je.batcher != nil {
				if flushErr := je.batcher.Flush(); flushErr != nil {
					log.Error().Err(flushErr).Msg("Failed to flush batch before error event")
				}
			}

			// Attempt to publish error event - if this fails, log but continue to return original error
			if publishErr := je.publishErrorEvent(err.Error()); publishErr != nil {
				log.Error().Err(publishErr).Msg("Failed to publish error event after job failure")
			}

			return fmt.Errorf("job execution failed: %w", err)
		}

		// Handle different event types
		switch e := event.Event.(type) {
		case *consolestream.ProcessStart:
			if err := je.publishProcessStartEvent(e); err != nil {
				log.Error().Err(err).Str("job_id", job.JobId).Msg("Failed to publish process start event")
				return fmt.Errorf("event publishing failed: %w", err)
			}

		case *consolestream.OutputData:
			// Use batcher for outputs if available, otherwise publish directly
			if je.batcher != nil {
				if err := je.batcher.AddOutput(e.Data, 0); err != nil {
					log.Error().Err(err).Str("job_id", job.JobId).Msg("Failed to buffer output event")
					// Continue - output events are best-effort
				}
			} else {
				// Fallback: publish directly if no batcher
				je.publishOutputEvent(e.Data)
			}

		case *consolestream.ProcessEnd:
			// Flush any buffered outputs before ProcessEnd
			if je.batcher != nil {
				if err := je.batcher.Flush(); err != nil {
					log.Error().Err(err).Msg("Failed to flush batch before process end event")
				}
			}

			if err := je.publishProcessEndEvent(e); err != nil {
				log.Error().Err(err).Str("job_id", job.JobId).Msg("Failed to publish process end event")
				return fmt.Errorf("event publishing failed: %w", err)
			}
			return nil

		default:
			// Handle other event types like heartbeat if needed
			log.Info().Str("event", event.String()).Msg("Received unhandled event")
		}
	}

	return errors.New("failed job execution") // Should not reach here normally
}

// assignSequence sets the sequence number and timestamp for an event
func (je *JobExecutor) assignSequence(event *jobv1.JobEvent) {
	event.Sequence = je.sequence
	je.sequence++

	if event.Timestamp == nil {
		event.Timestamp = timestamppb.Now()
	}
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

	je.assignSequence(startEvent)

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{startEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send process start event")
		return fmt.Errorf("failed to publish process start event: %w", err)
	}

	return nil
}

func (je *JobExecutor) publishOutputEvent(output []byte) {
	outputEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{
			Output: &jobv1.OutputEvent{
				Output: output,
			},
		},
	}

	je.assignSequence(outputEvent)

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{outputEvent},
	}); err != nil {
		// Log but don't fail the job - output events are best-effort
		// Losing individual output lines shouldn't terminate job execution
		log.Warn().Err(err).Msg("Failed to send output event - continuing execution")
	}
}

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

	je.assignSequence(endEvent)

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{endEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send process end event")
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

	je.assignSequence(errorEvent)

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{errorEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send error event")
		return fmt.Errorf("failed to publish error event: %w", err)
	}

	return nil
}
