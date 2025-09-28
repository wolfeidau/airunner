package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	consolestream "github.com/wolfeidau/console-stream"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type JobExecutor struct {
	eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse]
	taskToken   string
}

func NewJobExecutor(eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse], taskToken string) *JobExecutor {
	return &JobExecutor{
		eventStream: eventStream,
		taskToken:   taskToken,
	}
}

func (je *JobExecutor) Execute(ctx context.Context, job *jobv1.Job) error {
	log.Info().Str("job_id", job.JobId).Msg("Starting job execution")

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
			je.publishErrorEvent(err.Error())
			return fmt.Errorf("job execution failed: %w", err)
		}

		// Handle different event types
		switch e := event.Event.(type) {
		case *consolestream.ProcessStart:
			je.publishProcessStartEvent(e)

		case *consolestream.OutputData:
			je.publishOutputEvent(e.Data)

		case *consolestream.ProcessEnd:
			je.publishProcessEndEvent(e)
			return nil

		default:
			// Handle other event types like heartbeat if needed
			log.Info().Str("event", event.String()).Msg("Received unhandled event")
		}
	}

	return errors.New("failed job execution") // Should not reach here normally
}

func (je *JobExecutor) publishProcessStartEvent(event *consolestream.ProcessStart) {
	startEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
		EventData: &jobv1.JobEvent_ProcessStart{
			ProcessStart: &jobv1.ProcessStartEvent{
				Pid:       asInt32(event.PID),
				StartedAt: timestamppb.Now(),
			},
		},
	}

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{startEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send process start event")
	}
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

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{outputEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send output event")
	}
}

func (je *JobExecutor) publishProcessEndEvent(event *consolestream.ProcessEnd) {
	endEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
		EventData: &jobv1.JobEvent_ProcessEnd{
			ProcessEnd: &jobv1.ProcessEndEvent{
				Pid:         0, // console-stream doesn't provide PID in ProcessEnd
				ExitCode:    asInt32(event.ExitCode),
				RunDuration: durationpb.New(event.Duration),
			},
		},
	}

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{endEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send process end event")
	}
}

func (je *JobExecutor) publishErrorEvent(errorMessage string) {
	errorEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_ERROR,
		EventData: &jobv1.JobEvent_ProcessError{
			ProcessError: &jobv1.ProcessErrorEvent{
				ErrorMessage: errorMessage,
			},
		},
	}

	if err := je.eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: je.taskToken,
		Events:    []*jobv1.JobEvent{errorEvent},
	}); err != nil {
		log.Error().Err(err).Msg("Failed to send error event")
	}
}

func asInt32(i int) int32 {
	if i > 2147483647 {
		return 2147483647
	}
	if i < -2147483648 {
		return -2147483648
	}
	// #nosec G115 - bounded by explicit check
	return int32(i)
}
