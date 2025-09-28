package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"connectrpc.com/connect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type WorkerCmd struct {
	Server  string `help:"Server URL" default:"https://localhost:8080"`
	Queue   string `help:"Queue name to process" default:"default"`
	Timeout int    `help:"Visibility timeout in seconds" default:"300"`
}

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Printf("Starting worker for queue '%s' connecting to %s", w.Queue, w.Server)

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
			log.Println("Looking for jobs...")
		}

		if err := w.processJob(ctx, clients); err != nil {
			log.Printf("Error processing job: %v", err)
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

	log.Printf("Received job %s: %s", job.JobId, job.JobParams.Repository)

	// Start publishing events
	eventStream := clients.Events.PublishJobEvents(ctx)

	// Publish job start event
	startEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
		EventData: &jobv1.JobEvent_ProcessStart{
			ProcessStart: &jobv1.ProcessStartEvent{
				Pid: func() int32 {
					pid := os.Getpid()
					if pid > 2147483647 {
						return 2147483647
					}
					// #nosec G115 - bounded by explicit check
					return int32(pid)
				}(),
				StartedAt: timestamppb.Now(),
			},
		},
	}

	if err := eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{startEvent},
	}); err != nil {
		return fmt.Errorf("failed to send start event: %w", err)
	}

	// Simulate job execution
	startTime := time.Now()
	success := w.executeJob(ctx, job, taskToken, eventStream)
	duration := time.Since(startTime)

	// Publish job end event
	endEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
		EventData: &jobv1.JobEvent_ProcessEnd{
			ProcessEnd: &jobv1.ProcessEndEvent{
				Pid: func() int32 {
					pid := os.Getpid()
					if pid > 2147483647 {
						return 2147483647
					}
					// #nosec G115 - bounded by explicit check
					return int32(pid)
				}(),
				ExitCode: func() int32 {
					if success {
						return 0
					} else {
						return 1
					}
				}(),
				RunDuration: durationpb.New(duration),
			},
		},
	}

	if err := eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{endEvent},
	}); err != nil {
		log.Printf("Failed to send end event: %v", err)
	}

	if _, err := eventStream.CloseAndReceive(); err != nil {
		log.Printf("Failed to close event stream: %v", err)
	}

	// Complete the job
	result := &jobv1.JobResult{
		JobId:   job.JobId,
		Success: success,
		ExitCode: func() int32 {
			if success {
				return 0
			} else {
				return 1
			}
		}(),
		StartedAt:   timestamppb.New(startTime),
		CompletedAt: timestamppb.Now(),
	}

	if !success {
		result.ErrorMessage = "Job execution failed"
	}

	_, err = clients.Job.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{
		TaskToken: taskToken,
		JobResult: result,
	}))

	if err != nil {
		return fmt.Errorf("failed to complete job: %w", err)
	}

	log.Printf("Job %s completed successfully", job.JobId)
	return nil
}

func (w *WorkerCmd) executeJob(ctx context.Context, job *jobv1.Job, taskToken string, eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse]) bool {
	log.Printf("Executing job for repository: %s", job.JobParams.Repository)

	// Simulate some work - in a real implementation, this would clone the repo and run the job
	w.publishOutput(taskToken, eventStream, fmt.Sprintf("Cloning repository %s...\n", job.JobParams.Repository))
	time.Sleep(2 * time.Second)

	w.publishOutput(taskToken, eventStream, "Building project...\n")
	time.Sleep(3 * time.Second)

	w.publishOutput(taskToken, eventStream, "Build completed successfully!\n")

	return true // Success
}

func (w *WorkerCmd) publishOutput(taskToken string, eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse], output string) {
	outputEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{
			Output: &jobv1.OutputEvent{
				Output: []byte(output),
			},
		},
	}

	if err := eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{outputEvent},
	}); err != nil {
		log.Printf("Failed to send output event: %v", err)
	}
}
