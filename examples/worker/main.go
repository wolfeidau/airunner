package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: worker <server-url>")
	}

	serverURL := os.Args[1]
	log.Printf("Connecting to job server at %s", serverURL)

	// Create clients
	jobClient := jobv1connect.NewJobServiceClient(http.DefaultClient, serverURL)
	eventsClient := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, serverURL)

	// Start worker loop
	for {
		log.Println("Looking for jobs...")

		if err := processJob(context.Background(), jobClient, eventsClient); err != nil {
			log.Printf("Error processing job: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Brief pause before next poll
		time.Sleep(1 * time.Second)
	}
}

func processJob(ctx context.Context, jobClient jobv1connect.JobServiceClient, eventsClient jobv1connect.JobEventsServiceClient) error {
	// Dequeue a job
	req := &jobv1.DequeueJobRequest{
		Queue:                    "default",
		MaxJobs:                  1,
		VisibilityTimeoutSeconds: 300, // 5 minutes
	}

	stream, err := jobClient.DequeueJob(ctx, connect.NewRequest(req))
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
	eventStream := eventsClient.PublishJobEvents(ctx)

	// Publish job start event
	startEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
		EventData: &jobv1.JobEvent_ProcessStart{
			ProcessStart: &jobv1.ProcessStartEvent{
				Pid:       int32(os.Getpid()),
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
	success := executeJob(ctx, job, taskToken, eventStream)
	duration := time.Since(startTime)

	// Publish job end event
	endEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
		EventData: &jobv1.JobEvent_ProcessEnd{
			ProcessEnd: &jobv1.ProcessEndEvent{
				Pid:         int32(os.Getpid()),
				ExitCode:    func() int32 { if success { return 0 } else { return 1 } }(),
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
		JobId:       job.JobId,
		Success:     success,
		ExitCode:    func() int32 { if success { return 0 } else { return 1 } }(),
		StartedAt:   timestamppb.New(startTime),
		CompletedAt: timestamppb.Now(),
	}

	if !success {
		result.ErrorMessage = "Job execution failed"
	}

	_, err = jobClient.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{
		TaskToken: taskToken,
		JobResult: result,
	}))

	if err != nil {
		return fmt.Errorf("failed to complete job: %w", err)
	}

	log.Printf("Job %s completed successfully", job.JobId)
	return nil
}

func executeJob(ctx context.Context, job *jobv1.Job, taskToken string, eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse]) bool {
	log.Printf("Executing job for repository: %s", job.JobParams.Repository)

	// Simulate some work - in a real implementation, this would clone the repo and run the job
	outputEvent := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{
			Output: &jobv1.OutputEvent{
				Output: []byte(fmt.Sprintf("Cloning repository %s...\n", job.JobParams.Repository)),
			},
		},
	}

	if err := eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{outputEvent},
	}); err != nil {
		log.Printf("Failed to send output event: %v", err)
	}

	// Simulate work
	time.Sleep(2 * time.Second)

	// More output
	outputEvent2 := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{
			Output: &jobv1.OutputEvent{
				Output: []byte("Building project...\n"),
			},
		},
	}

	if err := eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{outputEvent2},
	}); err != nil {
		log.Printf("Failed to send output event: %v", err)
	}

	time.Sleep(3 * time.Second)

	// Final output
	outputEvent3 := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
		EventData: &jobv1.JobEvent_Output{
			Output: &jobv1.OutputEvent{
				Output: []byte("Build completed successfully!\n"),
			},
		},
	}

	if err := eventStream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: taskToken,
		Events:    []*jobv1.JobEvent{outputEvent3},
	}); err != nil {
		log.Printf("Failed to send output event: %v", err)
	}

	return true // Success
}