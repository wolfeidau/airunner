package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"connectrpc.com/connect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/api/gen/proto/go/job/v1/jobv1connect"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("Usage: monitor <server-url> <job-id>")
	}

	serverURL := os.Args[1]
	jobID := os.Args[2]

	log.Printf("Monitoring job %s on server %s", jobID, serverURL)

	// Create client
	client := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, serverURL)

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Start monitoring
	if err := monitorJob(ctx, client, jobID); err != nil {
		log.Fatalf("Failed to monitor job: %v", err)
	}

	log.Println("Monitoring finished")
}

func monitorJob(ctx context.Context, client jobv1connect.JobEventsServiceClient, jobID string) error {
	req := &jobv1.StreamJobEventsRequest{
		JobId:         jobID,
		FromSequence:  0, // Start from beginning
		FromTimestamp: 0, // No timestamp filter
		EventFilter:   []jobv1.EventType{}, // All event types
	}

	stream, err := client.StreamJobEvents(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to create event stream: %w", err)
	}
	defer stream.Close()

	fmt.Printf("Streaming events for job %s:\n", jobID)
	fmt.Println(strings.Repeat("=", 50))

	for stream.Receive() {
		event := stream.Msg().Event

		switch event.EventType {
		case jobv1.EventType_EVENT_TYPE_PROCESS_START:
			if start := event.GetProcessStart(); start != nil {
				fmt.Printf("[%s] 🚀 Process started (PID: %d)\n",
					event.Timestamp.AsTime().Format("15:04:05"),
					start.Pid)
			}

		case jobv1.EventType_EVENT_TYPE_PROCESS_END:
			if end := event.GetProcessEnd(); end != nil {
				status := "✅ SUCCESS"
				if end.ExitCode != 0 {
					status = "❌ FAILED"
				}
				fmt.Printf("[%s] %s Process ended (PID: %d, Exit Code: %d, Duration: %v)\n",
					event.Timestamp.AsTime().Format("15:04:05"),
					status,
					end.Pid,
					end.ExitCode,
					end.RunDuration.AsDuration())
			}

		case jobv1.EventType_EVENT_TYPE_PROCESS_ERROR:
			if err := event.GetProcessError(); err != nil {
				fmt.Printf("[%s] ❌ ERROR: %s\n",
					event.Timestamp.AsTime().Format("15:04:05"),
					err.ErrorMessage)
			}

		case jobv1.EventType_EVENT_TYPE_HEARTBEAT:
			if heartbeat := event.GetHeartbeat(); heartbeat != nil {
				status := "💓"
				if !heartbeat.ProcessAlive {
					status = "💀"
				}
				fmt.Printf("[%s] %s Heartbeat (Elapsed: %dms)\n",
					event.Timestamp.AsTime().Format("15:04:05"),
					status,
					heartbeat.ElapsedTime)
			}

		case jobv1.EventType_EVENT_TYPE_OUTPUT:
			if output := event.GetOutput(); output != nil {
				fmt.Printf("[%s] 📝 %s",
					event.Timestamp.AsTime().Format("15:04:05"),
					string(output.Output))
			}

		case jobv1.EventType_EVENT_TYPE_TERMINAL_RESIZE:
			if resize := event.GetTerminalResize(); resize != nil {
				fmt.Printf("[%s] 📺 Terminal resized to %dx%d (%dx%d pixels)\n",
					event.Timestamp.AsTime().Format("15:04:05"),
					resize.Cols,
					resize.Rows,
					resize.WidthPixels,
					resize.HeightPixels)
			}

		default:
			fmt.Printf("[%s] ❓ Unknown event type: %s (Sequence: %d)\n",
				event.Timestamp.AsTime().Format("15:04:05"),
				event.EventType.String(),
				event.Sequence)
		}
	}

	if err := stream.Err(); err != nil {
		return fmt.Errorf("stream error: %w", err)
	}

	return nil
}