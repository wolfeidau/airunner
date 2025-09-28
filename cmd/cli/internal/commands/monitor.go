package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
)

type MonitorCmd struct {
	Server        string            `help:"Server URL" default:"https://localhost:8080"`
	JobID         string            `arg:"" help:"Job ID to monitor"`
	FromSequence  int64             `help:"Start from sequence number" default:"0"`
	FromTimestamp int64             `help:"Start from timestamp" default:"0"`
	EventFilter   []jobv1.EventType `help:"Filter specific event types"`
}

func (m *MonitorCmd) Run(ctx context.Context, globals *Globals) error {
	fmt.Printf("Monitoring job %s on server %s\n", m.JobID, m.Server)

	// Create clients
	config := client.Config{
		ServerURL: m.Server,
		Timeout:   30 * time.Second,
		Debug:     globals.Debug,
	}
	clients := client.NewClients(config)

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Start monitoring
	if err := m.monitorJob(ctx, clients); err != nil {
		return fmt.Errorf("failed to monitor job: %w", err)
	}

	fmt.Println("Monitoring finished")
	return nil
}

func (m *MonitorCmd) monitorJob(ctx context.Context, clients *client.Clients) error {
	req := &jobv1.StreamJobEventsRequest{
		JobId:         m.JobID,
		FromSequence:  m.FromSequence,
		FromTimestamp: m.FromTimestamp,
		EventFilter:   m.EventFilter,
	}

	stream, err := clients.Events.StreamJobEvents(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to create event stream: %w", err)
	}
	defer stream.Close()

	fmt.Printf("Streaming events for job %s:\n", m.JobID)
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
				fmt.Printf("[%s] %s Heartbeat (Elapsed: %v)\n",
					event.Timestamp.AsTime().Format("15:04:05"),
					status,
					heartbeat.ElapsedTime.AsDuration())
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
