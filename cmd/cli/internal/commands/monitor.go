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
	"connectrpc.com/otelconnect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/client"
)

type MonitorCmd struct {
	Server        string            `help:"Server URL" default:"https://localhost:8993"`
	JobID         string            `arg:"" help:"Job ID to monitor"`
	FromSequence  int64             `help:"Start from sequence number" default:"0"`
	FromTimestamp int64             `help:"Start from timestamp" default:"0"`
	EventFilter   []jobv1.EventType `help:"Filter specific event types"`
	Timeout       time.Duration     `help:"Timeout for the monitor" default:"5m"`
	Token         string            `help:"JWT token for authentication" env:"AIRUNNER_TOKEN"`
	Playback      bool              `help:"Replay events at original speed based on timestamps"`
}

func (m *MonitorCmd) Run(ctx context.Context, globals *Globals) error {
	fmt.Printf("Monitoring job %s on server %s\n", m.JobID, m.Server)

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	// Create clients
	config := client.Config{
		ServerURL: m.Server,
		Timeout:   m.Timeout,
		Token:     m.Token,
		Debug:     globals.Debug,
	}
	clients := client.NewClients(config, connect.WithInterceptors(otelInterceptor))

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
	if err := monitorJob(ctx, clients, monitorJobArgs{
		JobID:         m.JobID,
		FromSequence:  m.FromSequence,
		FromTimestamp: m.FromTimestamp,
		EventFilter:   m.EventFilter,
		Playback:      m.Playback,
	}); err != nil {
		return fmt.Errorf("failed to monitor job: %w", err)
	}

	fmt.Println("Monitoring finished")
	return nil
}

type monitorJobArgs struct {
	JobID         string
	FromSequence  int64
	FromTimestamp int64
	EventFilter   []jobv1.EventType
	Playback      bool
}

func monitorJob(ctx context.Context, clients *client.Clients, args monitorJobArgs) error {
	req := &jobv1.StreamJobEventsRequest{
		JobId:         args.JobID,
		FromSequence:  args.FromSequence,
		FromTimestamp: args.FromTimestamp,
		EventFilter:   args.EventFilter,
	}

	stream, err := clients.Events.StreamJobEvents(ctx, connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to create event stream: %w", err)
	}
	defer stream.Close()

	fmt.Printf("Streaming events for job %s:\n", args.JobID)
	fmt.Println(strings.Repeat("=", 50))

	var timer *playbackTimer
	if args.Playback {
		timer = newPlaybackTimer()
	}

	for stream.Receive() {
		event := stream.Msg().Event

		// Handle playback timing
		if timer != nil && event.Timestamp != nil {
			timer.wait(event.Timestamp.AsTime())
		}

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

			return nil // we are done

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
				fmt.Printf("%s", string(output.Output))
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

type playbackTimer struct {
	firstEventTime    time.Time
	referenceWallTime time.Time
	initialized       bool
}

func newPlaybackTimer() *playbackTimer {
	return &playbackTimer{}
}

func (pt *playbackTimer) wait(eventTime time.Time) {
	if !pt.initialized {
		pt.firstEventTime = eventTime
		pt.referenceWallTime = time.Now()
		pt.initialized = true
		return
	}

	// Calculate elapsed time since first event
	elapsedEvent := eventTime.Sub(pt.firstEventTime)
	elapsedWall := time.Since(pt.referenceWallTime)

	// Sleep for the remaining time if playback is ahead
	if elapsedEvent > elapsedWall {
		time.Sleep(elapsedEvent - elapsedWall)
	}
}
