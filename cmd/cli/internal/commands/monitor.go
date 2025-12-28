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
	Server        string            `help:"Server URL" default:"https://localhost:443"`
	JobID         string            `arg:"" help:"Job ID to monitor"`
	FromSequence  int64             `help:"Start from sequence number" default:"0"`
	FromTimestamp int64             `help:"Start from timestamp" default:"0"`
	EventFilter   []jobv1.EventType `help:"Filter specific event types"`
	Timeout       time.Duration     `help:"Timeout for the monitor" default:"5m"`
	Playback      bool              `help:"Replay events at original speed based on timestamps"`
	Verbose       bool              `help:"Show verbose debug output including timestamps"`
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
		Debug:     globals.Debug,
	}
	clients, err := client.NewClients(config, connect.WithInterceptors(otelInterceptor))
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

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
		Verbose:       m.Verbose,
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
	Verbose       bool
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
		timer = newPlaybackTimer(args.Verbose)
	}

	// Linearizability verification: track sequence numbers to detect gaps
	var lastSequence int64
	var sequenceGaps []string
	var processEndReceived bool

	for {
		var receivedEvent bool

		// After PROCESS_END, use timeout to exit gracefully if no more events
		if processEndReceived {
			receiveChan := make(chan bool, 1)
			go func() {
				receiveChan <- stream.Receive()
			}()

			select {
			case receivedEvent = <-receiveChan:
				if !receivedEvent {
					goto streamComplete
				}
			case <-time.After(2 * time.Second):
				// Grace period expired, exit cleanly
				if args.Verbose {
					fmt.Printf("\n[DEBUG] Grace period expired after PROCESS_END, exiting\n")
				}
				goto streamComplete
			}
		} else {
			receivedEvent = stream.Receive()
			if !receivedEvent {
				goto streamComplete
			}
		}

		event := stream.Msg().Event

		// Verify sequence linearizability
		if lastSequence > 0 {
			expectedNext := lastSequence + 1
			if event.Sequence > expectedNext {
				gap := fmt.Sprintf("Gap detected: expected seq %d, got %d (missing %d events)",
					expectedNext, event.Sequence, event.Sequence-expectedNext)
				sequenceGaps = append(sequenceGaps, gap)
				if args.Verbose {
					fmt.Printf("\n[WARN] SEQUENCE GAP: %s\n", gap)
				}
			} else if event.Sequence <= lastSequence {
				if args.Verbose {
					fmt.Printf("\n[WARN] SEQUENCE OUT OF ORDER: got seq %d after %d\n",
						event.Sequence, lastSequence)
				}
			}
		}

		// Update lastSequence - for OUTPUT_BATCH, use EndSequence since the batch represents multiple sequences
		if event.EventType == jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH {
			if batch := event.GetOutputBatch(); batch != nil {
				lastSequence = batch.EndSequence
				if args.Verbose {
					fmt.Printf("[DEBUG] OUTPUT_BATCH covers sequences %d-%d\n", batch.StartSequence, batch.EndSequence)
				}
			} else {
				lastSequence = event.Sequence
			}
		} else {
			lastSequence = event.Sequence
		}

		// Handle playback timing
		// Skip for OUTPUT_BATCH - it handles timing internally for each output
		if timer != nil && event.Timestamp != nil && event.EventType != jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH {
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
				if args.Verbose {
					fmt.Printf("\n[DEBUG] PROCESS_END event: timestamp=%s\n",
						event.Timestamp.AsTime().Format("15:04:05.000"))
				}

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

			// Set flag to start grace period for any remaining events
			processEndReceived = true

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

		case jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH:
			if batch := event.GetOutputBatch(); batch != nil {
				if args.Verbose {
					batchTime := event.Timestamp.AsTime()
					firstOutputTime := time.UnixMilli(batch.FirstTimestampMs).UTC()
					fmt.Printf("\n[DEBUG] Batch event: timestamp=%s, outputs=%d, first_output=%s, playback_interval=%dms\n",
						batchTime.Format("15:04:05.000"),
						len(batch.Outputs),
						firstOutputTime.Format("15:04:05.000"),
						batch.PlaybackIntervalMillis)
				}

				// Unpack and replay each output from the batch with original timing
				for i, output := range batch.Outputs {
					// Calculate actual timestamp for this output
					// FirstTimestampMs is the absolute timestamp of the first item in the batch
					// TimestampDeltaMs is the offset from the first item
					outputTimestampMs := batch.FirstTimestampMs + int64(output.TimestampDeltaMs)
					outputTime := time.UnixMilli(outputTimestampMs).UTC()

					if args.Verbose && i < 5 { // Only show first 5 to avoid spam
						fmt.Printf("[DEBUG] Output %d: delta=%dms, timestamp=%s\n",
							i, output.TimestampDeltaMs, outputTime.Format("15:04:05.000"))
					}

					// Handle playback timing with actual timestamps
					if timer != nil {
						timer.wait(outputTime)
					}

					// Display output
					fmt.Printf("%s", string(output.Output))
				}

				if args.Verbose {
					fmt.Printf("[DEBUG] Batch complete\n\n")
				}
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

streamComplete:
	if err := stream.Err(); err != nil {
		return fmt.Errorf("stream error: %w", err)
	}

	// Report linearizability verification results
	if len(sequenceGaps) > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("=", 50))
		fmt.Printf("⚠️  LINEARIZABILITY VIOLATIONS DETECTED\n")
		fmt.Printf("%s\n", strings.Repeat("=", 50))
		for _, gap := range sequenceGaps {
			fmt.Printf("  • %s\n", gap)
		}
		fmt.Printf("\nThis indicates events were lost or failed to persist.\n")
		fmt.Printf("Check worker and server logs for errors.\n")
	}

	return nil
}

type playbackTimer struct {
	firstEventTime    time.Time
	referenceWallTime time.Time
	initialized       bool
	verbose           bool
}

func newPlaybackTimer(verbose bool) *playbackTimer {
	return &playbackTimer{verbose: verbose}
}

func (pt *playbackTimer) wait(eventTime time.Time) {
	if !pt.initialized {
		pt.firstEventTime = eventTime
		pt.referenceWallTime = time.Now()
		pt.initialized = true
		if pt.verbose {
			fmt.Printf("[DEBUG TIMER] Initialized: first_event=%s\n", eventTime.Format("15:04:05.000"))
		}
		return
	}

	// Calculate elapsed time since first event
	elapsedEvent := eventTime.Sub(pt.firstEventTime)
	elapsedWall := time.Since(pt.referenceWallTime)

	if pt.verbose {
		fmt.Printf("[DEBUG TIMER] Event time: %s, elapsed_event=%v, elapsed_wall=%v",
			eventTime.Format("15:04:05.000"), elapsedEvent, elapsedWall)
	}

	// Sleep for the remaining time if playback is ahead
	if elapsedEvent > elapsedWall {
		sleepDuration := elapsedEvent - elapsedWall
		if pt.verbose {
			fmt.Printf(", sleeping=%v\n", sleepDuration)
		}
		time.Sleep(sleepDuration)
	} else if pt.verbose {
		fmt.Printf(", no sleep needed\n")
	}
}
