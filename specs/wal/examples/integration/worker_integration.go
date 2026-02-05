// Package integration shows how to integrate WAL into the worker command
package integration

import (
	"context"

	"connectrpc.com/connect"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/worker"
	"github.com/wolfeidau/airunner/internal/worker/wal"
)

// Example: Integrating WAL into worker job processing
//
// This shows the key integration points in cmd/cli/internal/commands/worker.go

func processJobWithWAL(ctx context.Context, job *jobv1.Job, eventStream *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse], taskToken string) error {
	// ============================================================
	// STEP 1: Create WAL for this job
	// ============================================================
	jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId)
	if err != nil {
		return err
	}

	// Ensure WAL is stopped and archived on function exit
	defer func() {
		jobWAL.Stop(ctx)
	}()

	// ============================================================
	// STEP 2: Wrap gRPC stream as EventSender
	// ============================================================
	sender := &grpcEventSender{
		stream:    eventStream,
		taskToken: taskToken,
	}

	// ============================================================
	// STEP 3: Start async sender (background goroutine)
	// ============================================================
	if err := jobWAL.Start(ctx, sender); err != nil {
		return err
	}

	// ============================================================
	// STEP 4: Create EventBatcher with WAL callback
	// ============================================================
	batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		// Write to WAL with fsync (synchronous, ~5ms latency)
		// Async sender will retry sending to server until success
		return jobWAL.Append(ctx, event)
	})

	// ============================================================
	// STEP 5: Execute job as normal
	// ============================================================
	executor := worker.NewJobExecutor(eventStream, taskToken, batcher)
	return executor.Execute(ctx, job)
}

// grpcEventSender wraps a Connect RPC stream as an EventSender for the WAL
// This adapter allows the WAL to send events through the existing gRPC stream
type grpcEventSender struct {
	stream    *connect.ClientStreamForClient[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse]
	taskToken string
}

// Send implements wal.EventSender
func (s *grpcEventSender) Send(ctx context.Context, events []*jobv1.JobEvent) error {
	return s.stream.Send(&jobv1.PublishJobEventsRequest{
		TaskToken: s.taskToken,
		Events:    events,
	})
}

// Key Points:
//
// 1. WAL is created per-job (one WAL file per job)
// 2. WAL is stopped in defer to ensure cleanup
// 3. EventBatcher writes to WAL instead of direct stream send
// 4. Async sender runs in background retrying failed sends
// 5. On job completion, WAL archives and compresses the file
//
// Event Flow:
//
//   Job executes → EventBatcher → WAL.Append() [fsync to disk]
//                                      ↓
//                                 WAL file
//                                      ↓
//                              Async sender (100ms poll)
//                                      ↓
//                           Retry with exponential backoff
//                                      ↓
//                              grpcEventSender.Send()
//                                      ↓
//                                   Server
//
// Failure Handling:
//
// - Network failure: Async sender retries indefinitely with backoff
// - Worker crash: Next worker loads WAL and replays unsent events
// - Disk full: WAL.Append() fails, job execution fails
// - Corruption: WAL truncates at corruption point, events after are lost
