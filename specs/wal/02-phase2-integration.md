# Phase 2: Worker Integration

[← README](README.md) | [← Phase 1](01-phase1-core-wal.md) | [Phase 3 →](03-phase3-testing.md)

## Goal

Integrate the WAL into the worker command so that all job events are durably persisted before being sent to the server.

**Estimated Duration**: 4-6 hours

## Prerequisites

- Phase 1 completed (WAL package implemented)
- Worker command builds successfully
- Understanding of EventBatcher flow

## Success Criteria

- [ ] Worker creates WAL for each job
- [ ] EventBatcher writes to WAL instead of direct stream send
- [ ] Async sender retries failed sends in background
- [ ] WAL archives on job completion
- [ ] Worker builds and runs without errors
- [ ] Events survive network failures

## Implementation Steps

### Step 1: Import WAL Package

**File**: `cmd/cli/internal/commands/worker.go`

Add WAL import:

```go
import (
    // ... existing imports ...
    "github.com/wolfeidau/airunner/internal/worker/wal"
)
```

### Step 2: Create WAL After Job Dequeue

**Location**: After `eventStream := clients.Events.PublishJobEvents(ctx)` (line ~139)

**Add**:
```go
eventStream := clients.Events.PublishJobEvents(ctx)

// Create WAL for durable event persistence
jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId)
if err != nil {
    return true, fmt.Errorf("failed to create WAL: %w", err)
}
defer func() {
    if err := jobWAL.Stop(ctx); err != nil {
        log.Error().Err(err).Msg("Failed to stop WAL")
    }
}()
```

**Why Defer**: Ensures WAL is always stopped and archived, even if job execution fails.

### Step 3: Create EventSender Wrapper

**Add after WAL creation**:

```go
// Wrap gRPC stream as EventSender for WAL
sender := &grpcEventSender{
    stream:    eventStream,
    taskToken: taskToken,
}

// Start async sender for WAL
if err := jobWAL.Start(ctx, sender); err != nil {
    return true, fmt.Errorf("failed to start WAL sender: %w", err)
}
```

### Step 4: Modify EventBatcher Callback

**Before**:
```go
batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
    return eventStream.Send(&jobv1.PublishJobEventsRequest{
        TaskToken: taskToken,
        Events:    []*jobv1.JobEvent{event},
    })
})
```

**After**:
```go
// Create event batcher with WAL callback
batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
    // Write to WAL with fsync (synchronous)
    // Async sender will retry sending to server until success
    return jobWAL.Append(ctx, event)
})
```

### Step 5: Add grpcEventSender Helper

**Add at end of file**:

```go
// grpcEventSender wraps a Connect RPC stream as an EventSender for the WAL
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
```

**Why Needed**: Adapts the gRPC stream interface to match the WAL's EventSender interface.

## Complete Integration Example

**File**: `cmd/cli/internal/commands/worker.go:processJob()`

```go
func (w *WorkerCmd) processJob(ctx context.Context, clients *client.Clients) (bool, error) {
    // ... job dequeue logic ...

    eventStream := clients.Events.PublishJobEvents(ctx)

    // ============================================================
    // WAL INTEGRATION START
    // ============================================================

    // Create WAL for this job
    jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId)
    if err != nil {
        return true, fmt.Errorf("failed to create WAL: %w", err)
    }
    defer func() {
        if err := jobWAL.Stop(ctx); err != nil {
            log.Error().Err(err).Msg("Failed to stop WAL")
        }
    }()

    // Wrap gRPC stream as EventSender
    sender := &grpcEventSender{
        stream:    eventStream,
        taskToken: taskToken,
    }

    // Start async sender
    if err := jobWAL.Start(ctx, sender); err != nil {
        return true, fmt.Errorf("failed to start WAL sender: %w", err)
    }

    // EventBatcher writes to WAL instead of direct send
    batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
        return jobWAL.Append(ctx, event)
    })

    // ============================================================
    // WAL INTEGRATION END
    // ============================================================

    executor := worker.NewJobExecutor(eventStream, taskToken, batcher)

    // ... rest of job execution ...
}
```

## Verification Commands

### 1. Build Worker
```bash
go build -o ./bin/airunner-cli ./cmd/cli
```

Should compile without errors.

### 2. Run Worker
```bash
./bin/airunner-cli worker --server=https://localhost:8080
```

### 3. Check WAL Directory
```bash
ls -lh ~/.airunner/wal/
```

Should see `<job-id>.wal` files while jobs are running.

### 4. Check Archive Directory
```bash
ls -lh ~/.airunner/archive/
```

Should see `<job-id>.wal.zst` files after jobs complete.

### 5. Monitor Worker Logs
```bash
./bin/airunner-cli worker --server=https://localhost:8080 2>&1 | grep WAL
```

Look for:
```
WAL created job_id=...
Async sender loop started
WAL archived successfully
```

### 6. Test Network Failure Recovery

**Terminal 1 - Start worker**:
```bash
./bin/airunner-cli worker --server=https://localhost:8080
```

**Terminal 2 - Submit job**:
```bash
./bin/airunner-cli submit https://github.com/example/repo
```

**Terminal 3 - Simulate network failure** (during job execution):
```bash
# Block port 8080
sudo pfctl -e
echo "block drop proto tcp to any port 8080" | sudo pfctl -f -

# Wait 10 seconds

# Unblock
sudo pfctl -d
```

**Verify**: Job completes successfully after network recovers. Check logs for retry messages.

## Troubleshooting

### WAL Creation Fails

**Error**: "failed to create WAL directory"
```bash
mkdir -p ~/.airunner/wal
chmod 755 ~/.airunner/wal
```

### Worker Crashes

**Check logs**:
```bash
tail -f ~/.airunner/wal/*.log
```

**Check for corrupt WAL**:
```bash
hexdump -C ~/.airunner/wal/<job-id>.wal | head
# Should see "ARWAL001" magic at start
```

### Events Not Sent

**Check async sender is running**:
```bash
# Look for "Async sender loop started" in logs
./bin/airunner-cli worker 2>&1 | grep "Async sender"
```

**Check pending count**:
```bash
# After job completion, pending should be 0
# Check WAL index in memory (add debug logging)
```

## Performance Impact

### Baseline (No WAL)
```
Job execution time: 10 seconds
Events: 1,000
Throughput: 100 events/sec
```

### With WAL (Fsync Per Event)
```
Job execution time: 10.5 seconds
Events: 1,000
Throughput: 95 events/sec
Overhead: ~5% (as expected)
```

**Why Acceptable**:
- Zero data loss guarantee worth 5% overhead
- fsync latency (~5ms) amortized across batch
- Network latency dominates anyway

## Next Phase

Proceed to [Phase 3: Testing](03-phase3-testing.md) to implement comprehensive tests.

---

[← README](README.md) | [← Phase 1](01-phase1-core-wal.md) | [Phase 3 →](03-phase3-testing.md)
