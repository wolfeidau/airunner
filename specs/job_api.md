# Job API Implementation Plan

## Overview

This document outlines the implementation plan for the airunner job orchestration platform, featuring a distributed job queue system with real-time event streaming capabilities. The system is designed for long-running processes with single-job-per-worker patterns and comprehensive observability.

## Configuration & Scope

### Development vs Production
- **Memory Store**: For testing and local development only
- **Authentication/Authorization**: Will be scoped and implemented in a later phase
- **Service Discovery**: Will be addressed in future iterations
- **Error Handling**: Uses Connect RPC errors as the primary error handling mechanism

### Implementation Defaults
- Memory store cleanup interval: 30 seconds
- Event buffer size: Unlimited events per job (simple append-only for development)
- Default visibility timeout: 300 seconds (5 minutes)
- Long polling timeout for dequeue: 5 seconds
- Max concurrent streams per job: 10
- Idempotency token format: UUIDv4 with validation

## Architecture

### Service Split Design

The API is split into two independent services for better architectural separation:

1. **JobService** - Core job queue operations
2. **JobEventsService** - Real-time event streaming

This separation enables:
- Independent scaling based on different usage patterns
- Different backend implementations (memory vs. cloud services)
- Granular security and access control
- Client flexibility (workers vs. monitoring tools)

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Job Client    │    │  Events Client  │    │  Memory Store   │
│   (Workers)     │    │  (Monitoring)   │    │                 │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • EnqueueJob    │    │ • StreamEvents  │    │ • Job Storage   │
│ • DequeueJob    │    │ • PublishEvents │    │ • Queue Mgmt    │
│ • UpdateJob     │    │                 │    │ • Visibility    │
│ • CompleteJob   │    │                 │    │ • Events Buffer │
│ • ListJobs      │    │                 │    │ • Cleanup       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Implementation Plan

### Phase 1: Memory Store Foundation

**File: `internal/store/store.go`**

#### Core Data Structures

```go
type MemoryJobStore struct {
    mu sync.RWMutex

    // Core job storage
    jobs map[string]*Job                    // UUIDv4 job ID -> Job
    jobQueues map[string]string             // Job ID -> Queue name mapping
    queues map[string][]*Job               // Queue name -> Jobs (FIFO)

    // Visibility timeout management
    invisibleJobs map[string]time.Time     // Job ID -> Visibility expiry
    taskTokens map[string]string           // UUIDv4 task token -> Job ID

    // Idempotency support
    requestIds map[string]string           // Request ID -> Job ID

    // Event streaming
    jobEvents map[string][]*JobEvent       // Job ID -> Event buffer
    eventStreams map[string][]chan *JobEvent // Job ID -> Active streams

    // Background cleanup
    cleanupTicker *time.Ticker
    stopCleanup chan bool
}
```

#### Key Features

1. **UUID Strategy & Type Consistency**
   - UUIDv4 for job IDs (random, widely supported) - simplified cross-language compatibility
   - UUIDv4 for task tokens (secure, random) - prevents token prediction attacks
   - UUIDv4 for request IDs (idempotency tokens) - prevents duplicate job creation
   - All UUID fields in protobuf use standard `string` type for simplicity

2. **Visibility Timeout (SQS-like behavior)**
   - Jobs become invisible after dequeue for specified duration
   - Background cleanup returns expired jobs to queues
   - Workers can extend timeout via UpdateJob

3. **FIFO Queue Processing**
   - First-in-first-out job selection from queue front
   - Predictable job ordering and processing
   - Simple and reliable queue semantics

4. **Event Streaming**
   - Real-time event buffers per job
   - Multiple concurrent stream subscriptions
   - Sequence-based ordering with source-assigned monotonic sequence numbers
   - Timestamp-based replay capability

#### Store Interface

```go
type JobStore interface {
    // Job lifecycle
    EnqueueJob(ctx context.Context, req *EnqueueJobRequest) (*EnqueueJobResponse, error)
    DequeueJobs(ctx context.Context, queue string, maxJobs int, timeoutSeconds int) ([]*JobWithToken, error)
    UpdateJobVisibility(ctx context.Context, queue string, taskToken string, timeoutSeconds int) error
    CompleteJob(ctx context.Context, taskToken string, result *JobResult) error
    ListJobs(ctx context.Context, req *ListJobsRequest) (*ListJobsResponse, error)

    // Event streaming
    PublishEvents(ctx context.Context, taskToken string, events []*JobEvent) error
    StreamEvents(ctx context.Context, jobId string, fromSequence int64, fromTimestamp int64, eventFilter []EventType) (<-chan *JobEvent, error)

    // Lifecycle
    Start() error
    Stop() error
}
```

### Phase 2: JobServer Implementation

**Files: `internal/server/job.go`, `internal/server/job_event.go`, `internal/server/server.go`**

#### Service Implementation

```go
type JobServer struct {
    store JobStore
}

func NewJobServer(store JobStore) *JobServer {
    return &JobServer{store: store}
}
```

#### Method Implementations

1. **EnqueueJob**
   - Generate UUIDv4 job ID
   - Check request ID for idempotency
   - Validate job parameters
   - Store job in SCHEDULED state
   - Return job ID and creation timestamp

2. **DequeueJob (Streaming)**
   - Long-polling implementation
   - FIFO job selection from queue front
   - Generate UUIDv4 task token
   - Set visibility timeout
   - Transition job to RUNNING state
   - Stream job to client

3. **UpdateJob**
   - Validate task token and queue for partitioning support
   - Extend visibility timeout
   - Update job timestamps

4. **CompleteJob**
   - Validate task token
   - Update job state (COMPLETED/FAILED)
   - Store job result
   - Clean up visibility timeout
   - Remove from active processing

5. **ListJobs**
   - Filter by queue and state
   - Implement pagination
   - Return sorted results (by creation time)

### Phase 3: JobEventsServer Implementation

**File: `internal/server/events.go`**

#### Service Implementation

```go
type JobEventsServer struct {
    store JobStore
}

func NewJobEventsServer(store JobStore) *JobEventsServer {
    return &JobEventsServer{store: store}
}
```

#### Method Implementations

1. **StreamJobEvents (Server Streaming)**
   - Validate job ID exists (UUID format)
   - Support timestamp-based replay from specific timestamp
   - Real-time event streaming with EVENT_TYPE_UNSPECIFIED as default
   - Events ordered by monotonic sequence number for guaranteed ordering
   - Handle client disconnections gracefully
   - Multiple concurrent streams per job (max 10)

2. **PublishJobEvents (Client Streaming)**
   - Validate task token (UUID format)
   - Buffer incoming events in memory
   - Validate monotonic sequence numbers assigned by worker (protects against network reordering)
   - Store events with worker-assigned sequences to preserve source ordering
   - Timestamp validation for event ordering
   - Fanout to active streams with non-blocking sends
   - Efficient batch processing for multiple events

#### Sequence Number Assignment Strategy

**Design Decision: Source-Assigned Sequences**

Sequences are assigned by the worker (event source) rather than the store for the following reasons:

1. **Network Reordering Protection**: Events transmitted over the network from remote workers may arrive out of order. Source-assigned sequences preserve the true temporal order of events as they occurred.

2. **Per-Execution Scoping**: Sequences are scoped to a single job execution attempt. If a job times out and is re-executed, the new execution starts with sequence=1, making it easier to distinguish between execution attempts.

3. **Single-Worker Model**: The current architecture assigns one worker per job execution, eliminating the need for store-side sequence coordination.

**Store Responsibilities**:
- Validate that received sequences are monotonic within a batch
- Detect missing or duplicate events (future enhancement)
- Preserve worker-assigned sequences when storing and streaming events

**Future Considerations**:
- If multiple goroutines need to publish events for the same execution, consider adding an `execution_id` field to distinguish retry attempts
- For distributed tracing, sequences provide happened-before relationships within an execution

### Phase 4: Integration Tests

**File: `internal/server/server_test.go`**

#### Test Categories

1. **Core Job Lifecycle Tests**
   ```go
   func TestCompleteJobWorkflow(t *testing.T) {
       // Test: enqueue → dequeue → update → complete
   }
   ```

2. **Visibility Timeout Tests**
   ```go
   func TestVisibilityTimeoutExpiry(t *testing.T) {
       // Test: job returns to queue after timeout
   }

   func TestVisibilityTimeoutExtension(t *testing.T) {
       // Test: UpdateJob extends timeout
   }
   ```

3. **Concurrency Tests**
   ```go
   func TestConcurrentWorkers(t *testing.T) {
       // Test: multiple workers on same queue
   }
   ```

4. **Event Streaming Tests**
   ```go
   func TestEventStreamingAndReplay(t *testing.T) {
       // Test: real-time events + historical replay
   }
   ```

5. **Error Handling Tests**
   ```go
   func TestInvalidTaskToken(t *testing.T) {
       // Test: invalid/expired task tokens
   }
   ```

### Phase 5: Example Implementations

**File: `examples/worker/main.go`**

#### Single-Job Worker Pattern

```go
func main() {
    client := jobv1connect.NewJobServiceClient(http.DefaultClient, "http://localhost:8080")
    eventsClient := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, "http://localhost:8080")

    for {
        // Dequeue single job
        job := dequeueJob(client, "default", 1, 300) // 5 min timeout

        if job != nil {
            // Start event streaming
            go publishEvents(eventsClient, job.TaskToken) // Worker assigns sequences

            // Extend timeout periodically
            go extendTimeout(client, job.TaskToken)

            // Execute job
            result := executeJob(job)

            // Complete job
            completeJob(client, job.TaskToken, result)
        }
    }
}
```

**File: `examples/monitor/main.go`**

#### Event Monitoring

```go
func main() {
    client := jobv1connect.NewJobEventsServiceClient(http.DefaultClient, "http://localhost:8080")

    // Stream events for specific job
    stream := streamJobEvents(client, jobId)

    for event := range stream {
        switch event.EventType {
        case EventType_EVENT_TYPE_OUTPUT:
            fmt.Print(string(event.GetOutput().Output))
        case EventType_EVENT_TYPE_PROCESS_END:
            fmt.Printf("Process exited with code: %d\n", event.GetProcessEnd().ExitCode)
        }
    }
}
```

## Implementation Details

### UUID Generation & Validation

```go
// UUIDv4 for job IDs (random, widely supported)
func generateJobID() string {
    return uuid.New().String()
}

// UUIDv4 for task tokens (random, secure)
func generateTaskToken() string {
    return uuid.New().String()
}

// UUIDv4 for request IDs (idempotency)
func generateRequestID() string {
    return uuid.New().String()
}

// Validate UUID format for API inputs
func validateUUID(id string) error {
    if _, err := uuid.Parse(id); err != nil {
        return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid UUID format: %w", err))
    }
    return nil
}
```

### Background Cleanup

```go
func (s *MemoryJobStore) cleanupExpiredJobs() {
    s.mu.Lock()
    defer s.mu.Unlock()

    now := time.Now()
    for jobId, expiry := range s.invisibleJobs {
        if now.After(expiry) {
            // Return job to queue
            job := s.jobs[jobId]
            job.State = JobState_JOB_STATE_SCHEDULED
            queueName := s.jobQueues[jobId]
            s.queues[queueName] = append(s.queues[queueName], job)

            // Clean up tracking
            delete(s.invisibleJobs, jobId)
            delete(s.taskTokens, job.taskToken)
        }
    }
}
```

### Event Fanout

```go
func (s *MemoryJobStore) fanoutEvent(jobId string, event *JobEvent) {
    s.mu.RLock()
    streams := s.eventStreams[jobId]
    s.mu.RUnlock()

    for _, ch := range streams {
        select {
        case ch <- event:
        default:
            // Channel full, skip this stream
        }
    }
}
```

### Sequence Validation

```go
func (s *MemoryJobStore) PublishEvents(ctx context.Context, taskToken string, events []*JobEvent) error {
    jobId, exists := s.taskTokens[taskToken]
    if !exists {
        return fmt.Errorf("invalid task token")
    }

    // Validate sequences are monotonic within this batch
    // (sequences are already assigned by worker)
    for i := 1; i < len(events); i++ {
        if events[i].Sequence <= events[i-1].Sequence {
            return connect.NewError(connect.CodeInvalidArgument,
                fmt.Errorf("non-monotonic sequence detected: %d -> %d",
                    events[i-1].Sequence, events[i].Sequence))
        }
    }

    // Store events with worker-assigned sequences preserved
    s.jobEvents[jobId] = append(s.jobEvents[jobId], events...)

    // Fanout to active streams
    for _, event := range events {
        s.fanoutEvent(jobId, event)
    }

    return nil
}
```

## API Schema Notes

### Protobuf Design Decisions
- **Type Consistency**: All job IDs and task tokens use standard `string` type throughout
- **Event Types**: Include `EVENT_TYPE_UNSPECIFIED = 0` for proto3 best practices
- **Field Evolution**: Some field number gaps exist to allow for future proto evolution
- **Validation**: JobResult includes job_id field for cross-validation with task token
- **Pagination**: ListJobsResponse uses last_page field for UI pagination support

### Error Handling Strategy
Use Connect RPC error codes for all API errors:
- `CodeInvalidArgument`: Malformed UUIDs, invalid parameters
- `CodeNotFound`: Non-existent job IDs or expired task tokens
- `CodeFailedPrecondition`: Invalid state transitions
- `CodeResourceExhausted`: Queue limits exceeded
- `CodeInternal`: Store operation failures

## Deployment Considerations

### Memory Usage

- Event buffers: Unlimited size with simple append (development mode)
- Job retention: Configurable cleanup after completion
- Stream management: Automatic cleanup on client disconnect

### Performance

- Non-blocking operations where possible
- Efficient data structures for lookups
- Batch event processing
- Connection pooling for clients

### Monitoring

- Metrics collection points:
  - Queue depths
  - Job processing times
  - Event throughput
  - Worker health

### Future Extensibility

- Interface-based design for multiple store backends
- Plugin architecture for custom event handlers
- Webhook integration for external notifications
- Metrics and observability hooks

## SQS Backend Compatibility

The interface design enables future SQS backend implementation:

```go
type SQSJobStore struct {
    sqsClient *sqs.Client
    dynamoDB  *dynamodb.Client // For job metadata and state
    s3Client  *s3.Client      // For large job payloads
}
```

**Mapping Strategy:**
- SQS messages for job queue management
- DynamoDB for job metadata and state tracking
- S3 for large job parameters/results
- EventBridge/Kinesis for event streaming

This design provides a production-ready job orchestration platform with comprehensive observability, suitable for both development (memory backend) and production (cloud backends) environments.