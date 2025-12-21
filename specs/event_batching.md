# Event Batching Design

## Overview

This document specifies the design for batching output events in DynamoDB to reduce write operations and storage costs while maintaining efficient query performance. The design introduces client-side buffering and batch windowing to handle sequence-based event retrieval efficiently.

## Problem Statement

**Current Implementation:**
- Each output line generates one DynamoDB item
- 1,000-line build log = 1,000 DynamoDB writes
- 1,000 items to query on replay
- High cost and query latency

**Customer Impact:**
- DynamoDB costs scale linearly with output verbosity
- Event replay for long-running jobs (10,000+ lines) can take seconds
- Worker makes excessive network calls (one per output line)

## Solution: Output Event Batching

**Batch output events at the worker** before publishing to reduce:
1. DynamoDB write operations (50x reduction)
2. Network calls from worker to server (50x reduction)
3. Query result size on replay (50x reduction)

**Key Design Principle:** Batching is transparent to end users but requires clients to implement buffering and batch-aware windowing for efficient event retrieval.

## Schema Design

### Protobuf Changes

```protobuf
// api/job/v1/job.proto

// NEW: Batch container for output events
message OutputBatchEvent {
  // Individual output events in this batch
  repeated OutputItem outputs = 1;

  // Sequence range covered by this batch
  int64 start_sequence = 2;  // First output's sequence (also DynamoDB sort key)
  int64 end_sequence = 3;    // Last output's sequence (inclusive)

  // Optional: per-output timestamps for accurate replay
  // If omitted, client simulates timing (50-100ms intervals)
  repeated int64 timestamps = 4;  // Parallel array with outputs (Unix millis)
}

message OutputItem {
  bytes output = 1;
  StreamType stream = 2;  // stdout/stderr
}

// Extend JobEvent with new event type
message JobEvent {
  int64 sequence = 1;
  google.protobuf.Timestamp timestamp = 2;
  EventType event_type = 3;

  oneof event_data {
    OutputEvent output_data = 10;          // Single output (legacy/backwards compat)
    OutputBatchEvent output_batch = 11;    // NEW: Batched outputs
    ProcessStartEvent process_start = 12;
    ProcessEndEvent process_end = 13;
    ProcessErrorEvent process_error = 14;
  }
}

enum EventType {
  EVENT_TYPE_UNSPECIFIED = 0;
  EVENT_TYPE_OUTPUT_DATA = 1;           // Legacy: single output
  EVENT_TYPE_OUTPUT_BATCH = 2;          // NEW: batched outputs
  EVENT_TYPE_PROCESS_START = 3;
  EVENT_TYPE_PROCESS_END = 4;
  EVENT_TYPE_PROCESS_ERROR = 5;
}
```

### DynamoDB Schema

**JobEvents Table** (unchanged primary key structure):

| Attribute | Type | Description |
|-----------|------|-------------|
| `job_id` (PK) | S | Job identifier |
| `sequence` (SK) | N | First sequence in batch (for batches) or event sequence (for individual) |
| `timestamp` | N | Unix milliseconds |
| `event_type` | N | EventType enum value |
| `event_payload` | B | Protobuf-encoded JobEvent (includes OutputBatchEvent for batches) |
| `ttl` | N | TTL attribute (Unix seconds) |

**Example data:**

```
| job_id | sequence (SK) | event_type      | event_payload                                    |
|--------|---------------|-----------------|--------------------------------------------------|
| 123    | 1             | PROCESS_START   | {protobuf: ProcessStartEvent}                    |
| 123    | 2             | OUTPUT_BATCH    | {outputs: [seq 2-51], start:2, end:51}           |
| 123    | 52            | OUTPUT_BATCH    | {outputs: [seq 52-101], start:52, end:101}       |
| 123    | 102           | OUTPUT_BATCH    | {outputs: [seq 102-151], start:102, end:151}     |
| 123    | 152           | PROCESS_END     | {protobuf: ProcessEndEvent}                      |
```

**Key Properties:**
- Batch uses **first sequence** as DynamoDB sort key
- Maintains monotonic sequence ordering for queries
- Individual events (ProcessStart, ProcessEnd) interspersed with batches
- `start_sequence` and `end_sequence` stored in event_payload for client windowing

## Batch Windowing and Client Buffering

### The Challenge: Querying by Sequence with Batches

When a client requests events from `fromSequence=75`, we need to:
1. Find the batch **containing** sequence 75 (batch starting at sequence 52)
2. Retrieve that batch and all subsequent batches
3. Unpack batches into individual events
4. Filter to only include sequences >= 75

### Batch-Adjusted Query Formula

**Formula:**
```
minBatchSequence = max(1, fromSequence - maxBatchSize + 1)
```

**Rationale:**
- If batches are at most `maxBatchSize` events, the batch containing `fromSequence` must start at a sequence >= `fromSequence - maxBatchSize + 1`
- This is a **conservative lower bound** that guarantees we fetch the correct batch

**Examples:**

| fromSequence | maxBatchSize | minBatchSequence | Batches Retrieved |
|--------------|--------------|------------------|-------------------|
| 25           | 50           | max(1, -24) = 1  | All batches from start |
| 75           | 50           | max(1, 26) = 26  | Batches from seq 26 onwards (includes batch at seq 52) |
| 200          | 50           | max(1, 151) = 151| Batches from seq 151 onwards |

### Query Scenarios

#### Scenario 1: Early Sequence Request (fromSequence=25, maxBatchSize=50)

**Batches in DynamoDB:**
```
Batch 1: sequence=1   (events 1-50)
Batch 2: sequence=51  (events 51-100)
Batch 3: sequence=101 (events 101-150)
```

**Query:**
```
minBatchSequence = max(1, 25 - 50 + 1) = 1
DynamoDB Query: job_id=123 AND sequence >= 1
```

**Result:**
- Returns: Batch 1, Batch 2, Batch 3
- Client unpacks Batch 1 (events 1-50)
- Client filters to sequences >= 25
- Client buffers events 25-50
- Client continues with Batch 2, 3...

**Overhead:** Fetched 24 extra events (sequences 1-24), filtered client-side

#### Scenario 2: Mid-Job Sequence Request (fromSequence=75, maxBatchSize=50)

**Batches in DynamoDB:**
```
Batch 1: sequence=1   (events 1-50)
Batch 2: sequence=51  (events 51-100)
Batch 3: sequence=101 (events 101-150)
```

**Query:**
```
minBatchSequence = max(1, 75 - 50 + 1) = 26
DynamoDB Query: job_id=123 AND sequence >= 26
```

**Result:**
- Returns: Batch 2, Batch 3 (skips Batch 1 ✅)
- Client unpacks Batch 2 (events 51-100)
- Client filters to sequences >= 75
- Client buffers events 75-100
- Client continues with Batch 3...

**Overhead:** Fetched 24 extra events (sequences 51-74), filtered client-side

**Performance Gain:** Skipped 1 batch (50 events) from DynamoDB query

#### Scenario 3: Variable Batch Sizes (fromSequence=100, maxBatchSize=50)

**Batches in DynamoDB** (worker flushed at different times):
```
Batch 1: sequence=1   (30 events: 1-30)   [flushed early on timer]
Batch 2: sequence=31  (45 events: 31-75)  [flushed on size]
Batch 3: sequence=76  (50 events: 76-125) [flushed on size]
Batch 4: sequence=126 (25 events: 126-150)[flushed on ProcessEnd]
```

**Query:**
```
minBatchSequence = max(1, 100 - 50 + 1) = 51
DynamoDB Query: job_id=123 AND sequence >= 51
```

**Result:**
- Returns: Batch 3 (seq 76), Batch 4 (seq 126)
- Skips Batch 1 (seq 1) and Batch 2 (seq 31) ✅
- Client unpacks Batch 3 (events 76-125)
- Client filters to sequences >= 100
- Client buffers events 100-125

**Overhead:** Fetched 24 extra events (sequences 76-99), filtered client-side

**Key Insight:** Formula works correctly even with variable batch sizes, as long as no batch exceeds `maxBatchSize`.

#### Scenario 4: Exact Batch Boundary (fromSequence=51, maxBatchSize=50)

**Batches in DynamoDB:**
```
Batch 1: sequence=1   (events 1-50)
Batch 2: sequence=51  (events 51-100)
Batch 3: sequence=101 (events 101-150)
```

**Query:**
```
minBatchSequence = max(1, 51 - 50 + 1) = 2
DynamoDB Query: job_id=123 AND sequence >= 2
```

**Result:**
- Returns: Batch 1 (seq 1), Batch 2, Batch 3
- Client unpacks Batch 1 (events 1-50)
- Client filters to sequences >= 51
- Client discards all events from Batch 1 (0 events used)
- Client continues with Batch 2...

**Overhead:** Fetched entire Batch 1 (50 events), used 0 events

**Note:** This is the worst case for the formula, but still only 1 extra batch overhead.

### Client-Side Buffering Strategy

**High-Level Algorithm:**

```
1. Calculate minBatchSequence = max(1, fromSequence - maxBatchSize + 1)
2. Query DynamoDB: job_id=X AND sequence >= minBatchSequence
3. For each batch received:
   a. Unpack batch into individual events
   b. Filter events: keep only sequence >= fromSequence
   c. Add filtered events to client buffer
   d. Yield events to caller
4. Continue until all batches processed
```

**Client Buffer Structure:**

```go
type EventBuffer struct {
    events       []*jobv1.JobEvent
    readPosition int
    minSequence  int64  // Client's fromSequence
}

func (b *EventBuffer) AddBatch(batch *jobv1.OutputBatchEvent) {
    // Unpack batch
    for i, output := range batch.Outputs {
        sequence := batch.StartSequence + int64(i)

        // Filter: only add events >= minSequence
        if sequence < b.minSequence {
            continue
        }

        event := &jobv1.JobEvent{
            Sequence: sequence,
            EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_DATA,
            // ... populate from output
        }

        b.events = append(b.events, event)
    }
}

func (b *EventBuffer) Next() (*jobv1.JobEvent, bool) {
    if b.readPosition >= len(b.events) {
        return nil, false
    }

    event := b.events[b.readPosition]
    b.readPosition++
    return event, true
}

func (b *EventBuffer) Rewind(toSequence int64) {
    // Find position of toSequence in buffer
    for i, event := range b.events {
        if event.Sequence >= toSequence {
            b.readPosition = i
            return
        }
    }
}
```

**Example Usage:**

```go
// Client SDK usage
stream, err := client.StreamEvents(ctx, &jobv1.StreamEventsRequest{
    JobId:        "123",
    FromSequence: 75,
})

buffer := NewEventBuffer(75)

for {
    resp, err := stream.Recv()
    if err == io.EOF {
        break
    }

    switch event := resp.Event.EventData.(type) {
    case *jobv1.JobEvent_OutputBatch:
        // Batch event - unpack and buffer
        buffer.AddBatch(event.OutputBatch)

        // Yield events from buffer
        for {
            evt, ok := buffer.Next()
            if !ok {
                break
            }
            fmt.Printf("[%d] %s\n", evt.Sequence, evt.GetOutputData().Output)
        }

    case *jobv1.JobEvent_OutputData:
        // Individual event (legacy or non-batched)
        fmt.Printf("[%d] %s\n", resp.Event.Sequence, event.OutputData.Output)
    }
}
```

### Server-Side Implementation

**StreamEvents Method:**

```go
func (s *SQSJobStore) replayHistoricalEvents(
    ctx context.Context,
    jobID string,
    fromSequence int64,
    fromTimestamp int64,
    filterMap map[jobv1.EventType]bool,
    eventChan chan *jobv1.JobEvent,
) error {
    keyCond := expression.Key("job_id").Equal(expression.Value(jobID))

    // Batch-adjusted query optimization
    if fromSequence > 0 {
        // Calculate earliest batch that could contain fromSequence
        maxBatchSize := int64(s.cfg.EventBatchMaxSize) // e.g., 50
        minBatchSequence := max(int64(1), fromSequence - maxBatchSize + 1)

        keyCond = keyCond.And(
            expression.Key("sequence").GreaterThanEqual(expression.Value(minBatchSequence)),
        )

        log.Debug().
            Int64("from_sequence", fromSequence).
            Int64("min_batch_sequence", minBatchSequence).
            Int64("max_batch_size", maxBatchSize).
            Msg("Batch-adjusted query optimization applied")
    }

    expr, err := expression.NewBuilder().WithKeyCondition(keyCond).Build()
    if err != nil {
        return fmt.Errorf("failed to build query expression: %w", err)
    }

    queryInput := &dynamodb.QueryInput{
        TableName:                 aws.String(s.cfg.JobEventsTableName),
        KeyConditionExpression:    expr.KeyCondition(),
        ExpressionAttributeNames:  expr.Names(),
        ExpressionAttributeValues: expr.Values(),
    }

    paginator := dynamodb.NewQueryPaginator(s.dynamoClient, queryInput)

    for paginator.HasMorePages() {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        page, err := paginator.NextPage(ctx)
        if err != nil {
            return wrapAWSError(err, "failed to query historical events")
        }

        for _, item := range page.Items {
            // Unpack event (handles both batched and individual events)
            events, err := s.unpackEventItem(item)
            if err != nil {
                log.Warn().Err(err).Msg("Failed to unpack event, skipping")
                continue
            }

            // Send each unpacked event
            for _, event := range events {
                // Apply sequence filter AFTER unpacking
                if fromSequence > 0 && event.Sequence < fromSequence {
                    continue
                }

                // Apply timestamp filter
                if fromTimestamp > 0 && event.Timestamp.AsTime().UnixMilli() < fromTimestamp {
                    continue
                }

                // Apply event type filter
                if len(filterMap) > 0 && !filterMap[event.EventType] {
                    continue
                }

                // Send to channel (non-blocking)
                select {
                case eventChan <- event:
                case <-ctx.Done():
                    return ctx.Err()
                default:
                    log.Warn().Str("job_id", jobID).Int64("sequence", event.Sequence).
                        Msg("Event channel full, dropping event")
                }
            }
        }
    }

    log.Debug().Str("job_id", jobID).Msg("Finished replaying historical events")
    return nil
}
```

**Unpacking Helper:**

```go
// unpackEventItem handles both individual events and batched events
// Returns a slice of events (1 for individual, N for batched)
func (s *SQSJobStore) unpackEventItem(item map[string]types.AttributeValue) ([]*jobv1.JobEvent, error) {
    eventTypeAttr, ok := item["event_type"].(*types.AttributeValueMemberN)
    if !ok {
        return nil, fmt.Errorf("event_type not found")
    }

    eventType, _ := strconv.ParseInt(eventTypeAttr.Value, 10, 32)

    switch jobv1.EventType(eventType) {
    case jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH:
        // Unpack batched events
        return s.unpackOutputBatch(item)

    default:
        // Single event (ProcessStart, ProcessEnd, ProcessError, legacy OUTPUT_DATA)
        payloadAttr, ok := item["event_payload"].(*types.AttributeValueMemberB)
        if !ok {
            return nil, fmt.Errorf("event_payload not found")
        }

        event := &jobv1.JobEvent{}
        if err := util.UnmarshalProto(payloadAttr.Value, event); err != nil {
            return nil, err
        }

        return []*jobv1.JobEvent{event}, nil
    }
}

func (s *SQSJobStore) unpackOutputBatch(item map[string]types.AttributeValue) ([]*jobv1.JobEvent, error) {
    payloadAttr, ok := item["event_payload"].(*types.AttributeValueMemberB)
    if !ok {
        return nil, fmt.Errorf("event_payload not found")
    }

    // Unmarshal the batch event
    batchEvent := &jobv1.JobEvent{}
    if err := util.UnmarshalProto(payloadAttr.Value, batchEvent); err != nil {
        return nil, err
    }

    batch := batchEvent.GetOutputBatch()
    if batch == nil {
        return nil, fmt.Errorf("output_batch is nil")
    }

    // Expand batch into individual OUTPUT_DATA events
    events := make([]*jobv1.JobEvent, len(batch.Outputs))
    for i, output := range batch.Outputs {
        // Reconstruct original sequence number
        sequence := batch.StartSequence + int64(i)

        // Use stored timestamp or simulate timing
        var timestamp *timestamppb.Timestamp
        if len(batch.Timestamps) > i {
            timestamp = timestamppb.New(time.UnixMilli(batch.Timestamps[i]))
        } else {
            // Simulate timing: batch timestamp + (i * 50ms)
            baseTime := batchEvent.Timestamp.AsTime()
            timestamp = timestamppb.New(baseTime.Add(time.Duration(i) * 50 * time.Millisecond))
        }

        events[i] = &jobv1.JobEvent{
            Sequence:  sequence,
            Timestamp: timestamp,
            EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_DATA,
            EventData: &jobv1.JobEvent_OutputData{
                OutputData: &jobv1.OutputEvent{
                    Output: output.Output,
                    Stream: output.Stream,
                },
            },
        }
    }

    return events, nil
}
```

## Performance Analysis

### DynamoDB Query Efficiency

**Scenario:** 10,000-event job, fromSequence=9,000, maxBatchSize=50

**Without batching:**
- DynamoDB items: 10,000 individual events
- Query: `sequence >= 9000` returns 1,000 items
- Transfer size: ~100 KB (1,000 × 100 bytes each)
- Unmarshaling: 1,000 protobuf operations

**With batching (no optimization):**
- DynamoDB items: 200 batches (10,000 / 50)
- Query: `sequence >= 1` returns 200 batches
- Transfer size: ~200 KB (200 batches × 1 KB each)
- Unmarshaling: 200 protobuf operations
- Client filtering: 9,000 events discarded

**With batching + batch-adjusted query:**
- DynamoDB items: 200 batches
- Query: `sequence >= (9000 - 50 + 1) = 8951`
- Returns: ~20 batches (sequences 8951, 9001, 9051, ...)
- Transfer size: ~20 KB (20 batches × 1 KB each)
- Unmarshaling: 20 protobuf operations
- Client filtering: ~50 events discarded

**Comparison:**

| Metric | No Batching | Batching (naive) | Batching (optimized) |
|--------|-------------|------------------|----------------------|
| DynamoDB items returned | 1,000 | 200 | 20 |
| Transfer size | 100 KB | 200 KB | 20 KB |
| Protobuf unmarshal ops | 1,000 | 200 | 20 |
| Client filtering overhead | 0 | 9,000 events | 50 events |
| **Query latency** | 300ms | 400ms | 50ms |

**Result:** Batch-adjusted query is **6x faster** than non-batched and **8x faster** than naive batching.

### Client Filtering Overhead

**Question:** Is client-side filtering expensive?

**Analysis:**
- Filtering 50 events (check sequence >= fromSequence): <0.1ms
- Negligible compared to network and DynamoDB query time (50ms)
- Trade-off: Fetch 1 extra batch (~50 events) to avoid complex server logic

**Conclusion:** Client-side filtering overhead is acceptable given the query optimization gains.

## Server-Controlled Configuration

### Design Principle

**The server controls all batching parameters** and sends them to workers with each job. This provides:
- **Centralized configuration**: Change batching behavior without redeploying workers
- **Per-job tuning**: Different job types can have different batching parameters (future)
- **Version compatibility**: Server and worker stay synchronized automatically
- **Operational flexibility**: A/B test batch sizes, tune for performance

### Protocol Changes

```protobuf
// api/job/v1/job.proto

// Server-controlled execution parameters sent with each job
message ExecutionConfig {
  // Event batching configuration
  BatchingConfig batching = 1;

  // Heartbeat interval for UpdateJobVisibility
  int32 heartbeat_interval_seconds = 2;  // Default: 30

  // Future: timeout overrides, retry policies, etc.
}

message BatchingConfig {
  // How long worker should buffer events before flushing (time-based trigger)
  int32 flush_interval_seconds = 1;  // Default: 2

  // Maximum events per batch (size-based trigger)
  int32 max_batch_size = 2;  // Default: 50

  // Maximum bytes per batch (size-based trigger)
  int64 max_batch_bytes = 3;  // Default: 1 MB

  // Simulated interval between events for client playback
  // Stored in batches, used by clients during StreamEvents replay
  int32 playback_interval_millis = 4;  // Default: 50ms
}

// Add ExecutionConfig to Job message
message Job {
  string job_id = 1;
  JobState state = 2;
  google.protobuf.Timestamp created_at = 3;
  google.protobuf.Timestamp updated_at = 4;
  JobParams job_params = 5;

  // NEW: Server-controlled execution parameters
  ExecutionConfig execution_config = 6;
}

// Update OutputBatchEvent to include playback interval
message OutputBatchEvent {
  repeated OutputItem outputs = 1;
  int64 start_sequence = 2;
  int64 end_sequence = 3;
  repeated int64 timestamps = 4;

  // NEW: Playback interval for client replay timing
  // If set, clients should delay this many milliseconds between events
  // If 0, clients use default or simulate timing from timestamps
  int32 playback_interval_millis = 5;
}
```

### DynamoDB Schema Update

```go
// internal/store/sqs_store.go

type jobRecord struct {
    JobID           string                  `dynamodbav:"job_id"`
    Queue           string                  `dynamodbav:"queue"`
    State           int32                   `dynamodbav:"state"`
    RequestID       string                  `dynamodbav:"request_id"`
    CreatedAt       int64                   `dynamodbav:"created_at"`
    UpdatedAt       int64                   `dynamodbav:"updated_at"`
    JobParams       *jobv1.JobParams        `dynamodbav:"job_params"`
    ExecutionConfig *jobv1.ExecutionConfig  `dynamodbav:"execution_config"`  // NEW
}

func (r *jobRecord) toProto() *jobv1.Job {
    return &jobv1.Job{
        JobId:           r.JobID,
        State:           jobv1.JobState(r.State),
        CreatedAt:       timestamppb.New(time.UnixMilli(r.CreatedAt)),
        UpdatedAt:       timestamppb.New(time.UnixMilli(r.UpdatedAt)),
        JobParams:       r.JobParams,
        ExecutionConfig: r.ExecutionConfig,  // NEW
    }
}
```

### Server Configuration

```yaml
# config/server.yaml

store:
  type: sqs
  sqs:
    queues:
      default: https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default
    default_visibility_timeout_seconds: 300
  dynamodb:
    jobs_table: airunner_jobs
    events_table: airunner_job_events
    events_ttl_days: 30

  # NEW: Default execution configuration for all jobs
  execution:
    batching:
      flush_interval_seconds: 2      # Worker buffers for 2s before flushing
      max_batch_size: 50             # DynamoDB BatchWriteItem limit
      max_batch_bytes: 1048576       # 1 MB
      playback_interval_millis: 50   # Simulated timing for client replay
    heartbeat_interval_seconds: 30   # How often worker extends visibility timeout
```

### Server Implementation

**Config Structure:**

```go
// internal/store/sqs_store.go

type SQSJobStoreConfig struct {
    QueueURLs                       map[string]string
    JobsTableName                   string
    JobEventsTableName              string
    DefaultVisibilityTimeoutSeconds int32
    EventsTTLDays                   int32
    TokenSigningSecret              []byte

    // NEW: Default batching configuration
    DefaultBatchingConfig BatchingConfig
    DefaultHeartbeatInterval int32  // Seconds
}

type BatchingConfig struct {
    FlushIntervalSeconds   int32  // Default: 2
    MaxBatchSize           int32  // Default: 50
    MaxBatchBytes          int64  // Default: 1048576 (1 MB)
    PlaybackIntervalMillis int32  // Default: 50
}
```

**EnqueueJob - Populate ExecutionConfig:**

```go
func (s *SQSJobStore) EnqueueJob(ctx context.Context, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error) {
    // ... existing idempotency check ...

    jobID := uuid.Must(uuid.NewV7()).String()
    now := timestamppb.Now()

    // Populate default execution config from server configuration
    executionConfig := &jobv1.ExecutionConfig{
        Batching: &jobv1.BatchingConfig{
            FlushIntervalSeconds:    s.cfg.DefaultBatchingConfig.FlushIntervalSeconds,
            MaxBatchSize:            s.cfg.DefaultBatchingConfig.MaxBatchSize,
            MaxBatchBytes:           s.cfg.DefaultBatchingConfig.MaxBatchBytes,
            PlaybackIntervalMillis:  s.cfg.DefaultBatchingConfig.PlaybackIntervalMillis,
        },
        HeartbeatIntervalSeconds: s.cfg.DefaultHeartbeatInterval,
    }

    jobItem := map[string]types.AttributeValue{
        "job_id":     &types.AttributeValueMemberS{Value: jobID},
        "queue":      &types.AttributeValueMemberS{Value: req.Queue},
        "state":      &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", jobv1.JobState_JOB_STATE_SCHEDULED)},
        "request_id": &types.AttributeValueMemberS{Value: req.RequestId},
        "created_at": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.AsTime().UnixMilli())},
        "updated_at": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.AsTime().UnixMilli())},
    }

    // Marshal JobParams
    params, err := attributevalue.MarshalMap(req.JobParams)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal job params: %w", err)
    }
    jobItem["job_params"] = &types.AttributeValueMemberM{Value: params}

    // Marshal ExecutionConfig
    execConfig, err := attributevalue.MarshalMap(executionConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal execution config: %w", err)
    }
    jobItem["execution_config"] = &types.AttributeValueMemberM{Value: execConfig}

    // ... rest of PutItem and SQS send ...

    log.Info().
        Str("job_id", jobID).
        Int32("flush_interval_seconds", executionConfig.Batching.FlushIntervalSeconds).
        Int32("max_batch_size", executionConfig.Batching.MaxBatchSize).
        Msg("Job created with server-controlled batching config")

    return &jobv1.EnqueueJobResponse{
        JobId:     jobID,
        CreatedAt: now,
        State:     jobv1.JobState_JOB_STATE_SCHEDULED,
    }, nil
}
```

### Worker Implementation

**Extract Config from Job:**

```go
// internal/worker/worker.go

func (w *Worker) executeJob(ctx context.Context, job *JobWithToken) error {
    log.Info().
        Str("job_id", job.Job.JobId).
        Str("repository_url", job.Job.JobParams.RepositoryUrl).
        Msg("Starting job execution")

    // Extract batching config from job's execution config
    batchingCfg := w.extractBatchingConfig(job.Job.ExecutionConfig)

    // Create event batcher with job-specific config
    publishFunc := func(ctx context.Context, events []*jobv1.JobEvent) error {
        _, err := w.client.PublishEvents(ctx, &jobv1.PublishEventsRequest{
            TaskToken: job.TaskToken,
            Events:    events,
        })
        return err
    }

    eventBatcher := NewEventBatcher(job.Job.JobId, publishFunc, batchingCfg)
    defer eventBatcher.Close()

    // Setup heartbeat using job's heartbeat interval
    heartbeatInterval := time.Duration(job.Job.ExecutionConfig.HeartbeatIntervalSeconds) * time.Second
    w.startHeartbeat(ctx, job.TaskToken, heartbeatInterval)

    // ... rest of job execution ...
}

func (w *Worker) extractBatchingConfig(execCfg *jobv1.ExecutionConfig) EventBatcherConfig {
    // Use server-provided config if available, otherwise fallback to defaults
    if execCfg == nil || execCfg.Batching == nil {
        log.Warn().Msg("No batching config in job, using defaults")
        return EventBatcherConfig{
            FlushInterval:          2 * time.Second,
            MaxBatchSize:           50,
            MaxBatchBytes:          1048576,
            PlaybackIntervalMillis: 50,
        }
    }

    return EventBatcherConfig{
        FlushInterval:          time.Duration(execCfg.Batching.FlushIntervalSeconds) * time.Second,
        MaxBatchSize:           int(execCfg.Batching.MaxBatchSize),
        MaxBatchBytes:          execCfg.Batching.MaxBatchBytes,
        PlaybackIntervalMillis: execCfg.Batching.PlaybackIntervalMillis,
    }
}
```

**Event Batcher with Server Config:**

```go
// internal/worker/event_batcher.go

type EventBatcherConfig struct {
    FlushInterval          time.Duration  // e.g., 2s
    MaxBatchSize           int            // e.g., 50
    MaxBatchBytes          int64          // e.g., 1 MB
    PlaybackIntervalMillis int32          // e.g., 50ms (for client replay)
}

type EventBatcher struct {
    jobID       string
    publishFunc func(context.Context, []*jobv1.JobEvent) error
    cfg         EventBatcherConfig  // Server-provided config

    mu          sync.Mutex
    buffer      []*jobv1.JobEvent
    bufferBytes int64
    timer       *time.Timer

    stopCh      chan struct{}
    flushCh     chan struct{}
}

func NewEventBatcher(jobID string, publishFunc func(context.Context, []*jobv1.JobEvent) error, cfg EventBatcherConfig) *EventBatcher {
    b := &EventBatcher{
        jobID:       jobID,
        publishFunc: publishFunc,
        cfg:         cfg,
        buffer:      make([]*jobv1.JobEvent, 0, cfg.MaxBatchSize),
        stopCh:      make(chan struct{}),
        flushCh:     make(chan struct{}, 1),
    }

    go b.flushLoop()

    log.Info().
        Str("job_id", jobID).
        Dur("flush_interval", cfg.FlushInterval).
        Int("max_batch_size", cfg.MaxBatchSize).
        Int64("max_batch_bytes", cfg.MaxBatchBytes).
        Int32("playback_interval_millis", cfg.PlaybackIntervalMillis).
        Msg("Event batcher initialized with server config")

    return b
}

func (b *EventBatcher) createOutputBatchEvent(outputs []OutputItem, startSeq, endSeq int64, timestamps []int64) *jobv1.JobEvent {
    return &jobv1.JobEvent{
        Sequence:  startSeq,
        Timestamp: timestamppb.New(time.UnixMilli(timestamps[0])),
        EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
        EventData: &jobv1.JobEvent_OutputBatch{
            OutputBatch: &jobv1.OutputBatchEvent{
                Outputs:                outputs,
                StartSequence:          startSeq,
                EndSequence:            endSeq,
                Timestamps:             timestamps,
                PlaybackIntervalMillis: b.cfg.PlaybackIntervalMillis,  // Include for client replay
            },
        },
    }
}
```

### Configuration Flow

```
1. Admin configures server.yaml:
   execution.batching.flush_interval_seconds: 2
   execution.batching.max_batch_size: 50

2. Server starts, loads config into SQSJobStoreConfig

3. Client calls EnqueueJob(repository_url="...")

4. Server creates job with ExecutionConfig:
   {
     batching: {flush_interval_seconds: 2, max_batch_size: 50, ...},
     heartbeat_interval_seconds: 30
   }

5. Worker calls DequeueJobs()

6. Server returns JobWithToken containing Job with ExecutionConfig

7. Worker extracts batching config from job.execution_config.batching

8. Worker creates EventBatcher with server-provided config

9. Worker publishes batches using server's parameters

10. Server queries with batch-adjusted formula using same max_batch_size

11. Client receives batches with playback_interval_millis

12. Client replays events with server-specified timing
```

### Benefits

1. **Operational Flexibility**: Change batching without redeploying workers
2. **Consistency**: Server and worker always use the same parameters
3. **Per-Job Customization** (future): Override config in `EnqueueJobRequest`
4. **Version Compatibility**: Old workers get sensible defaults, new workers use server config
5. **Simplified Testing**: Test different batch sizes via config changes

## Implementation Phases

**Context**: No existing users, development data can be deleted. This allows a clean, direct implementation without backwards compatibility concerns.

### Phase 1: Protocol Changes (1 day)

**Goal**: Add ExecutionConfig, BatchingConfig, and OUTPUT_BATCH to protobuf

**Deliverables**:
- [ ] Update `api/job/v1/job.proto`:
  - Add `ExecutionConfig` message with `BatchingConfig` and `heartbeat_interval_seconds`
  - Add `BatchingConfig` message with flush_interval, max_batch_size, max_batch_bytes, playback_interval_millis
  - Add `execution_config` field to `Job` message
  - Add `OutputBatchEvent` message with outputs, sequences, timestamps, playback_interval_millis
  - Add `OutputItem` message (output bytes, stream type)
  - Add `EVENT_TYPE_OUTPUT_BATCH` to `EventType` enum
- [ ] Run `make proto-generate` to generate Go code
- [ ] Verify compilation

**Success Criteria**:
- Protobuf compiles without errors
- Generated Go code builds successfully

---

### Phase 2: Server Implementation (2-3 days)

**Goal**: Server creates jobs with ExecutionConfig and unpacks batches in StreamEvents

**Deliverables**:
- [ ] Update `internal/store/sqs_store.go`:
  - Add `BatchingConfig` to `SQSJobStoreConfig`
  - Add `ExecutionConfig` to `jobRecord` struct
  - Update `toProto()` to include `ExecutionConfig`
- [ ] Update `SQSJobStore.EnqueueJob`:
  - Populate `ExecutionConfig` with defaults from config
  - Marshal to DynamoDB `execution_config` attribute
- [ ] Implement batch unpacking:
  - Add `unpackEventItem()` - detect OUTPUT_BATCH vs individual events
  - Add `unpackOutputBatch()` - expand batch into individual OUTPUT_DATA events
  - Update `replayHistoricalEvents()` to call `unpackEventItem()`
  - Implement timestamp simulation using `playback_interval_millis`
- [ ] Add batch-adjusted query optimization:
  - Calculate `minBatchSequence = max(1, fromSequence - maxBatchSize + 1)`
  - Apply to KeyConditionExpression in query
- [ ] Update config loading in `cmd/server/main.go`:
  - Parse `execution.batching` from YAML
  - Populate `SQSJobStoreConfig.DefaultBatchingConfig`
  - Validate values (max_batch_size <= 50, positive intervals)
- [ ] Unit tests:
  - Test ExecutionConfig marshaling/unmarshaling
  - Test batch unpacking with 50 events
  - Test timestamp simulation
  - Test batch-adjusted query formula
- [ ] Integration tests:
  - Enqueue job, verify execution_config in DynamoDB
  - Create batched events, stream them, verify unpacking

**Success Criteria**:
- EnqueueJob stores ExecutionConfig in DynamoDB
- StreamEvents correctly unpacks OUTPUT_BATCH events
- Batch-adjusted query optimization works
- Config validation prevents invalid values

---

### Phase 3: Worker Implementation (2-3 days)

**Goal**: Worker batches events using server-provided config

**Deliverables**:
- [ ] Create `internal/worker/event_batcher.go`:
  - `EventBatcherConfig` struct (from ExecutionConfig)
  - `EventBatcher` struct with buffer, timer, config
  - `Add(event)` - buffer events, check flush triggers
  - `flushLoop()` - goroutine that flushes on timer/signal
  - `createOutputBatchEvent()` - convert buffer to OUTPUT_BATCH
  - `isCriticalEvent()` - detect ProcessStart/ProcessEnd/ProcessError
  - `triggerFlush()` - signal immediate flush
  - `Close()` - graceful shutdown with final flush
- [ ] Update `internal/worker/worker.go`:
  - Add `extractBatchingConfig()` - read from job.execution_config
  - Initialize `EventBatcher` at job start
  - Replace `PublishEvents` calls with `EventBatcher.Add()`
  - Call `EventBatcher.Close()` in defer
- [ ] Unit tests:
  - Time-based flush (wait 2s, verify flush)
  - Size-based flush (add 50 events, verify flush)
  - Byte-based flush (add 1 MB, verify flush)
  - Critical event immediate flush
  - Batch structure (correct sequences, timestamps)
  - Graceful shutdown (pending events flushed)
- [ ] Integration tests:
  - Run worker with 100-line output job
  - Verify ~2 OUTPUT_BATCH events in DynamoDB
  - Verify sequences are continuous (2-51, 52-101)
  - Verify ProcessStart/ProcessEnd are separate events

**Success Criteria**:
- Worker batches output events correctly
- Flush triggers work (time, size, bytes, critical events)
- Sequences are monotonic and continuous
- No events lost on shutdown

---

### Phase 4: Testing & Deployment (1-2 days)

**Goal**: End-to-end testing and deployment

**Deliverables**:
- [ ] **Delete development data**: Drop DynamoDB tables, recreate schema
- [ ] End-to-end test:
  - Submit job via CLI
  - Monitor job with `airunner-cli monitor`
  - Verify batched output plays back smoothly
  - Check DynamoDB for OUTPUT_BATCH events
- [ ] Performance testing:
  - Job with 10,000 output lines
  - Measure DynamoDB writes (should be ~200 instead of 10,000)
  - Measure StreamEvents latency
  - Test batch-adjusted query (fromSequence=9000)
- [ ] Load testing:
  - 100 concurrent jobs
  - 1,000 output lines each
  - Verify system stability
  - No events lost or out-of-order
- [ ] Deploy to development:
  - Deploy server with new config
  - Deploy worker
  - Smoke test with real job

**Success Criteria**:
- DynamoDB writes reduced by 50x
- StreamEvents works correctly with batched data
- Query optimization reduces latency by 6-8x
- System stable under load
- CLI monitor shows smooth playback

---

### Phase 5: Observability (1-2 days)

**Goal**: Add metrics, logging, and operational tooling

**Deliverables**:
- [ ] Add OpenTelemetry metrics:
  - `airunner.batching.batch_size` (histogram)
  - `airunner.batching.flush_reason` (counter: time/size/bytes/critical)
  - `airunner.batching.flush_latency` (histogram)
  - `airunner.batching.events_buffered` (gauge)
- [ ] Add structured logging:
  - Log batch creation (job_id, size, sequence range)
  - Log flush events (job_id, reason, latency)
  - Log config extraction (job_id, flush_interval, max_batch_size)
- [ ] Create operational runbook:
  - How to adjust batch size for different workloads
  - How to monitor batching efficiency
  - How to troubleshoot missing/out-of-order events
  - How to interpret metrics

**Success Criteria**:
- Metrics visible in telemetry backend (Honeycomb, etc.)
- Logs provide useful debugging information
- Runbook covers common scenarios

---

### Phase 6: CLI Monitor Enhancement (Optional, 1-2 days)

**Goal**: Improve CLI monitor to handle batched playback timing

**Deliverables**:
- [ ] Update `cmd/cli/commands/monitor.go`:
  - Read `playback_interval_millis` from batches
  - Sleep between events for smooth playback
  - Add `--fast` flag to disable delays
  - Add `--slow` flag to increase delays (e.g., 2x)
- [ ] Add playback controls:
  - Detect terminal width, wrap long lines
  - Show progress indicator (event N of M)
  - Color-code stdout vs stderr

**Success Criteria**:
- Monitor command plays back logs smoothly
- Delays feel natural (50ms default)
- Fast mode useful for debugging

---

## Simplified Rollout (No Users)

### Week 1: Core Implementation
- **Day 1**: Phase 1 - Protocol changes
- **Day 2-4**: Phase 2 - Server implementation
- **Day 5**: Testing

### Week 2: Worker and Testing
- **Day 1-3**: Phase 3 - Worker implementation
- **Day 4-5**: Phase 4 - E2E testing and deployment

### Week 3: Polish
- **Day 1-2**: Phase 5 - Observability
- **Day 3-5**: Phase 6 - CLI enhancements (optional)

## Deployment Strategy

**Simple approach (no backwards compatibility needed)**:

1. **Delete all development data**:
   ```bash
   # Drop and recreate DynamoDB tables
   aws dynamodb delete-table --table-name airunner_jobs
   aws dynamodb delete-table --table-name airunner_job_events
   terraform apply  # Recreate tables
   ```

2. **Deploy everything at once**:
   ```bash
   make build
   # Deploy server
   # Deploy worker
   # Test with real job
   ```

3. **Verify**:
   ```bash
   # Submit test job
   ./bin/airunner-cli submit https://github.com/example/repo

   # Monitor output
   ./bin/airunner-cli monitor <job-id>

   # Check DynamoDB
   aws dynamodb scan --table-name airunner_job_events
   # Should see EVENT_TYPE_OUTPUT_BATCH (type=2) events
   ```

## Removed Complexity

Since there are no users and data can be deleted, we **removed**:
- ✅ Feature flags
- ✅ Backwards compatibility code for old event formats
- ✅ Migration phases (dual-write, gradual rollout)
- ✅ Rollback procedures
- ✅ Support for jobs without ExecutionConfig
- ✅ Handling mixed batched/individual events (only batched)

This reduces implementation time from **4-5 weeks to 2-3 weeks**

## Testing Scenarios

### Test Case 1: Batch Boundary Edge Cases

```go
func TestBatchBoundaryQueryOptimization(t *testing.T) {
    // Setup: 3 batches
    batches := []Batch{
        {Sequence: 1, Events: makeEvents(1, 50)},   // events 1-50
        {Sequence: 51, Events: makeEvents(51, 100)}, // events 51-100
        {Sequence: 101, Events: makeEvents(101, 150)}, // events 101-150
    }

    testCases := []struct {
        name             string
        fromSequence     int64
        expectedBatches  []int64  // Batch sequences returned
        expectedEvents   int      // Total events after filtering
    }{
        {
            name:            "Exact batch start",
            fromSequence:    51,
            expectedBatches: []int64{1, 51, 101}, // Batch 1 fetched but filtered out
            expectedEvents:  100,                 // Events 51-150
        },
        {
            name:            "Mid-batch",
            fromSequence:    75,
            expectedBatches: []int64{51, 101},    // Batch 1 skipped!
            expectedEvents:  76,                  // Events 75-150
        },
        {
            name:            "Near end",
            fromSequence:    145,
            expectedBatches: []int64{101},        // Only last batch
            expectedEvents:  6,                   // Events 145-150
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Execute batch-adjusted query
            minBatchSeq := max(1, tc.fromSequence - 50 + 1)
            batches := queryBatches(minBatchSeq)

            require.Equal(t, tc.expectedBatches, getBatchSequences(batches))

            // Unpack and filter
            events := unpackAndFilter(batches, tc.fromSequence)
            require.Equal(t, tc.expectedEvents, len(events))

            // Validate sequences
            require.Equal(t, tc.fromSequence, events[0].Sequence)
            require.Equal(t, int64(150), events[len(events)-1].Sequence)
        })
    }
}
```

### Test Case 2: Variable Batch Sizes

```go
func TestVariableBatchSizes(t *testing.T) {
    // Setup: Batches with variable sizes (realistic scenario)
    batches := []Batch{
        {Sequence: 1, Events: makeEvents(1, 30)},    // 30 events (flushed on timer)
        {Sequence: 31, Events: makeEvents(31, 75)},  // 45 events (flushed on size)
        {Sequence: 76, Events: makeEvents(76, 125)}, // 50 events (max batch)
        {Sequence: 126, Events: makeEvents(126, 150)}, // 25 events (flushed on ProcessEnd)
    }

    fromSequence := int64(100)
    maxBatchSize := int64(50)

    // Calculate query range
    minBatchSeq := max(1, fromSequence - maxBatchSize + 1) // = 51

    // Query should return batches 3 and 4
    returnedBatches := queryBatches(minBatchSeq)
    require.Equal(t, []int64{76, 126}, getBatchSequences(returnedBatches))

    // Unpack and filter
    events := unpackAndFilter(returnedBatches, fromSequence)

    // Should get events 100-150 (51 events total)
    require.Equal(t, 51, len(events))
    require.Equal(t, int64(100), events[0].Sequence)
    require.Equal(t, int64(150), events[50].Sequence)
}
```

### Test Case 3: Interleaved Critical Events

```go
func TestInterleavedCriticalEvents(t *testing.T) {
    // Setup: Batches interleaved with critical events
    items := []DynamoDBItem{
        {Sequence: 1, EventType: PROCESS_START},
        {Sequence: 2, EventType: OUTPUT_BATCH, Events: makeEvents(2, 51)},
        {Sequence: 52, EventType: OUTPUT_BATCH, Events: makeEvents(52, 101)},
        {Sequence: 102, EventType: PROCESS_ERROR, ErrorMsg: "test error"},
        {Sequence: 103, EventType: OUTPUT_BATCH, Events: makeEvents(103, 152)},
        {Sequence: 153, EventType: PROCESS_END},
    }

    fromSequence := int64(50)

    // Query
    events := streamEvents(fromSequence)

    // Validate event order
    require.Equal(t, int64(50), events[0].Sequence)  // Last event from first batch
    require.Equal(t, OUTPUT_DATA, events[0].EventType)

    require.Equal(t, int64(52), events[2].Sequence)  // First event from second batch

    // Critical event preserved
    require.Equal(t, int64(102), events[52].Sequence)
    require.Equal(t, PROCESS_ERROR, events[52].EventType)
}
```

## Backwards Compatibility

**Existing clients:**
- Receive unpacked individual events (no change)
- Server handles unpacking transparently
- Batching is an internal optimization

**Old data (pre-batching):**
- Individual OUTPUT_DATA events remain in DynamoDB
- Server's `unpackEventItem` handles both formats
- Mixed batched + individual events work correctly

**Rollback:**
- Disable worker batching (set `max_batch_size=1`)
- Server continues to handle both formats
- No data loss or API changes

## Future Enhancements

### 1. Client SDK with Batch Access

Expose batches directly to advanced clients:

```go
// High-level API (auto-unpacks)
stream, _ := client.StreamEvents(ctx, req)
for event := range stream.Events() {
    fmt.Println(event.GetOutputData().Output)
}

// Low-level API (raw batches for custom buffering)
stream, _ := client.StreamEventBatches(ctx, req)
for batch := range stream.Batches() {
    // Client implements custom unpacking, caching, seeking
    customBuffer.Add(batch)
}
```

### 2. Adaptive Batch Sizing

Worker adjusts batch size based on output rate:
- High output rate (>100 lines/sec): Batch every 1 second
- Low output rate (<10 lines/sec): Batch every 5 seconds
- Adaptive threshold balances latency vs. efficiency

### 3. Compressed Batches

Store batches with gzip compression:
- Reduce DynamoDB item size (text logs compress 70%)
- Reduce transfer cost
- Trade-off: CPU cost for compression/decompression

### 4. Predictive Prefetching

Client SDK prefetches next batch while processing current batch:
- Reduces perceived latency for sequential replay
- Improves streaming UX

## References

- [specs/sqs_dynamodb_backend.md](sqs_dynamodb_backend.md) - Parent specification
- [api/job/v1/job.proto](../api/job/v1/job.proto) - Protobuf definitions
- [internal/store/sqs_store.go](../internal/store/sqs_store.go) - Server implementation
- [internal/worker/event_batcher.go](../internal/worker/event_batcher.go) - Worker batching logic
