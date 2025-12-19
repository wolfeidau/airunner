# SQS/DynamoDB Backend Implementation Plan

## Overview

This document outlines the implementation plan for adding production-ready AWS backend support to airunner, using SQS for job queueing and DynamoDB for persistence. The design maintains full API compatibility with the existing `JobStore` interface.

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SQSJobStore                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│   │     SQS      │    │   DynamoDB   │    │   DynamoDB   │              │
│   │   Queues     │    │  Jobs Table  │    │ Events Table │              │
│   ├──────────────┤    ├──────────────┤    ├──────────────┤              │
│   │ • Dequeue    │    │ • Job state  │    │ • Event log  │              │
│   │ • Visibility │    │ • Metadata   │    │ • Streaming  │              │
│   │ • Delete     │    │ • Idempotency│    │ • Replay     │              │
│   └──────────────┘    └──────────────┘    └──────────────┘              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Design Principle:** SQS is transport-only; DynamoDB is the source of truth.

## AWS Resources

### SQS Queues

One SQS Standard queue per logical job queue:

- **Naming**: `airunner-{env}-{queueName}` (e.g., `airunner-prod-default`)
- **Configuration**:
  - `VisibilityTimeout`: 300 seconds (default, overridden per-message)
  - `ReceiveMessageWaitTimeSeconds`: 20 (long polling)
  - `MessageRetentionPeriod`: 14 days
  - Dead-letter queue with redrive policy (maxReceiveCount: 3)
  - SSE-SQS encryption enabled

**SQS Message Body Format:**

```json
{
  "job_id": "01234567-89ab-cdef-0123-456789abcdef",
  "queue": "default",
  "attempt": 1
}
```

### DynamoDB Tables

#### Jobs Table: `airunner_jobs`

| Attribute | Type | Description |
|-----------|------|-------------|
| `job_id` (PK) | S | UUIDv7 job identifier |
| `queue` | S | Queue name |
| `state` | N | JobState enum value |
| `job_params` | M | Serialized JobParams |
| `request_id` | S | Idempotency token |
| `created_at` | N | Unix milliseconds |
| `updated_at` | N | Unix milliseconds |
| `result` | M | JobResult (populated on completion) |

**Global Secondary Indexes:**

| Index | PK | SK | Projection | Purpose |
|-------|----|----|------------|---------|
| GSI1 | `queue` | `created_at` | ALL | ListJobs by queue |
| GSI2 | `request_id` | - | KEYS_ONLY | Idempotency lookup |

**Capacity:** On-demand billing mode for unpredictable workloads.

#### JobEvents Table: `airunner_job_events`

| Attribute | Type | Description |
|-----------|------|-------------|
| `job_id` (PK) | S | Job identifier |
| `sequence` (SK) | N | Monotonic sequence number |
| `timestamp` | N | Unix milliseconds |
| `event_type` | N | EventType enum value |
| `event_payload` | B | Protobuf-encoded event data |
| `ttl` | N | TTL attribute (Unix seconds) |

**Configuration:**
- TTL enabled on `ttl` attribute (recommended: 7-30 days retention)
- DynamoDB Streams: NEW_IMAGE (for cross-instance fanout, optional)

## Task Token Design

Use a **stateless, self-describing task token** for cross-instance compatibility:

```
taskToken = base64url(job_id + "|" + queue_name + "|" + sqs_receipt_handle)
```

Benefits:
- No in-memory state required
- Works across multiple API server replicas
- Self-contained: any server can process any token
- Still opaque to clients

## Implementation Details

### SQSJobStore Structure

```go
type SQSJobStoreConfig struct {
    QueueURLs                       map[string]string // queue name -> SQS URL
    JobsTableName                   string
    JobEventsTableName              string
    DefaultVisibilityTimeoutSeconds int32
}

type SQSJobStore struct {
    sqsClient    *sqs.Client
    dynamoClient *dynamodb.Client
    cfg          SQSJobStoreConfig

    // Local event streaming (same semantics as MemoryJobStore)
    mu           sync.RWMutex
    eventStreams map[string][]chan *jobv1.JobEvent

    stopCh chan struct{}
    wg     sync.WaitGroup
}
```

### Method Implementations

#### EnqueueJob

1. **Idempotency check**: Query GSI2 by `request_id`
   - If exists, return existing job metadata
2. **Create job in DynamoDB**: PutItem with `attribute_not_exists(job_id)` condition
3. **Send to SQS**: Minimal JSON message body
4. **Return**: `EnqueueJobResponse{JobId, CreatedAt, State}`

```go
func (s *SQSJobStore) EnqueueJob(ctx context.Context, req *jobv1.EnqueueJobRequest) (*jobv1.EnqueueJobResponse, error) {
    // 1. Check idempotency via GSI2
    existing, err := s.getJobByRequestID(ctx, req.RequestId)
    if err != nil {
        return nil, err
    }
    if existing != nil {
        return &jobv1.EnqueueJobResponse{
            JobId:     existing.JobId,
            CreatedAt: existing.CreatedAt,
            State:     existing.State,
        }, nil
    }

    // 2. Create job record
    jobId := uuid.Must(uuid.NewV7()).String()
    now := time.Now()
    
    // PutItem to DynamoDB...
    
    // 3. Send to SQS
    // SendMessage with job_id in body...
    
    return &jobv1.EnqueueJobResponse{...}, nil
}
```

#### DequeueJobs

1. **ReceiveMessage** from SQS (max 10 messages per call)
2. **Get job metadata** from DynamoDB for each message
3. **Filter poison messages**: Skip if job not found or already completed
4. **Update job state** to RUNNING in DynamoDB
5. **Set visibility timeout** via ChangeMessageVisibility
6. **Build task tokens** from job_id + queue + receipt_handle
7. **Return** slice of `JobWithToken`

```go
func (s *SQSJobStore) DequeueJobs(ctx context.Context, queue string, maxJobs int, timeoutSeconds int) ([]*JobWithToken, error) {
    queueURL := s.cfg.QueueURLs[queue]
    n := min(maxJobs, 10) // SQS limit
    
    output, err := s.sqsClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
        QueueUrl:            aws.String(queueURL),
        MaxNumberOfMessages: int32(n),
        WaitTimeSeconds:     0, // Long polling handled at service layer
    })
    // Process messages...
}
```

#### UpdateJobVisibility

1. **Decode task token** → job_id, queue, receipt_handle
2. **Validate queue** matches embedded queue name
3. **ChangeMessageVisibility** in SQS
4. **Update updated_at** in DynamoDB (optional)

#### CompleteJob

1. **Decode task token** → job_id, queue, receipt_handle
2. **Validate job_id** matches result.job_id
3. **UpdateItem** in DynamoDB: set state, result fields
4. **DeleteMessage** from SQS
5. **Handle race conditions**: Job may reappear if delete fails; guard on dequeue

#### ListJobs

1. **Query GSI1** if queue specified, otherwise **Scan** (with warning)
2. **Apply FilterExpression** for state
3. **In-memory pagination** using page/page_size
4. **Return** jobs and last_page

#### PublishEvents

1. **Decode task token** → job_id
2. **Validate job exists** in DynamoDB
3. **BatchWriteItem** events to JobEvents table
4. **Local fanout** to active streams via `fanoutEvent()`

#### StreamEvents

1. **Validate job exists** in DynamoDB
2. **Create channel** and register in eventStreams map
3. **Spawn goroutine**:
   - Query historical events from JobEvents table
   - Apply sequence/timestamp/type filters
   - Stream to channel
   - Wait for context cancellation
4. **Real-time events** arrive via PublishEvents → fanoutEvent

## Error Handling

| Scenario | Error Code | Handling |
|----------|------------|----------|
| Invalid task token | `InvalidArgument` | Return immediately |
| Job not found | `NotFound` | Return error |
| Queue not configured | `InvalidArgument` | Return error |
| AWS throttling | `ResourceExhausted` | Retry with backoff |
| AWS internal error | `Internal` | Log and return |
| Poison message | N/A | Delete from SQS, skip |

## Operational Considerations

### At-Least-Once Processing

SQS provides at-least-once delivery. Handle redelivery:

1. **On dequeue**: Check job state in DynamoDB
   - If COMPLETED/FAILED: delete SQS message, skip
2. **Workers must be idempotent**: Same job_id may be processed multiple times

### Race Conditions

**CompleteJob vs. Visibility Timeout:**
- If CompleteJob updates DynamoDB but fails to delete SQS message, job may reappear
- Guard: Check job state on dequeue before returning to worker

### Cost Optimization

- Use on-demand DynamoDB billing for variable workloads
- Enable TTL on JobEvents to auto-expire old events
- Use SQS long polling (20s) to reduce empty receives
- Consider S3 for large event payloads (OutputEvent.output)

### Monitoring

Emit metrics for:
- SQS operations: SendMessage, ReceiveMessage, DeleteMessage latency/errors
- DynamoDB: RCU/WCU usage, throttling events
- Job lifecycle: enqueue rate, completion rate, failure rate
- Event streaming: active streams, events/second

## Implementation Phases

### Phase 1: Core Store Implementation (2-3 days)

- [x] Create `internal/store/sqs_store.go`
- [x] Implement `SQSJobStore` struct and config
- [x] Implement `EnqueueJob` with idempotency
- [x] Implement `DequeueJobs` with visibility management
- [x] Implement `UpdateJobVisibility`
- [x] Implement `CompleteJob`
- [x] Implement `ListJobs` via GSI1
- [x] Add task token encoding/decoding utilities

### Phase 2: Event Streaming (1-2 days)

- [ ] Implement `PublishEvents` with DynamoDB writes
- [ ] Implement `StreamEvents` with historical replay
- [ ] Implement local `fanoutEvent` for real-time streaming
- [ ] Add TTL support for event retention

### Phase 3: Infrastructure & Testing (1-2 days)

- [ ] Create Terraform/CDK for AWS resources
- [ ] Add integration tests with LocalStack
- [ ] Add configuration loading for AWS clients
- [ ] Update orchestrator cmd to use SQSJobStore
- [ ] Document deployment and configuration

### Phase 4: Production Hardening (1-2 days)

- [ ] Add structured logging with zerolog
- [ ] Add metrics emission (CloudWatch/OpenTelemetry)
- [ ] Implement retry policies with exponential backoff
- [ ] Add health checks for AWS connectivity
- [ ] Load testing and capacity planning

## Future Enhancements

### Multi-Instance Event Streaming

For cross-instance real-time streaming:

1. Enable DynamoDB Streams on JobEvents table
2. Add KCL-based stream consumer to each API server
3. Demux events by job_id and fanout to local subscribers

### Large Payload Offloading

For jobs with large parameters or output:

1. Store payloads in S3 with key format: `jobs/{job_id}/params.json`
2. Store S3 references in DynamoDB
3. Generate pre-signed URLs for direct client access

### Cursor-Based Pagination

Replace page/page_size with cursor-based pagination:

1. Use DynamoDB `LastEvaluatedKey` as cursor
2. Base64-encode cursor for API response
3. Maintain backwards compatibility with page-based API

## Configuration Example

```yaml
store:
  type: sqs
  aws:
    region: us-west-2
  sqs:
    queues:
      default: https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default
      priority: https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-priority
    default_visibility_timeout_seconds: 300
  dynamodb:
    jobs_table: airunner_jobs
    events_table: airunner_job_events
    events_ttl_days: 30
```

## References

- [specs/job_api.md](job_api.md) - Original job API design
- [internal/store/store.go](../internal/store/store.go) - JobStore interface and MemoryJobStore
- [api/job/v1/job.proto](../api/job/v1/job.proto) - Protobuf definitions
