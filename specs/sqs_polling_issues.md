# SQS Polling and Message Retry Issues

This document analyzes issues in the SQS polling implementation that cause message retries due to interrupted calls.

## Critical Issues Identified

### 1. Race Condition in `DequeueJob` Streaming

**Location**: `internal/server/job.go:55-67`

```go
for _, jobWithToken := range jobs {
    resp := &v1.DequeueJobResponse{...}
    if err := stream.Send(resp); err != nil {  // <-- PROBLEM HERE
        return connect.NewError(connect.CodeInternal, err)
    }
}
```

**Problem**: By the time `stream.Send()` is called:
- The SQS message has been received (visibility timeout started)
- Job state is already updated to `RUNNING` in DynamoDB (`sqs_store.go:458-461`)
- If `stream.Send()` fails (network issue, client disconnect), the error returns but:
  - The SQS message is **NOT deleted** (only deleted on `CompleteJob`)
  - After visibility timeout expires → **message redelivers → retry**

### 2. No Context Cancellation Checks in Critical Section

**Location**: `internal/store/sqs_store.go:425-474`

The message processing loop doesn't check `ctx.Done()` between operations:

```go
for _, message := range output.Messages {
    // ... extract job_id
    job, err := s.getJobByID(ctx, tt.JobID)  // DynamoDB call
    // ... no ctx.Done() check here
    err = s.updateJobState(ctx, job)          // DynamoDB call
    // ... no ctx.Done() check here
    taskToken := s.encodeTaskToken(...)
    results = append(results, ...)
}
```

If context cancels mid-loop, partially processed messages leave inconsistent state.

### 3. Silent Failure on State Update

**Location**: `internal/store/sqs_store.go:461-465`

```go
err = s.updateJobState(ctx, job)
if err != nil {
    log.Error().Err(err).Str("job_id", jobID).Msg("Failed to update job state to RUNNING")
    continue  // <-- Message stays in queue, will retry
}
```

When state update fails, the message is left in the queue without any visibility adjustment. It will retry after the original visibility timeout.

### 4. Aggressive Polling Creates More Failure Windows

**Location**: `internal/server/job.go:45`

```go
ticker := time.NewTicker(100 * time.Millisecond)  // 10 polls/second
```

Combined with `WaitTimeSeconds: 0` in SQS (`sqs_store.go:406`), this creates:
- Many rapid SQS API calls
- More opportunities for context cancellation during critical operations
- Higher chance of hitting throttling limits under load

### 5. No Atomic Dequeue Operation

The dequeue flow has multiple failure points without rollback:

```
1. Receive SQS message (visibility timer starts)
2. Get job from DynamoDB ← failure here = message retries
3. Update job state to RUNNING ← failure here = state inconsistent
4. Stream to client ← failure here = job marked RUNNING but client doesn't have it
```

## Specific Scenarios Causing Retries

| Scenario | What Happens | Result |
|----------|--------------|--------|
| Client disconnect during `stream.Send()` | Job already RUNNING in DynamoDB, message not deleted | Retry after visibility timeout |
| Network timeout between DynamoDB calls | State partially updated | Inconsistent state + retry |
| Context cancelled (request timeout) | Operations abandoned mid-flow | Message retries |
| Throttling on DynamoDB | `updateJobState` fails, continues | Message retries |

## Recommendations

### 1. Enable SQS Long Polling

Change `WaitTimeSeconds: 0` to `20` (SQS max) in `sqs_store.go:406` to reduce API calls and failure windows.

### 2. Add Context Checks in Message Loop

Check `ctx.Err()` between DynamoDB operations in the message processing loop.

### 3. Release Messages on Stream Failures

If `stream.Send()` fails, immediately change visibility timeout to 0 to release the message back to queue instead of waiting for timeout expiry.

```go
// Pseudo-code for releasing message on failure
if err := stream.Send(resp); err != nil {
    // Release message back to queue immediately
    s.store.ChangeMessageVisibility(ctx, queueURL, receiptHandle, 0)
    return connect.NewError(connect.CodeInternal, err)
}
```

### 4. Consider Two-Phase Dequeue

Restructure the dequeue flow:
1. Receive message from SQS
2. Stream job to client
3. Client ACKs receipt
4. **Then** update state to RUNNING

This ensures the client received the job before committing state changes.

### 5. Add Idempotency to Job State Updates

Allow re-running jobs that are already in RUNNING state (for retry scenarios). The worker should handle receiving a job it may have partially processed.

### 6. Reduce Polling Frequency

Consider increasing the polling interval from 100ms to 500ms-1s when using short polling, or switch to long polling which is more efficient.

## Related Files

- `internal/store/sqs_store.go` - SQS/DynamoDB store implementation
- `internal/server/job.go` - Job service with dequeue streaming
- `internal/server/job_event.go` - Event streaming service
- `internal/worker/worker.go` - Client-side job executor
