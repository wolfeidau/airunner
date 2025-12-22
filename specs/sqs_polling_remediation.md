# Implementation Plan: SQS Polling Fixes

## Summary

Fix message retry issues caused by interrupted calls during SQS polling by implementing the 6 recommendations from `specs/sqs_polling_issues.md`.

## Files to Modify

1. `internal/store/store.go` - Add `ReleaseJob` method to interface and `MemoryJobStore`
2. `internal/store/sqs_store.go` - Implement fixes for SQS store
3. `internal/server/job.go` - Handle stream failures with job release
4. `internal/telemetry/metrics.go` - Add `JobsRedeliveredTotal` metric
5. `internal/store/store_test.go` - Unit tests for `MemoryJobStore.ReleaseJob`
6. `internal/store/sqs_store_test.go` - Unit tests for `SQSJobStore.ReleaseJob`

## Implementation Details

### 1. Add `ReleaseJob` Method to JobStore Interface

**File**: `internal/store/store.go`

Add new method to the `JobStore` interface:
```go
// ReleaseJob returns a job back to the queue, resetting its state to SCHEDULED
// This is used when a dequeued job cannot be delivered to the client
ReleaseJob(ctx context.Context, taskToken string) error
```

Implement in `MemoryJobStore`:
- Look up job by task token
- Reset state to `JOB_STATE_SCHEDULED`
- Return job to front of queue
- Clean up visibility timeout and task token tracking

### 2. SQS Store Changes

**File**: `internal/store/sqs_store.go`

#### 2a. Enable Long Polling (Recommendation 1)
- Change `WaitTimeSeconds: 0` to `WaitTimeSeconds: 20` at line 406
- This reduces API calls and failure windows significantly

#### 2b. Add Context Checks (Recommendation 2)
- Add `ctx.Err()` checks between DynamoDB operations in `DequeueJobs` message loop (lines 426-474)
- If context is cancelled, release any already-processed messages before returning

#### 2c. Implement `ReleaseJob` (Recommendation 3)
- Decode task token to get queue and receipt handle
- Change SQS message visibility to 0 (immediate release)
- Update job state to `JOB_STATE_SCHEDULED` in DynamoDB
- Log the release for debugging

#### 2d. Handle RUNNING Jobs on Retry (Recommendation 5)
- Modify the state filter at lines 451-455 to allow RUNNING jobs to be re-dequeued
- A RUNNING job appearing in SQS means the previous dequeue failed to deliver
- Generate new task token for the re-dequeued job

### 3. Server Changes

**File**: `internal/server/job.go`

#### 3a. Release Jobs on Stream Failure (Recommendation 3)
- If `stream.Send()` fails, call `s.store.ReleaseJob()` for that job
- This immediately returns the message to SQS instead of waiting for visibility timeout

#### 3b. Reduce Polling Frequency (Recommendation 6)
- Change ticker from `100 * time.Millisecond` to `500 * time.Millisecond`
- With long polling enabled (20s), the ticker is only used for empty queue retries
- 500ms is sufficient and reduces unnecessary iterations

### 4. Skip Two-Phase Dequeue (Recommendation 4)

This would require protocol changes and is not necessary if we implement the release-on-failure pattern correctly. The other fixes address the root cause of retry issues.

## Design Decisions

- **Hardcoded timing values**: Long polling (20s) and polling interval (500ms) will be constants, not configurable
- **Redelivery metric**: Add `JobsRedeliveredTotal` counter metric to track when RUNNING jobs are re-dequeued
- **Unit tests**: Write tests for `ReleaseJob` in both `MemoryJobStore` and `SQSJobStore`

## Testing Considerations

- Test that `ReleaseJob` returns job to queue immediately
- Test that released jobs can be re-dequeued
- Test that RUNNING jobs from previous failed dequeues are handled
- Test context cancellation during dequeue releases messages
- Verify long polling reduces SQS API calls
- Unit tests for `ReleaseJob` in both store implementations

## Order of Implementation

1. Add `JobsRedeliveredTotal` metric to `internal/telemetry/metrics.go`
2. Add `ReleaseJob` to interface and implement in `MemoryJobStore`
3. Add unit tests for `MemoryJobStore.ReleaseJob`
4. Implement `ReleaseJob` in `SQSJobStore`
5. Add unit tests for `SQSJobStore.ReleaseJob`
6. Add context checks in `DequeueJobs`
7. Handle RUNNING jobs in SQS dequeue (with redelivery metric)
8. Enable long polling (change to 20s)
9. Update `job.go` to release on stream failure
10. Reduce polling frequency (change to 500ms)
