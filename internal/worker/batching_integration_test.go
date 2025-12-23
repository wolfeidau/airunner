package worker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestEventBatcherIntegrationWithStore tests the full end-to-end batching flow:
// 1. Create job with ExecutionConfig
// 2. EventBatcher batches outputs
// 3. Server stores batches with correct sequences
// 4. Client retrieves events
func TestEventBatcherIntegrationWithStore(t *testing.T) {
	ctx := context.Background()
	jobStore := store.NewMemoryJobStore()
	require.NoError(t, jobStore.Start())
	defer func() { require.NoError(t, jobStore.Stop()) }()

	// Create a job with batching configuration
	enqueueResp, err := jobStore.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		RequestId: "test-req-1",
		Queue:     "default",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Command:    "echo",
			Args:       []string{"hello"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, enqueueResp)

	jobID := enqueueResp.JobId

	// Verify job has ExecutionConfig
	job, err := getJobByID(ctx, jobStore, jobID)
	require.NoError(t, err)
	require.NotNil(t, job.ExecutionConfig)
	require.NotNil(t, job.ExecutionConfig.Batching)

	// Dequeue job and get task token
	dequeued, err := jobStore.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	require.Len(t, dequeued, 1)

	taskToken := dequeued[0].TaskToken

	// Create EventBatcher with job's config
	publishedEvents := make([]*jobv1.JobEvent, 0)
	batcher := NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		publishedEvents = append(publishedEvents, event)
		return jobStore.PublishEvents(ctx, taskToken, []*jobv1.JobEvent{event})
	})
	defer func() { require.NoError(t, batcher.Stop(ctx)) }()

	// Simulate worker outputting 100 lines (with max batch size of 50, should get 2 batches)
	for i := 0; i < 100; i++ {
		output := []byte("output line\n")
		require.NoError(t, batcher.AddOutput(ctx, output, 0))
	}

	// Flush remaining
	require.NoError(t, batcher.Flush(ctx))

	// Should have published 2 batches (50 + 50)
	require.Len(t, publishedEvents, 2)

	// Verify batch structure
	batch1 := publishedEvents[0].GetOutputBatch()
	require.NotNil(t, batch1)
	require.Equal(t, int64(1), batch1.StartSequence)
	require.Equal(t, int64(50), batch1.EndSequence)
	require.Len(t, batch1.Outputs, 50)

	batch2 := publishedEvents[1].GetOutputBatch()
	require.NotNil(t, batch2)
	require.Equal(t, int64(51), batch2.StartSequence)
	require.Equal(t, int64(100), batch2.EndSequence)
	require.Len(t, batch2.Outputs, 50)
}

// TestEventBatcherWithNonOutputEvents tests that non-output events flush the buffer first
func TestEventBatcherIntegrationWithNonOutputEvents(t *testing.T) {
	ctx := context.Background()
	jobStore := store.NewMemoryJobStore()
	require.NoError(t, jobStore.Start())
	defer func() { require.NoError(t, jobStore.Stop()) }()

	// Create job
	enqueueResp, err := jobStore.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		RequestId: "test-req-2",
		Queue:     "default",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Command:    "echo",
			Args:       []string{"hello"},
		},
	})
	require.NoError(t, err)

	jobID := enqueueResp.JobId
	job, err := getJobByID(ctx, jobStore, jobID)
	require.NoError(t, err)
	require.NotNil(t, job)

	// Dequeue and get token
	dequeued, err := jobStore.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	taskToken := dequeued[0].TaskToken

	// Create batcher
	publishedEvents := make([]*jobv1.JobEvent, 0)
	batcher := NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		publishedEvents = append(publishedEvents, event)
		return jobStore.PublishEvents(ctx, taskToken, []*jobv1.JobEvent{event})
	})
	defer func() { require.NoError(t, batcher.Stop(ctx)) }()

	// Add some outputs (not enough to trigger flush)
	for i := 0; i < 5; i++ {
		require.NoError(t, batcher.AddOutput(ctx, []byte("line\n"), 0))
	}

	require.Empty(t, publishedEvents, "Should not publish yet")

	// Add a heartbeat event - should flush buffer first
	heartbeat := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_HEARTBEAT,
		EventData: &jobv1.JobEvent_Heartbeat{
			Heartbeat: &jobv1.HeartbeatEvent{ProcessAlive: true},
		},
	}

	require.NoError(t, batcher.AddEvent(ctx, heartbeat))

	// Should have published: 1 batch + 1 heartbeat
	require.Len(t, publishedEvents, 2)

	// First should be batch with 5 items
	batch := publishedEvents[0].GetOutputBatch()
	require.NotNil(t, batch)
	require.Len(t, batch.Outputs, 5)
	require.Equal(t, int64(1), batch.StartSequence)
	require.Equal(t, int64(5), batch.EndSequence)

	// Second should be heartbeat
	require.Equal(t, jobv1.EventType_EVENT_TYPE_HEARTBEAT, publishedEvents[1].EventType)
	// Heartbeat should have sequence 6 (after 5 outputs)
	require.Equal(t, int64(6), publishedEvents[1].Sequence)
}

// TestEventBatcherTimestampEncoding tests timestamp delta encoding across a batch
func TestEventBatcherIntegrationTimestampEncoding(t *testing.T) {
	ctx := context.Background()
	jobStore := store.NewMemoryJobStore()
	require.NoError(t, jobStore.Start())
	defer func() { require.NoError(t, jobStore.Stop()) }()

	// Create job
	enqueueResp, err := jobStore.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		RequestId: "test-req-3",
		Queue:     "default",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Command:    "echo",
			Args:       []string{"hello"},
		},
	})
	require.NoError(t, err)

	jobID := enqueueResp.JobId
	job, err := getJobByID(ctx, jobStore, jobID)
	require.NoError(t, err)

	// Dequeue
	dequeued, err := jobStore.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	taskToken := dequeued[0].TaskToken

	// Create batcher
	publishedEvents := make([]*jobv1.JobEvent, 0)
	batcher := NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		publishedEvents = append(publishedEvents, event)
		return jobStore.PublishEvents(ctx, taskToken, []*jobv1.JobEvent{event})
	})
	defer func() { require.NoError(t, batcher.Stop(ctx)) }()

	// Add outputs with delays
	require.NoError(t, batcher.AddOutput(ctx, []byte("line1\n"), 0))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, batcher.AddOutput(ctx, []byte("line2\n"), 0))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, batcher.AddOutput(ctx, []byte("line3\n"), 0))

	require.NoError(t, batcher.Flush(ctx))

	require.Len(t, publishedEvents, 1)
	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 3)

	// Verify timestamps are encoded as deltas
	// First item should have small delta
	require.InDelta(t, 0, batch.Outputs[0].TimestampDeltaMs, 10)

	// Second and third should have accumulated deltas
	require.Greater(t, batch.Outputs[1].TimestampDeltaMs, int32(40))
	require.Greater(t, batch.Outputs[2].TimestampDeltaMs, int32(80))

	// Verify we can reconstruct timestamps
	// Each delta from first should be cumulative
	// Item 1: ~0ms, Item 2: ~50ms, Item 3: ~100ms
	for i := 0; i < len(batch.Outputs); i++ {
		expectedDelta := util.AsInt32FromInt64(int64(i) * 50)
		actualDelta := batch.Outputs[i].TimestampDeltaMs
		require.InDelta(t, expectedDelta, actualDelta, 30, "Item %d delta should be ~%dms", i, expectedDelta)
	}
}

// TestEventBatcherBackwardsCompatibility tests that jobs without ExecutionConfig use defaults
func TestEventBatcherIntegrationBackwardsCompatibility(t *testing.T) {
	// Create a job with nil ExecutionConfig (simulating old job from before batching)
	publishedEvents := make([]*jobv1.JobEvent, 0)
	ctx := context.Background()
	batcher := NewEventBatcher(nil, func(event *jobv1.JobEvent) error {
		publishedEvents = append(publishedEvents, event)
		return nil
	})
	defer func() { require.NoError(t, batcher.Stop(ctx)) }()

	// Should have created batcher with defaults
	require.NotNil(t, batcher)

	// Add outputs - should work with defaults
	for i := 0; i < 10; i++ {
		require.NoError(t, batcher.AddOutput(ctx, []byte("line\n"), 0))
	}

	require.Empty(t, publishedEvents, "Should not flush with defaults yet")

	require.NoError(t, batcher.Flush(ctx))
	require.Len(t, publishedEvents, 1)

	batch := publishedEvents[0].GetOutputBatch()
	require.Len(t, batch.Outputs, 10)
}

// TestEventBatcherSequenceAcrossMultipleBatches verifies monotonic sequence numbering
func TestEventBatcherIntegrationSequenceMonotonicity(t *testing.T) {
	ctx := context.Background()
	jobStore := store.NewMemoryJobStore()
	require.NoError(t, jobStore.Start())
	defer func() { require.NoError(t, jobStore.Stop()) }()

	// Create job
	enqueueResp, err := jobStore.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		RequestId: "test-req-4",
		Queue:     "default",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Command:    "echo",
			Args:       []string{"hello"},
		},
	})
	require.NoError(t, err)

	jobID := enqueueResp.JobId
	job, err := getJobByID(ctx, jobStore, jobID)
	require.NoError(t, err)
	require.NotNil(t, job)

	// Dequeue
	dequeued, err := jobStore.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	taskToken := dequeued[0].TaskToken

	// Create batcher with small batch size
	config := &jobv1.ExecutionConfig{
		Batching: &jobv1.BatchingConfig{
			FlushIntervalSeconds:   10,
			MaxBatchSize:           10,
			MaxBatchBytes:          1000000,
			PlaybackIntervalMillis: 50,
		},
	}
	publishedEvents := make([]*jobv1.JobEvent, 0)
	batcher := NewEventBatcher(config, func(event *jobv1.JobEvent) error {
		publishedEvents = append(publishedEvents, event)
		return jobStore.PublishEvents(ctx, taskToken, []*jobv1.JobEvent{event})
	})
	defer func() { require.NoError(t, batcher.Stop(ctx)) }()

	// Add 100 outputs - should create 10 batches of 10
	for i := 0; i < 100; i++ {
		require.NoError(t, batcher.AddOutput(ctx, []byte("line\n"), 0))
	}
	require.NoError(t, batcher.Flush(ctx))

	// Should have 10 batches
	require.Len(t, publishedEvents, 10)

	// Verify sequences are monotonic and gapless
	expectedSeq := int64(1)
	for i, event := range publishedEvents {
		batch := event.GetOutputBatch()
		require.NotNil(t, batch, "Event %d should be a batch", i)
		require.Equal(t, expectedSeq, batch.StartSequence, "Event %d has wrong start sequence", i)
		require.Equal(t, expectedSeq+9, batch.EndSequence, "Event %d has wrong end sequence", i)
		require.Len(t, batch.Outputs, 10, "Event %d has wrong output count", i)

		expectedSeq += 10
	}
}

// TestEventBatcherProcessLifecycle tests a realistic job lifecycle with multiple event types
func TestEventBatcherIntegrationProcessLifecycle(t *testing.T) {
	ctx := context.Background()
	jobStore := store.NewMemoryJobStore()
	require.NoError(t, jobStore.Start())
	defer func() { require.NoError(t, jobStore.Stop()) }()

	// Create job
	enqueueResp, err := jobStore.EnqueueJob(ctx, &jobv1.EnqueueJobRequest{
		RequestId: "test-req-5",
		Queue:     "default",
		JobParams: &jobv1.JobParams{
			Repository: "https://github.com/example/repo",
			Command:    "echo",
			Args:       []string{"hello"},
		},
	})
	require.NoError(t, err)

	jobID := enqueueResp.JobId
	job, err := getJobByID(ctx, jobStore, jobID)
	require.NoError(t, err)

	// Dequeue
	dequeued, err := jobStore.DequeueJobs(ctx, "default", 1, 300)
	require.NoError(t, err)
	taskToken := dequeued[0].TaskToken

	// Create batcher
	publishedEvents := make([]*jobv1.JobEvent, 0)
	batcher := NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		publishedEvents = append(publishedEvents, event)
		return jobStore.PublishEvents(ctx, taskToken, []*jobv1.JobEvent{event})
	})
	defer func() { require.NoError(t, batcher.Stop(ctx)) }()

	// Simulate job lifecycle:
	// 1. ProcessStart
	processStart := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_START,
		EventData: &jobv1.JobEvent_ProcessStart{
			ProcessStart: &jobv1.ProcessStartEvent{
				Pid:       1234,
				StartedAt: timestamppb.Now(),
			},
		},
	}
	require.NoError(t, batcher.AddEvent(ctx, processStart))

	// 2. Some outputs
	for i := 0; i < 20; i++ {
		require.NoError(t, batcher.AddOutput(ctx, []byte("output\n"), 0))
	}

	// 3. Heartbeat (should flush buffer)
	heartbeat := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_HEARTBEAT,
		EventData: &jobv1.JobEvent_Heartbeat{
			Heartbeat: &jobv1.HeartbeatEvent{ProcessAlive: true},
		},
	}
	require.NoError(t, batcher.AddEvent(ctx, heartbeat))

	// 4. More outputs
	for i := 0; i < 30; i++ {
		require.NoError(t, batcher.AddOutput(ctx, []byte("output\n"), 0))
	}

	// 5. ProcessEnd (should flush buffer)
	processEnd := &jobv1.JobEvent{
		EventType: jobv1.EventType_EVENT_TYPE_PROCESS_END,
		EventData: &jobv1.JobEvent_ProcessEnd{
			ProcessEnd: &jobv1.ProcessEndEvent{
				Pid:      1234,
				ExitCode: 0,
			},
		},
	}
	require.NoError(t, batcher.AddEvent(ctx, processEnd))

	// Stop is called in defer, verify event sequence:
	// 1. ProcessStart (seq 1)
	// 2. OutputBatch with 20 items (seq 2, contains 2-21)
	// 3. Heartbeat (seq 22)
	// 4. OutputBatch with 30 items (seq 23, contains 23-52)
	// 5. ProcessEnd (seq 53)

	require.GreaterOrEqual(t, len(publishedEvents), 5)

	// Find events by type
	var processStartIdx, batch1Idx, heartbeatIdx, batch2Idx, processEndIdx int
	for i, event := range publishedEvents {
		switch event.EventType {
		case jobv1.EventType_EVENT_TYPE_PROCESS_START:
			processStartIdx = i
		case jobv1.EventType_EVENT_TYPE_HEARTBEAT:
			heartbeatIdx = i
		case jobv1.EventType_EVENT_TYPE_PROCESS_END:
			processEndIdx = i
		case jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH:
			if batch1Idx == 0 {
				batch1Idx = i
			} else if batch2Idx == 0 {
				batch2Idx = i
			}
		}
	}

	// Verify ProcessStart is first
	require.Zero(t, processStartIdx)
	require.Equal(t, int64(1), publishedEvents[processStartIdx].Sequence)

	// Verify batch1
	require.Positive(t, batch1Idx)
	batch1 := publishedEvents[batch1Idx].GetOutputBatch()
	require.Len(t, batch1.Outputs, 20)
	require.Equal(t, int64(2), batch1.StartSequence)

	// Verify heartbeat comes after batch1
	require.Greater(t, heartbeatIdx, batch1Idx)

	// Verify batch2 exists
	require.Greater(t, batch2Idx, heartbeatIdx)
	batch2 := publishedEvents[batch2Idx].GetOutputBatch()
	require.Len(t, batch2.Outputs, 30)

	// Verify ProcessEnd comes last
	require.Greater(t, processEndIdx, batch2Idx)
}

// getJobByID is a helper to retrieve a job from the store (for testing only)
// Uses ListJobs to find the job
func getJobByID(ctx context.Context, jobStore store.JobStore, jobID string) (*jobv1.Job, error) {
	resp, err := jobStore.ListJobs(ctx, &jobv1.ListJobsRequest{
		Page:     1,
		PageSize: 100,
	})
	if err != nil {
		return nil, err
	}

	for _, job := range resp.Jobs {
		if job.JobId == jobID {
			return job, nil
		}
	}

	return nil, nil
}
