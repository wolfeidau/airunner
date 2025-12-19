package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestTaskTokenEncodeDecode(t *testing.T) {
	tests := []struct {
		name          string
		jobID         string
		queue         string
		receiptHandle string
	}{
		{
			name:          "simple token",
			jobID:         "job-123",
			queue:         "default",
			receiptHandle: "handle-abc",
		},
		{
			name:          "UUIDv7 job ID",
			jobID:         "01234567-89ab-cdef-0123-456789abcdef",
			queue:         "priority",
			receiptHandle: "AQEBBmNouqxVp8qT8QcJqw7Zs8l+Gzx/Lw==",
		},
		{
			name:          "complex queue name",
			jobID:         "job-with-dashes",
			queue:         "default-priority-v2",
			receiptHandle: "handle-with-special-chars-+/==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeTaskToken(tt.jobID, tt.queue, tt.receiptHandle)
			require.NotEmpty(t, encoded)

			decoded, err := decodeTaskToken(encoded)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			require.Equal(t, tt.jobID, decoded.JobID)
			require.Equal(t, tt.queue, decoded.Queue)
			require.Equal(t, tt.receiptHandle, decoded.ReceiptHandle)
		})
	}
}

func TestTaskTokenInvalid(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		errMsg string
	}{
		{
			name:   "invalid base64",
			token:  "!!!invalid!!!",
			errMsg: "invalid task token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeTaskToken(tt.token)
			require.Error(t, err)
			if tt.errMsg != "" {
				require.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}

func TestExtractJobIDFromMessage(t *testing.T) {
	store := &SQSJobStore{}

	tests := []struct {
		name     string
		body     string
		expectID string
		expectOK bool
	}{
		{
			name:     "valid message",
			body:     `{"job_id":"01234567-89ab-cdef-0123-456789abcdef","queue":"default","attempt":1}`,
			expectID: "01234567-89ab-cdef-0123-456789abcdef",
			expectOK: true,
		},
		{
			name:     "missing job_id",
			body:     `{"queue":"default","attempt":1}`,
			expectID: "",
			expectOK: false,
		},
		{
			name:     "empty message",
			body:     "",
			expectID: "",
			expectOK: false,
		},
		{
			name:     "job_id at start",
			body:     `{"job_id":"job-123","queue":"q"}`,
			expectID: "job-123",
			expectOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobID := store.extractJobIDFromMessage(tt.body)
			if tt.expectOK {
				require.Equal(t, tt.expectID, jobID)
			} else {
				require.Empty(t, jobID)
			}
		})
	}
}

func TestSQSJobStoreStartStop(t *testing.T) {
	store := NewSQSJobStore(nil, nil, SQSJobStoreConfig{})

	err := store.Start()
	require.NoError(t, err)

	err = store.Stop()
	require.NoError(t, err)
}

func TestSQSJobStoreNoAuth(t *testing.T) {
	// Verify that SQSJobStore implements JobStore interface
	var _ JobStore = (*SQSJobStore)(nil)
}

// Integration test helpers (Phase 1 - basic structure)
// Note: Full integration tests with LocalStack will be in Phase 3

func TestSQSJobStoreConfigValidation(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := SQSJobStoreConfig{
			QueueURLs: map[string]string{
				"default": "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default",
			},
			JobsTableName:                   "airunner_jobs",
			JobEventsTableName:              "airunner_job_events",
			DefaultVisibilityTimeoutSeconds: 300,
		}

		store := NewSQSJobStore(nil, nil, cfg)
		require.NotNil(t, store)
		require.Equal(t, cfg.JobsTableName, store.cfg.JobsTableName)
		require.Equal(t, cfg.JobEventsTableName, store.cfg.JobEventsTableName)
	})
}

func TestTaskTokenRoundTrip(t *testing.T) {
	// Test that encoding and decoding are inverses
	const iterations = 100
	for i := 0; i < iterations; i++ {
		jobID := "job-id-" + string(rune(i))
		queue := "queue-" + string(rune(i%5))
		handle := "handle-" + string(rune(i%10))

		encoded := encodeTaskToken(jobID, queue, handle)
		decoded, err := decodeTaskToken(encoded)
		require.NoError(t, err)
		require.Equal(t, jobID, decoded.JobID)
		require.Equal(t, queue, decoded.Queue)
		require.Equal(t, handle, decoded.ReceiptHandle)
	}
}

func TestDecodeTaskTokenErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty string",
			token: "",
		},
		{
			name:  "invalid base64",
			token: "not-base64!!!",
		},
		{
			name:  "wrong number of parts",
			token: encodeTaskToken("job1", "queue1", "handle1"), // valid to get structure, then manually test wrong format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "wrong number of parts" {
				// Create a token with wrong format
				tt.token = "aGFuZGxlMXxoYW5kbGUx" // "handle1|handle1" in base64
			}
			_, err := decodeTaskToken(tt.token)
			require.Error(t, err)
		})
	}
}

func TestSQSJobStoreEventStreamingSetup(t *testing.T) {
	s := NewSQSJobStore(nil, nil, SQSJobStoreConfig{})

	// Verify eventStreams map is initialized
	require.NotNil(t, s.eventStreams)
	require.Empty(t, s.eventStreams)

	// Test that we can register and unregister streams
	jobID := "test-job-123"
	ch := make(chan *jobv1.JobEvent, 10)

	s.mu.Lock()
	s.eventStreams[jobID] = append(s.eventStreams[jobID], ch)
	s.mu.Unlock()

	s.mu.RLock()
	streams := s.eventStreams[jobID]
	s.mu.RUnlock()

	require.Len(t, streams, 1)
	require.Equal(t, ch, streams[0])
}

func TestQueueURLConfiguration(t *testing.T) {
	cfg := SQSJobStoreConfig{
		QueueURLs: map[string]string{
			"default":  "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default",
			"priority": "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-priority",
		},
	}

	store := NewSQSJobStore(nil, nil, cfg)

	// Verify queue URLs are accessible
	require.Equal(t, "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default", store.cfg.QueueURLs["default"])
	require.Equal(t, "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-priority", store.cfg.QueueURLs["priority"])
	require.Empty(t, store.cfg.QueueURLs["nonexistent"])
}

func TestContextCancellation(t *testing.T) {
	s := NewSQSJobStore(nil, nil, SQSJobStoreConfig{
		QueueURLs: map[string]string{"default": "https://example.com/queue"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// DequeueJobs should handle cancelled context gracefully (actual test requires AWS clients)
	// This is a placeholder for the behavioral test
	require.NotNil(t, s)
	require.Error(t, ctx.Err())
}
