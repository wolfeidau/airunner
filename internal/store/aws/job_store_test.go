package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
)

func TestTaskTokenEncodeDecode(t *testing.T) {
	// Create store with test signing secret
	st := &JobStore{
		cfg: JobStoreConfig{
			TokenSigningSecret: []byte("test-secret-key-for-hmac-signing"),
		},
	}

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
			encoded := st.encodeTaskToken(tt.jobID, tt.queue, tt.receiptHandle)
			require.NotEmpty(t, encoded)

			decoded, err := st.decodeTaskToken(encoded)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			require.Equal(t, tt.jobID, decoded.JobID)
			require.Equal(t, tt.queue, decoded.Queue)
			require.Equal(t, tt.receiptHandle, decoded.ReceiptHandle)
		})
	}
}

func TestTaskTokenInvalid(t *testing.T) {
	st := &JobStore{
		cfg: JobStoreConfig{
			TokenSigningSecret: []byte("test-secret-key"),
		},
	}

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
		{
			name:   "empty token",
			token:  "",
			errMsg: "token cannot be empty",
		},
		{
			name:   "wrong number of parts",
			token:  "djF8am9ifHF1ZXVl", // base64("v1|job|queue") - missing receipt and signature
			errMsg: "expected 5 parts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.decodeTaskToken(tt.token)
			require.Error(t, err)
			if tt.errMsg != "" {
				require.Contains(t, err.Error(), tt.errMsg)
			}
		})
	}
}

func TestTaskTokenSignatureValidation(t *testing.T) {
	st1 := &JobStore{
		cfg: JobStoreConfig{
			TokenSigningSecret: []byte("secret-key-1"),
		},
	}
	st2 := &JobStore{
		cfg: JobStoreConfig{
			TokenSigningSecret: []byte("secret-key-2"), // Different secret
		},
	}

	t.Run("tampering detection", func(t *testing.T) {
		// Create a valid token
		token := st1.encodeTaskToken("job-123", "default", "receipt-abc")

		// Try to decode with wrong secret - should fail
		_, err := st2.decodeTaskToken(token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("valid signature", func(t *testing.T) {
		// Create and decode with same secret - should succeed
		token := st1.encodeTaskToken("job-456", "priority", "receipt-xyz")
		decoded, err := st1.decodeTaskToken(token)
		require.NoError(t, err)
		require.Equal(t, "job-456", decoded.JobID)
	})
}

func TestExtractJobIDFromMessage(t *testing.T) {
	st := &JobStore{}

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
			jobID := st.extractJobIDFromMessage(tt.body)
			if tt.expectOK {
				require.Equal(t, tt.expectID, jobID)
			} else {
				require.Empty(t, jobID)
			}
		})
	}
}

func TestAWSJobStoreStartStop(t *testing.T) {
	store := NewJobStore(nil, nil, JobStoreConfig{})

	err := store.Start()
	require.NoError(t, err)

	err = store.Stop()
	require.NoError(t, err)
}

func TestAWSJobStoreNoAuth(t *testing.T) {
	// Verify that AWSJobStore implements JobStore interface
	var _ store.JobStore = (*JobStore)(nil)
}

// Integration test helpers (Phase 1 - basic structure)
// Note: Full integration tests with LocalStack will be in Phase 3

func TestAWSJobStoreConfigValidation(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := JobStoreConfig{
			QueueURLs: map[string]string{
				"default": "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default",
			},
			JobsTableName:                   "airunner_jobs",
			JobEventsTableName:              "airunner_job_events",
			DefaultVisibilityTimeoutSeconds: 300,
		}

		store := NewJobStore(nil, nil, cfg)
		require.NotNil(t, store)
		require.Equal(t, cfg.JobsTableName, store.cfg.JobsTableName)
		require.Equal(t, cfg.JobEventsTableName, store.cfg.JobEventsTableName)
	})
}

func TestTaskTokenRoundTrip(t *testing.T) {
	st := &JobStore{
		cfg: JobStoreConfig{
			TokenSigningSecret: []byte("test-round-trip-secret"),
		},
	}

	// Test that encoding and decoding are inverses
	const iterations = 100
	for i := 0; i < iterations; i++ {
		jobID := "job-id-" + string(rune(i))
		queue := "queue-" + string(rune(i%5))
		handle := "handle-" + string(rune(i%10))

		encoded := st.encodeTaskToken(jobID, queue, handle)
		decoded, err := st.decodeTaskToken(encoded)
		require.NoError(t, err)
		require.Equal(t, jobID, decoded.JobID)
		require.Equal(t, queue, decoded.Queue)
		require.Equal(t, handle, decoded.ReceiptHandle)
	}
}

func TestDecodeTaskTokenErrorCases(t *testing.T) {
	st := &JobStore{
		cfg: JobStoreConfig{
			TokenSigningSecret: []byte("test-error-cases-secret"),
		},
	}

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
			token: "aGFuZGxlMXxoYW5kbGUx", // base64("handle1|handle1") - only 2 parts
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.decodeTaskToken(tt.token)
			require.Error(t, err)
		})
	}
}

func TestJobStoreEventStreamingSetup(t *testing.T) {
	st := NewJobStore(nil, nil, JobStoreConfig{})

	// Verify eventStreams map is initialized
	require.NotNil(t, st.eventStreams)
	require.Empty(t, st.eventStreams)

	// Test that we can register and unregister streams
	jobID := "test-job-123"
	ch := make(chan *jobv1.JobEvent, 10)

	st.mu.Lock()
	st.eventStreams[jobID] = append(st.eventStreams[jobID], ch)
	st.mu.Unlock()

	st.mu.RLock()
	streams := st.eventStreams[jobID]
	st.mu.RUnlock()

	require.Len(t, streams, 1)
	require.Equal(t, ch, streams[0])
}

func TestQueueURLConfiguration(t *testing.T) {
	cfg := JobStoreConfig{
		QueueURLs: map[string]string{
			"default":  "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default",
			"priority": "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-priority",
		},
	}

	st := NewJobStore(nil, nil, cfg)

	// Verify queue URLs are accessible
	require.Equal(t, "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-default", st.cfg.QueueURLs["default"])
	require.Equal(t, "https://sqs.us-west-2.amazonaws.com/123456789/airunner-prod-priority", st.cfg.QueueURLs["priority"])
	require.Empty(t, st.cfg.QueueURLs["nonexistent"])
}

func TestContextCancellation(t *testing.T) {
	st := &JobStore{
		cfg: JobStoreConfig{
			QueueURLs: map[string]string{"default": "https://example.com/queue"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// DequeueJobs should handle cancelled context gracefully (actual test requires AWS clients)
	// This is a placeholder for the behavioral test
	require.NotNil(t, st)
	require.Error(t, ctx.Err())
}

func TestAWSJobStoreReleaseJob(t *testing.T) {
	t.Run("release with invalid token fails", func(t *testing.T) {
		store := &JobStore{
			cfg: JobStoreConfig{
				TokenSigningSecret: []byte("test-secret"),
				QueueURLs:          map[string]string{"default": "https://example.com/queue"},
			},
		}

		err := store.ReleaseJob(context.Background(), "invalid-token")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid task token")
	})

	t.Run("release with empty token fails", func(t *testing.T) {
		store := &JobStore{
			cfg: JobStoreConfig{
				TokenSigningSecret: []byte("test-secret"),
			},
		}

		err := store.ReleaseJob(context.Background(), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "token cannot be empty")
	})

	t.Run("release with unconfigured queue fails", func(t *testing.T) {
		store := &JobStore{
			cfg: JobStoreConfig{
				TokenSigningSecret: []byte("test-secret"),
				QueueURLs:          map[string]string{"other": "https://example.com/other"},
			},
		}

		// Create a valid token for a queue that doesn't exist in config
		token := store.encodeTaskToken("job-123", "default", "receipt-abc")

		err := store.ReleaseJob(context.Background(), token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "queue not configured")
	})

	// Note: Full integration tests for ReleaseJob with actual SQS/DynamoDB
	// are in sqs_store_integration_test.go using LocalStack
}

func TestEventSizeValidation(t *testing.T) {
	st := NewJobStore(nil, nil, JobStoreConfig{
		JobEventsTableName: "test_job_events",
	})

	ctx := context.Background()
	jobID := "test-job-123"

	t.Run("event exceeds size limit", func(t *testing.T) {
		// Create a large event that exceeds maxEventPayloadBytes (350KB)
		// Using 400KB to ensure it exceeds the limit
		largeOutput := make([]byte, 400*1024) // 400KB
		for i := range largeOutput {
			largeOutput[i] = 'A'
		}

		largeEvent := &jobv1.JobEvent{
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
			Sequence:  1,
			EventData: &jobv1.JobEvent_Output{
				Output: &jobv1.OutputEvent{
					Output: largeOutput,
				},
			},
		}

		// This should fail BEFORE reaching the AWS client due to size validation
		err := st.batchWriteEvents(ctx, jobID, []*jobv1.JobEvent{largeEvent})
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds maximum size")
		require.ErrorIs(t, err, store.ErrEventTooLarge)
		require.Contains(t, err.Error(), "storage limit")                       // Check that error mentions the limit
		require.Contains(t, err.Error(), "Consider reducing output batch size") // Check for helpful message
	})

	t.Run("mixed event sizes batch rejected", func(t *testing.T) {
		// Create a batch with one small and one oversized event
		// The batch should be rejected due to the oversized event
		smallEvent := &jobv1.JobEvent{
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
			Sequence:  1,
			EventData: &jobv1.JobEvent_Output{
				Output: &jobv1.OutputEvent{
					Output: []byte("small output data"),
				},
			},
		}

		largeEvent := &jobv1.JobEvent{
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT,
			Sequence:  2,
			EventData: &jobv1.JobEvent_Output{
				Output: &jobv1.OutputEvent{
					Output: make([]byte, 400*1024), // 400KB
				},
			},
		}

		// Should fail on the large event (sequence 2)
		err := st.batchWriteEvents(ctx, jobID, []*jobv1.JobEvent{smallEvent, largeEvent})
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds maximum size")
		require.Contains(t, err.Error(), "seq=2") // Verify it identifies the correct event
		require.ErrorIs(t, err, store.ErrEventTooLarge)
	})
}
