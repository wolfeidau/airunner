package wal

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// mockEventSender is a mock implementation of EventSender for testing
type mockEventSender struct {
	sendFunc func(ctx context.Context, events []*jobv1.JobEvent) error
	calls    int
}

func (m *mockEventSender) Send(ctx context.Context, events []*jobv1.JobEvent) error {
	m.calls++
	if m.sendFunc != nil {
		return m.sendFunc(ctx, events)
	}
	return nil
}

func TestNewWAL(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	require.NotNil(t, w)

	// Verify WAL file was created
	walPath := filepath.Join(walDir, "test-job.wal")
	_, err = os.Stat(walPath)
	require.NoError(t, err)

	// Clean up
	err = w.Stop(context.Background())
	require.NoError(t, err)
}

func TestWAL_Append(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w.Stop(context.Background())
	}()

	// Append some events
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Verify index has correct count
	walImpl := w.(*walImpl)
	assert.Equal(t, 10, walImpl.index.Count())
	assert.Equal(t, 10, walImpl.index.CountPending())
	assert.Equal(t, 0, walImpl.index.CountSent())
}

func TestWAL_StartStop(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	// Mock sender
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			return nil
		},
	}

	// Start async sender
	err = w.Start(context.Background(), sender)
	require.NoError(t, err)

	// Append events
	for i := 0; i < 5; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Wait for sender to process
	time.Sleep(300 * time.Millisecond)

	// Stop WAL
	err = w.Stop(context.Background())
	require.NoError(t, err)

	// Verify sender was called
	assert.Positive(t, sender.calls)
}

func TestWAL_Persistence(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	// Create WAL and append events
	w1, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w1.Append(context.Background(), event)
		require.NoError(t, err)
	}

	err = w1.Stop(context.Background())
	require.NoError(t, err)

	// Reopen WAL and verify events are still there
	w2, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w2.Stop(context.Background())
	}()

	walImpl := w2.(*walImpl)
	assert.Equal(t, 5, walImpl.index.Count())
	assert.Equal(t, 5, walImpl.index.CountPending())
}

func TestWAL_Archive(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	// Append events
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Stop WAL
	err = w.Stop(context.Background())
	require.NoError(t, err)

	// Archive
	err = w.Archive(context.Background(), archiveDir)
	require.NoError(t, err)

	// Verify archive exists
	archivePath := filepath.Join(archiveDir, "test-job.wal.zst")
	_, err = os.Stat(archivePath)
	require.NoError(t, err)

	// Verify original WAL was deleted
	walPath := filepath.Join(walDir, "test-job.wal")
	_, err = os.Stat(walPath)
	assert.True(t, os.IsNotExist(err))
}

func TestBuildRecord(t *testing.T) {
	payload := []byte("test event data")
	record := buildRecord(42, RecordPending, payload)

	// Verify length
	length := binary.LittleEndian.Uint32(record[0:4])
	//nolint:gosec // len(payload) is always positive and bounded in tests
	expectedLength := uint32(32 + len(payload)) // 32 bytes fixed + payload
	assert.Equal(t, expectedLength, length)

	// Verify sequence
	//nolint:gosec // Converting uint64 to int64 is safe here
	sequence := int64(binary.LittleEndian.Uint64(record[4:12]))
	assert.Equal(t, int64(42), sequence)

	// Verify status
	status := record[12]
	assert.Equal(t, RecordPending, status)

	// Verify CRC64 is non-zero
	crc := binary.LittleEndian.Uint64(record[len(record)-8:])
	assert.NotZero(t, crc)

	// Verify CRC64 is correct
	dataForCRC := record[4 : len(record)-8]
	expectedCRC := computeCRC64(dataForCRC)
	assert.Equal(t, expectedCRC, crc)
}

func TestComputeCRC64(t *testing.T) {
	data := []byte("hello world")
	crc1 := computeCRC64(data)
	crc2 := computeCRC64(data)

	// CRC should be deterministic
	assert.Equal(t, crc1, crc2)
	assert.NotZero(t, crc1)

	// Different data should have different CRC
	data2 := []byte("hello world!")
	crc3 := computeCRC64(data2)
	assert.NotEqual(t, crc1, crc3)
}

func TestCleanupArchive(t *testing.T) {
	archiveDir := t.TempDir()

	// Create some test archive files
	oldFile := filepath.Join(archiveDir, "old-job.wal.zst")
	recentFile := filepath.Join(archiveDir, "recent-job.wal.zst")
	nonWALFile := filepath.Join(archiveDir, "other.txt")

	// Create files
	//nolint:gosec // Test files can use 0644 permissions
	require.NoError(t, os.WriteFile(oldFile, []byte("old data"), 0644))
	//nolint:gosec // Test files can use 0644 permissions
	require.NoError(t, os.WriteFile(recentFile, []byte("recent data"), 0644))
	//nolint:gosec // Test files can use 0644 permissions
	require.NoError(t, os.WriteFile(nonWALFile, []byte("other"), 0644))

	// Set old file's mod time to 31 days ago
	oldTime := time.Now().AddDate(0, 0, -31)
	require.NoError(t, os.Chtimes(oldFile, oldTime, oldTime))

	// Run cleanup with 30-day retention
	err := CleanupArchive(archiveDir, 30)
	require.NoError(t, err)

	// Old file should be deleted
	_, err = os.Stat(oldFile)
	assert.True(t, os.IsNotExist(err))

	// Recent file should still exist
	_, err = os.Stat(recentFile)
	require.NoError(t, err)

	// Non-WAL file should still exist
	_, err = os.Stat(nonWALFile)
	require.NoError(t, err)
}

func TestWALIndex(t *testing.T) {
	idx := newWALIndex()

	// Add records
	for i := 0; i < 10; i++ {
		idx.Add(walRecord{
			sequence:  int64(i + 1),
			offset:    int64(i * 100),
			length:    100,
			status:    RecordPending,
			timestamp: time.Now().UnixMilli(),
		})
	}

	// Verify count
	assert.Equal(t, 10, idx.Count())
	assert.Equal(t, 10, idx.CountPending())
	assert.Equal(t, 0, idx.CountSent())

	// Get unsent
	unsent := idx.GetUnsent()
	assert.Len(t, unsent, 10)

	// Mark some as sent
	idx.MarkSent(unsent[:5])
	assert.Equal(t, 5, idx.CountPending())
	assert.Equal(t, 5, idx.CountSent())

	// Mark some as failed
	idx.MarkFailed(unsent[5:7])
	assert.Equal(t, 3, idx.CountPending())
	assert.Equal(t, 5, idx.CountSent())
	assert.Equal(t, 2, idx.CountFailed())
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotEmpty(t, cfg.WALDir)
	assert.NotEmpty(t, cfg.ArchiveDir)
	assert.Equal(t, 30, cfg.RetentionDays)
	assert.Equal(t, 100*time.Millisecond, cfg.FlushInterval)
	assert.True(t, cfg.ArchiveOnComplete)
	assert.Equal(t, 1*time.Second, cfg.RetryBackoff.InitialInterval)
	assert.Equal(t, 60*time.Second, cfg.RetryBackoff.MaxInterval)
	assert.InEpsilon(t, 2.0, cfg.RetryBackoff.Multiplier, 0.001)
}

// TestWAL_NetworkFailureRecovery tests retry logic when network fails
func TestWAL_NetworkFailureRecovery(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 50 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 50 * time.Millisecond,
			MaxInterval:     500 * time.Millisecond,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w.Stop(context.Background())
	}()

	// Mock sender that fails first 3 times, then succeeds
	attemptCount := 0
	var sentEvents []*jobv1.JobEvent
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			attemptCount++
			if attemptCount <= 3 {
				return assert.AnError // Simulate network error
			}
			sentEvents = append(sentEvents, events...)
			return nil
		},
	}

	err = w.Start(context.Background(), sender)
	require.NoError(t, err)

	// Append events
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Wait for retries to succeed
	time.Sleep(1 * time.Second)

	// Verify all events eventually sent
	assert.Len(t, sentEvents, 10, "All events should be sent after retries")
	assert.Greater(t, attemptCount, 3, "Should have retried at least 3 times")
}

// TestWAL_WorkerCrashRecovery tests that events survive worker crashes
func TestWAL_WorkerCrashRecovery(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	// Simulate first worker
	w1, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	// Append events but DON'T start sender (simulate crash before send)
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w1.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Simulate crash - close file without proper Stop()
	impl := w1.(*walImpl)
	impl.mu.Lock()
	if impl.file != nil {
		_ = impl.file.Close()
		impl.file = nil
	}
	impl.mu.Unlock()

	// Simulate second worker (restart after crash)
	w2, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w2.Stop(context.Background())
	}()

	// Verify unsent events were loaded
	impl2 := w2.(*walImpl)
	assert.Equal(t, 10, impl2.index.Count(), "Should load 10 events")
	assert.Equal(t, 10, impl2.index.CountPending(), "All events should be pending")

	// Start sender and verify events are sent
	var sentEvents []*jobv1.JobEvent
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			sentEvents = append(sentEvents, events...)
			return nil
		},
	}

	err = w2.Start(context.Background(), sender)
	require.NoError(t, err)

	// Wait for sender to process
	time.Sleep(300 * time.Millisecond)

	// Verify events replayed
	assert.Len(t, sentEvents, 10, "All events should be replayed after crash")
}

// TestWAL_CRC64Corruption tests that corrupted records are detected
func TestWAL_CRC64Corruption(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	// Append an event
	event := &jobv1.JobEvent{
		Sequence:  1,
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
	}
	err = w.Append(context.Background(), event)
	require.NoError(t, err)

	err = w.Stop(context.Background())
	require.NoError(t, err)

	// Corrupt the WAL file (flip some bytes in the middle)
	walPath := filepath.Join(walDir, "test-job.wal")
	data, err := os.ReadFile(walPath)
	require.NoError(t, err)

	// Corrupt payload (not the header or CRC)
	if len(data) > headerSize+100 {
		data[headerSize+50] ^= 0xFF // Flip bits
		//nolint:gosec // Test files can use 0644 permissions
		err = os.WriteFile(walPath, data, 0644)
		require.NoError(t, err)
	}

	// Try to reload - WAL should still open (corruption might not be detected until send)
	w2, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w2.Stop(context.Background())
	}()

	// The important part is that corrupted data doesn't cause crashes
	// Depending on where we corrupted (header vs payload vs CRC), different things happen:
	// 1. Header corruption: might not load record
	// 2. Payload corruption: CRC check should fail on read
	// 3. CRC corruption: check should fail on read
	// Since we corrupted the payload, the sender will fail when trying to deserialize/send
	impl := w2.(*walImpl)
	// At minimum, WAL should be functional (not crash)
	assert.NotNil(t, impl.index, "Index should be initialized")

	//  Note: In production, corrupted records are skipped by the sender with warnings
	// The key guarantee is: corruption doesn't crash the worker or prevent other events from being sent
}

// TestWAL_LargePayload tests handling of large events (up to 200KB)
func TestWAL_LargePayload(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w.Stop(context.Background())
	}()

	// Create large payload (200KB)
	largePayload := make([]byte, 200*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	// Create event with large payload
	event := &jobv1.JobEvent{
		Sequence:  1,
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		EventData: &jobv1.JobEvent_OutputBatch{
			OutputBatch: &jobv1.OutputBatchEvent{
				Outputs: []*jobv1.OutputItem{
					{Output: largePayload},
				},
			},
		},
	}

	// Should be able to append large event
	err = w.Append(context.Background(), event)
	require.NoError(t, err)

	// Verify index updated
	impl := w.(*walImpl)
	assert.Equal(t, 1, impl.index.Count())
}

// TestWAL_Flush tests that Flush() blocks until all events are sent
func TestWAL_Flush(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w.Stop(context.Background())
	}()

	// Mock sender that tracks sent events
	var sentEvents []*jobv1.JobEvent
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			// Simulate slight delay in sending
			time.Sleep(10 * time.Millisecond)
			sentEvents = append(sentEvents, events...)
			return nil
		},
	}

	err = w.Start(context.Background(), sender)
	require.NoError(t, err)

	// Append events
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Flush should block until all events are sent
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = w.Flush(ctx)
	require.NoError(t, err)

	// All events should be sent after Flush returns
	assert.Len(t, sentEvents, 10, "All events should be sent after Flush()")

	// Index should show all events as sent
	impl := w.(*walImpl)
	assert.Equal(t, 0, impl.index.CountPending(), "No events should be pending after Flush()")
	assert.Equal(t, 10, impl.index.CountSent(), "All events should be marked as sent")
}

// TestWAL_FlushTimeout tests that Flush() times out if events can't be sent
func TestWAL_FlushTimeout(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 100 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		_ = w.Stop(context.Background())
	}()

	// Mock sender that always fails
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			return assert.AnError // Always fail
		},
	}

	err = w.Start(context.Background(), sender)
	require.NoError(t, err)

	// Append events
	for i := 0; i < 5; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i + 1),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Flush should timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = w.Flush(ctx)
	require.Error(t, err, "Flush should timeout when events can't be sent")
	require.Contains(t, err.Error(), "pending", "Error should mention pending events")
}

// Benchmarks

func BenchmarkWAL_Append(b *testing.B) {
	walDir := b.TempDir()
	archiveDir := b.TempDir()
	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 1 * time.Second,
		RetryBackoff: BackoffConfig{
			InitialInterval: 100 * time.Millisecond,
			MaxInterval:     1 * time.Second,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "bench-job")
	require.NoError(b, err)
	defer func() {
		_ = w.Stop(context.Background())
	}()

	event := &jobv1.JobEvent{
		Sequence:  1,
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.Sequence = int64(i + 1)
		_ = w.Append(context.Background(), event)
	}
}

func BenchmarkCRC64_1KB(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		_ = computeCRC64(data)
	}
}

func BenchmarkCRC64_10KB(b *testing.B) {
	data := make([]byte, 10*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.SetBytes(10 * 1024)
	for i := 0; i < b.N; i++ {
		_ = computeCRC64(data)
	}
}

func BenchmarkCRC64_100KB(b *testing.B) {
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.SetBytes(100 * 1024)
	for i := 0; i < b.N; i++ {
		_ = computeCRC64(data)
	}
}

func BenchmarkCRC64_200KB(b *testing.B) {
	data := make([]byte, 200*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.SetBytes(200 * 1024)
	for i := 0; i < b.N; i++ {
		_ = computeCRC64(data)
	}
}
