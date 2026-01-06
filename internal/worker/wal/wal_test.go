package wal

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// TestBuildRecord tests record construction
func TestBuildRecord(t *testing.T) {
	payload := []byte("test event")
	record := buildRecord(42, RecordPending, payload)

	// Verify length field (seq:8 + status:1 + reserved:3 + timestamp:8 + payload)
	length := binary.LittleEndian.Uint32(record[0:4])
	// #nosec G115 - len(payload) is bounded and safe conversion
	expectedLength := uint32(8 + 1 + 3 + 8 + len(payload))
	assert.Equal(t, expectedLength, length)

	// Verify sequence
	// #nosec G115 - safe conversion from protocol data
	sequence := int64(binary.LittleEndian.Uint64(record[4:12]))
	assert.Equal(t, int64(42), sequence)

	// Verify status
	status := record[12]
	assert.Equal(t, RecordPending, status)

	// Verify CRC64 is non-zero
	crc := binary.LittleEndian.Uint64(record[len(record)-8:])
	assert.NotZero(t, crc)
}

// TestComputeCRC64 tests CRC64 computation
func TestComputeCRC64(t *testing.T) {
	data1 := []byte("test data")
	data2 := []byte("test data")
	data3 := []byte("different data")

	crc1 := computeCRC64(data1)
	crc2 := computeCRC64(data2)
	crc3 := computeCRC64(data3)

	// Same data should produce same CRC
	assert.Equal(t, crc1, crc2)

	// Different data should produce different CRC (with high probability)
	assert.NotEqual(t, crc1, crc3)
}

// TestWALAppend tests appending events to WAL
func TestWALAppend(t *testing.T) {
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
		require.NoError(t, w.Stop(context.Background()))
	}()

	// Append events
	for i := 0; i < 5; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err := w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Verify WAL file exists
	walPath := filepath.Join(walDir, "test-job.wal")
	_, err = os.Stat(walPath)
	require.NoError(t, err)

	// Verify file size is reasonable
	info, _ := os.Stat(walPath)
	assert.Greater(t, info.Size(), int64(100)) // At least header + 1 record
}

// TestWALIndex tests index functionality
func TestWALIndex(t *testing.T) {
	idx := newWalIndex()

	// Add records
	idx.addRecord(1, 16, RecordPending)
	idx.addRecord(2, 150, RecordPending)
	idx.addRecord(3, 300, RecordSent)

	// Test getRecord
	rec := idx.getRecord(2)
	assert.NotNil(t, rec)
	assert.Equal(t, int64(2), rec.sequence)

	// Test getUnsent
	unsent := idx.getUnsent()
	assert.Len(t, unsent, 2) // Only pending records

	// Test markSent
	idx.markSent(1)
	unsent = idx.getUnsent()
	assert.Len(t, unsent, 1)

	// Test countByStatus
	assert.Equal(t, 1, idx.countByStatus(RecordPending))
	assert.Equal(t, 2, idx.countByStatus(RecordSent))
}

// TestWALReload tests loading existing WAL
func TestWALReload(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
	}

	// Create WAL and append events
	w1, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		require.NoError(t, w1.Append(context.Background(), event))
	}

	require.NoError(t, w1.Stop(context.Background()))

	// Reopen WAL
	w2, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, w2.Stop(context.Background()))
	}()

	// Should have loaded index from file
	// We can't directly inspect the index, but we can append more events
	event := &jobv1.JobEvent{
		Sequence:  int64(3),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
	}
	require.NoError(t, w2.Append(context.Background(), event))
}

// MockEventSender for testing
type mockEventSender struct {
	sendFunc func(ctx context.Context, events []*jobv1.JobEvent) error
	calls    int
	lastErr  error
}

func (m *mockEventSender) Send(ctx context.Context, events []*jobv1.JobEvent) error {
	m.calls++
	if m.sendFunc != nil {
		m.lastErr = m.sendFunc(ctx, events)
		return m.lastErr
	}
	return nil
}

// TestAsyncSender tests async sender with mock
func TestAsyncSender(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 50 * time.Millisecond,
		RetryBackoff: BackoffConfig{
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
		},
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, w.Stop(context.Background()))
	}()

	// Create mock sender
	sentEvents := []*jobv1.JobEvent{}
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			sentEvents = append(sentEvents, events...)
			return nil
		},
	}

	// Start async sender
	err = w.Start(context.Background(), sender)
	require.NoError(t, err)

	// Append events
	for i := range 3 {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		require.NoError(t, w.Append(context.Background(), event))
	}

	// Wait for async sender to process
	time.Sleep(200 * time.Millisecond)

	// Stop WAL
	require.NoError(t, w.Stop(context.Background()))

	// Verify events were sent (sender.calls indicates attempt was made)
	assert.Positive(t, sender.calls)
}

// TestComputeCRC64Consistency tests CRC64 is computed correctly
func TestComputeCRC64Consistency(t *testing.T) {
	data := []byte("test data for crc")

	crc1 := computeCRC64(data)
	crc2 := computeCRC64(data)

	assert.Equal(t, crc1, crc2, "CRC64 should be consistent for same data")
}

// TestExponentialBackoff tests backoff calculation
func TestExponentialBackoff(t *testing.T) {
	backoff := BackoffConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      2.0,
	}

	sender := &asyncSender{
		backoff: backoff,
	}

	// Test backoff increases exponentially
	b1 := sender.calculateBackoff(1)
	b2 := sender.calculateBackoff(2)
	b3 := sender.calculateBackoff(3)

	// Each backoff should be greater than previous (accounting for jitter)
	assert.Less(t, b1, b2)
	assert.Less(t, b2, b3)

	// Test max interval is respected
	bMax := sender.calculateBackoff(100)
	assert.LessOrEqual(t, bMax, 1500*time.Millisecond) // Max + 50% jitter
}

// TestWALIndexGetAll tests retrieving all records
func TestWALIndexGetAll(t *testing.T) {
	idx := newWalIndex()

	// Add records
	idx.addRecord(1, 16, RecordPending)
	idx.addRecord(2, 50, RecordPending)
	idx.addRecord(3, 100, RecordSent)

	// Get all
	all := idx.getAll()
	assert.Len(t, all, 3)

	// Should be sorted by sequence
	assert.Equal(t, int64(1), all[0].sequence)
	assert.Equal(t, int64(2), all[1].sequence)
	assert.Equal(t, int64(3), all[2].sequence)
}

// TestWALIndexCount tests count method
func TestWALIndexCount(t *testing.T) {
	idx := newWalIndex()

	assert.Equal(t, 0, idx.count())

	idx.addRecord(1, 16, RecordPending)
	assert.Equal(t, 1, idx.count())

	idx.addRecord(2, 50, RecordPending)
	assert.Equal(t, 2, idx.count())

	idx.addRecord(3, 100, RecordSent)
	assert.Equal(t, 3, idx.count())
}

// TestDefaultConfig tests that default config is valid
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotEmpty(t, cfg.WALDir)
	assert.NotEmpty(t, cfg.ArchiveDir)
	assert.Positive(t, cfg.RetentionDays)
	assert.Greater(t, cfg.FlushInterval, time.Duration(0))
	assert.Greater(t, cfg.RetryBackoff.InitialInterval, time.Duration(0))
	assert.Greater(t, cfg.RetryBackoff.MaxInterval, time.Duration(0))
	assert.Greater(t, cfg.RetryBackoff.Multiplier, 1.0)
}

// TestWALStartWithoutSender tests that Start properly initializes sender
func TestWALStartWithoutSender(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		FlushInterval: 100 * time.Millisecond,
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, w.Stop(context.Background()))
	}()

	// Create a simple sender that tracks invocations
	callCount := 0
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			callCount++
			return nil
		},
	}

	// Start the sender
	err = w.Start(context.Background(), sender)
	require.NoError(t, err)

	// Append an event
	event := &jobv1.JobEvent{
		Sequence:  int64(0),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
	}
	err = w.Append(context.Background(), event)
	require.NoError(t, err)

	// Wait for async sender to process
	time.Sleep(200 * time.Millisecond)

	// Stop and verify sender was called
	err = w.Stop(context.Background())
	require.NoError(t, err)

	assert.Positive(t, callCount)
}

// BenchmarkWALAppend benchmarks WAL append performance
func BenchmarkWALAppend(b *testing.B) {
	walDir := b.TempDir()
	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    b.TempDir(),
		FlushInterval: 100 * time.Millisecond,
	}

	w, _ := NewWAL(cfg, "bench-job")
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

// BenchmarkCRC64Computation benchmarks CRC64 performance
func BenchmarkCRC64Computation(b *testing.B) {
	sizes := []int{1024, 10 * 1024, 100 * 1024, 200 * 1024}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dKB", size/1024), func(b *testing.B) {
			data := make([]byte, size)
			// #nosec G404 - random data for benchmark, not cryptographic
			_, _ = rand.Read(data)

			b.ResetTimer()
			b.SetBytes(int64(size))

			for i := 0; i < b.N; i++ {
				computeCRC64(data)
			}
		})
	}
}

// BenchmarkBuildRecord benchmarks record building
func BenchmarkBuildRecord(b *testing.B) {
	payload := make([]byte, 1000)
	// #nosec G404 - random data for benchmark, not cryptographic
	_, _ = rand.Read(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildRecord(int64(i), RecordPending, payload)
	}
}
