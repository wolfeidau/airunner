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
