package wal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// TestWALIntegration tests full WAL flow with async sender
func TestWALIntegration(t *testing.T) {
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

	// Create mock sender that tracks calls
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
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		err = w.Append(context.Background(), event)
		require.NoError(t, err)
	}

	// Wait for async sender to process
	time.Sleep(300 * time.Millisecond)

	// Stop WAL
	err = w.Stop(context.Background())
	require.NoError(t, err)

	// Verify sender was called
	assert.Positive(t, sender.calls, "sender should have been called")

	// Verify WAL file exists
	walPath := filepath.Join(walDir, "test-job.wal")
	_, err = os.Stat(walPath)
	require.NoError(t, err, "WAL file should exist")
}

// TestWALArchive tests compression and cleanup
func TestWALArchive(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 100 * time.Millisecond,
	}

	w, err := NewWAL(cfg, "test-job")
	require.NoError(t, err)

	// Append events
	for i := 0; i < 10; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		require.NoError(t, w.Append(context.Background(), event))
	}

	// Stop before archiving
	require.NoError(t, w.Stop(context.Background()))

	// Archive
	err = w.Archive(context.Background(), archiveDir)
	require.NoError(t, err)

	// Verify archived file exists
	archivePath := filepath.Join(archiveDir, "test-job.wal.zst")
	info, err := os.Stat(archivePath)
	require.NoError(t, err)
	assert.Positive(t, info.Size())

	// Verify original is deleted
	walPath := filepath.Join(walDir, "test-job.wal")
	_, err = os.Stat(walPath)
	assert.True(t, os.IsNotExist(err), "original WAL file should be deleted")
}

// TestWALNetworkFailureRecovery tests recovery from network failures
func TestWALNetworkFailureRecovery(t *testing.T) {
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

	// Create sender that fails first time then succeeds
	attemptCount := 0
	sentEvents := []*jobv1.JobEvent{}
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			attemptCount++
			// First attempt fails
			if attemptCount == 1 {
				return assert.AnError
			}
			// Second attempt succeeds
			sentEvents = append(sentEvents, events...)
			return nil
		},
	}

	// Start async sender
	require.NoError(t, w.Start(context.Background(), sender))

	// Append events
	for i := 0; i < 5; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		require.NoError(t, w.Append(context.Background(), event))
	}

	// Wait for retry logic to kick in
	time.Sleep(500 * time.Millisecond)

	// Stop WAL
	require.NoError(t, w.Stop(context.Background()))

	// Should have retried and eventually sent
	assert.Greater(t, attemptCount, 1, "should have retried after initial failure")
}

// TestWALReplayAfterCrash tests replaying from WAL after restart
func TestWALReplayAfterCrash(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:        walDir,
		ArchiveDir:    archiveDir,
		RetentionDays: 30,
		FlushInterval: 50 * time.Millisecond,
	}

	// First process - create WAL and append events
	w1, err := NewWAL(cfg, "crash-test")
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		require.NoError(t, w1.Append(context.Background(), event))
	}

	// "Crash" - close without syncing sender
	require.NoError(t, w1.Stop(context.Background()))

	// Second process - recover from WAL
	w2, err := NewWAL(cfg, "crash-test")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, w2.Stop(context.Background()))
	}()

	// Create new sender
	sentEvents := []*jobv1.JobEvent{}
	sender := &mockEventSender{
		sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
			sentEvents = append(sentEvents, events...)
			return nil
		},
	}

	// Start async sender
	require.NoError(t, w2.Start(context.Background(), sender))

	// Wait for replay
	time.Sleep(200 * time.Millisecond)

	// Verify events were replayed
	assert.Positive(t, sender.calls, "should have replayed events from WAL")
}

// TestWALCleanupArchive tests cleanup of old archives
func TestWALCleanupArchive(t *testing.T) {
	archiveDir := t.TempDir()

	// Create old archive files
	oldFile := filepath.Join(archiveDir, "old-job.wal.zst")
	f, err := os.Create(oldFile)
	require.NoError(t, err)
	_, err = f.Write([]byte("test"))
	require.NoError(t, err)
	f.Close()

	// Set modification time to 40 days ago
	pastTime := time.Now().AddDate(0, 0, -40)
	require.NoError(t, os.Chtimes(oldFile, pastTime, pastTime))

	// Create recent file
	recentFile := filepath.Join(archiveDir, "recent-job.wal.zst")
	f, err = os.Create(recentFile)
	require.NoError(t, err)
	_, err = f.Write([]byte("test"))
	require.NoError(t, err)
	f.Close()

	// Run cleanup with 30-day retention
	err = CleanupArchive(archiveDir, 30)
	require.NoError(t, err)

	// Verify old file is deleted
	_, err = os.Stat(oldFile)
	assert.True(t, os.IsNotExist(err), "old archive should be deleted")

	// Verify recent file still exists
	_, err = os.Stat(recentFile)
	require.NoError(t, err, "recent archive should still exist")
}

// TestWALCorruptionDetection tests handling of corrupted records
func TestWALCorruptionDetection(t *testing.T) {
	walDir := t.TempDir()
	archiveDir := t.TempDir()

	cfg := &WALConfig{
		WALDir:     walDir,
		ArchiveDir: archiveDir,
	}

	// Create WAL and append events
	w, err := NewWAL(cfg, "corrupt-test")
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		event := &jobv1.JobEvent{
			Sequence:  int64(i),
			EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		}
		require.NoError(t, w.Append(context.Background(), event))
	}

	walPath := filepath.Join(walDir, "corrupt-test.wal")
	require.NoError(t, w.Stop(context.Background()))

	// Corrupt the file by modifying some bytes in the middle
	file, err := os.OpenFile(walPath, os.O_RDWR, 0600)
	require.NoError(t, err)

	// Write garbage at offset 50
	_, err = file.Seek(50, 0)
	require.NoError(t, err)
	_, err = file.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	require.NoError(t, err)
	file.Close()

	// Reopen - should handle corruption gracefully
	w2, err := NewWAL(cfg, "corrupt-test")
	require.NoError(t, err)
	defer func() {
		_ = w2.Stop(context.Background())
	}()

	// Should be able to append new events
	event := &jobv1.JobEvent{
		Sequence:  int64(3),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
	}
	err = w2.Append(context.Background(), event)
	require.NoError(t, err)
}
