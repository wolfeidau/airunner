package wal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// WAL provides durable event persistence
type WAL interface {
	Append(ctx context.Context, event *jobv1.JobEvent) error
	Start(ctx context.Context, sender EventSender) error
	Stop(ctx context.Context) error
	Archive(ctx context.Context, archiveDir string) error
}

// EventSender sends events to the server
type EventSender interface {
	Send(ctx context.Context, events []*jobv1.JobEvent) error
}

// WALConfig configures WAL behavior
type WALConfig struct {
	WALDir            string
	ArchiveDir        string
	RetentionDays     int
	FlushInterval     time.Duration
	RetryBackoff      BackoffConfig
	ArchiveOnComplete bool
}

// BackoffConfig configures exponential backoff
type BackoffConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *WALConfig {
	homeDir, _ := os.UserHomeDir()
	return &WALConfig{
		WALDir:            filepath.Join(homeDir, ".airunner", "wal"),
		ArchiveDir:        filepath.Join(homeDir, ".airunner", "archive"),
		RetentionDays:     30,
		FlushInterval:     100 * time.Millisecond,
		ArchiveOnComplete: true,
		RetryBackoff: BackoffConfig{
			InitialInterval: 1 * time.Second,
			MaxInterval:     60 * time.Second,
			Multiplier:      2.0,
		},
	}
}

// walImpl implements the WAL interface
type walImpl struct {
	mu       sync.RWMutex
	cfg      *WALConfig
	jobID    string
	file     *os.File
	index    *walIndex
	sender   *asyncSender
	closed   bool
	sequence int64
	offset   int64 // Current file offset
}

// NewWAL creates a new WAL instance
func NewWAL(cfg *WALConfig, jobID string) (WAL, error) {
	// Create WAL directory
	if err := os.MkdirAll(cfg.WALDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}

	// Create archive directory
	if err := os.MkdirAll(cfg.ArchiveDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create archive directory: %w", err)
	}

	w := &walImpl{
		cfg:   cfg,
		jobID: jobID,
		index: newWalIndex(),
	}

	// Open or create WAL file
	if err := w.openOrCreate(); err != nil {
		return nil, err
	}

	log.Debug().
		Str("job_id", jobID).
		Str("wal_path", w.walPath()).
		Msg("WAL opened")

	return w, nil
}

func (w *walImpl) walPath() string {
	return filepath.Join(w.cfg.WALDir, w.jobID+".wal")
}

// openOrCreate opens existing WAL or creates new with header
func (w *walImpl) openOrCreate() error {
	path := w.walPath()

	// Try to open existing file
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err == nil {
		// File exists, load index
		if err := w.loadIndex(file); err != nil {
			file.Close()
			return err
		}
		w.file = file
		return nil
	}

	// Create new file
	file, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create WAL file: %w", err)
		}
		// Race condition - file created by another goroutine
		// Try again
		file, err = os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("failed to open WAL file: %w", err)
		}
		if err := w.loadIndex(file); err != nil {
			file.Close()
			return err
		}
		w.file = file
		return nil
	}

	// Write header
	if err := writeHeader(file); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}

	w.file = file
	w.index = newWalIndex()
	w.offset = int64(headerSize) // Start after header
	return nil
}

// loadIndex loads WAL index from file
func (w *walImpl) loadIndex(file *os.File) error {
	// Seek to start
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	// Read and validate header
	headerBuf := make([]byte, headerSize)
	if _, err := file.Read(headerBuf); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if string(headerBuf[:8]) != walMagic {
		return fmt.Errorf("invalid WAL magic")
	}

	index := newWalIndex()
	offset := int64(headerSize)

	// Scan file and build index
	for {
		rec, err := readRecordAt(file, offset)
		if err != nil {
			// EOF or corruption
			if err == errEOF {
				break
			}
			// Corruption detected - truncate at this point
			log.Error().
				Int64("offset", offset).
				Err(err).
				Msg("Corrupt WAL record - truncating")
			if err := file.Truncate(offset); err != nil {
				log.Error().Err(err).Msg("Failed to truncate WAL file")
			}
			break
		}

		index.addRecord(rec.sequence, rec.offset, rec.status)
		if rec.sequence >= w.sequence {
			w.sequence = rec.sequence + 1
		}

		offset = rec.offset + rec.length
	}

	w.index = index
	w.offset = offset // Set offset to next write position
	return nil
}

// Append writes event to WAL with fsync
func (w *walImpl) Append(ctx context.Context, event *jobv1.JobEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("WAL is closed")
	}

	// Marshal event
	payload, err := marshalEvent(event)
	if err != nil {
		return err
	}

	// Build record
	record := buildRecord(w.sequence, RecordPending, payload)

	// Write to file
	if _, err := w.file.Write(record); err != nil {
		return fmt.Errorf("failed to write record: %w", err)
	}

	// Fsync for durability
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("failed to fsync: %w", err)
	}

	// Add to index
	w.index.addRecord(w.sequence, w.offset, RecordPending)

	// Update offset for next record
	w.offset += int64(len(record))
	w.sequence++

	return nil
}

// Start starts the async sender
func (w *walImpl) Start(ctx context.Context, sender EventSender) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.sender != nil {
		return fmt.Errorf("async sender already started")
	}

	w.sender = newAsyncSender(w, sender, w.cfg.FlushInterval, w.cfg.RetryBackoff)
	go w.sender.start(ctx)

	return nil
}

// Stop flushes pending events and stops async sender
func (w *walImpl) Stop(ctx context.Context) error {
	w.mu.Lock()

	if w.closed {
		w.mu.Unlock()
		return nil
	}

	w.closed = true
	sender := w.sender

	w.mu.Unlock()

	// Stop async sender first (before closing file)
	if sender != nil {
		if err := sender.stop(ctx); err != nil {
			log.Error().Err(err).Msg("failed to stop async sender")
		}
	}

	// Now close file
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("failed to close WAL file: %w", err)
		}
		w.file = nil
	}

	log.Debug().
		Str("job_id", w.jobID).
		Msg("WAL closed")

	return nil
}

// Archive compresses WAL and optionally deletes original
func (w *walImpl) Archive(ctx context.Context, archiveDir string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed {
		return fmt.Errorf("WAL must be closed before archiving")
	}

	return archiveWAL(w.walPath(), archiveDir, w.jobID)
}

// Internal methods for sender

// getUnsent returns all unsent records
func (w *walImpl) getUnsent() []*walRecord {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.index.getUnsent()
}

// markSent marks records as sent
func (w *walImpl) markSent(sequence ...int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, seq := range sequence {
		w.index.markSent(seq)
	}

	// TODO: Write status update to WAL file

	return nil
}
