package wal

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// WAL provides durable event persistence with async retry
type WAL interface {
	// Append writes event to disk (synchronous, with fsync)
	// Returns error if disk write or fsync fails
	Append(ctx context.Context, event *jobv1.JobEvent) error

	// Start begins async sender goroutine
	// The sender will continuously retry failed sends with exponential backoff
	Start(ctx context.Context, sender EventSender) error

	// Flush blocks until all pending events are sent
	// Returns error if context is cancelled or events cannot be sent
	// Should be called before completing a job to ensure no data loss
	Flush(ctx context.Context) error

	// Stop flushes pending events and stops async sender
	// Blocks until all pending events are sent or context is cancelled
	Stop(ctx context.Context) error

	// Archive compresses WAL file and moves to archive directory
	// Uses zstd level 3 compression (~70% reduction)
	Archive(ctx context.Context, archiveDir string) error
}

// EventSender sends events to the server
// This interface allows decoupling WAL from transport mechanism
type EventSender interface {
	// Send transmits events to the server
	// Returns error if send fails (WAL will retry)
	Send(ctx context.Context, events []*jobv1.JobEvent) error
}

// WALConfig configures WAL behavior
type WALConfig struct {
	// WALDir is the directory for active WAL files
	WALDir string

	// ArchiveDir is the directory for compressed archives
	ArchiveDir string

	// RetentionDays is how long to keep archived files
	RetentionDays int

	// FlushInterval is how often the async sender checks for unsent events
	FlushInterval time.Duration

	// RetryBackoff configures exponential backoff for failed sends
	RetryBackoff BackoffConfig

	// ArchiveOnComplete enables automatic archiving after job completion
	ArchiveOnComplete bool
}

// BackoffConfig configures exponential backoff retry
type BackoffConfig struct {
	// InitialInterval is the first retry delay (e.g., 1 second)
	InitialInterval time.Duration

	// MaxInterval is the maximum retry delay (e.g., 60 seconds)
	MaxInterval time.Duration

	// Multiplier controls backoff growth (e.g., 2.0 for exponential)
	Multiplier float64
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
	mu     sync.RWMutex
	cfg    *WALConfig
	jobID  string
	file   *os.File
	index  *walIndex
	sender *asyncSender

	nextSequence int64
	walPath      string
	isStarted    bool
}

// NewWAL creates a new WAL instance for the given job ID
func NewWAL(cfg *WALConfig, jobID string) (WAL, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Ensure directories exist
	if err := os.MkdirAll(cfg.WALDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}
	if err := os.MkdirAll(cfg.ArchiveDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create archive directory: %w", err)
	}

	w := &walImpl{
		cfg:          cfg,
		jobID:        jobID,
		walPath:      filepath.Join(cfg.WALDir, fmt.Sprintf("%s.wal", jobID)),
		index:        newWALIndex(),
		nextSequence: 1,
	}

	// Open or create WAL file
	if err := w.openOrCreate(); err != nil {
		return nil, fmt.Errorf("failed to open WAL: %w", err)
	}

	log.Info().
		Str("job_id", jobID).
		Str("wal_path", w.walPath).
		Int64("records", int64(w.index.Count())).
		Msg("WAL initialized")

	return w, nil
}

// openOrCreate opens existing WAL or creates new one with header
func (w *walImpl) openOrCreate() error {
	// Check if WAL file exists
	fileExists := false
	if _, err := os.Stat(w.walPath); err == nil {
		fileExists = true
	}

	// Open file for read/write, create if not exists
	var err error
	w.file, err = os.OpenFile(w.walPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	if !fileExists {
		// New file - write header
		if err := w.writeHeader(); err != nil {
			w.file.Close()
			return fmt.Errorf("failed to write header: %w", err)
		}
		log.Debug().Str("job_id", w.jobID).Msg("Created new WAL file with header")
	} else {
		// Existing file - load index
		if err := w.loadIndex(); err != nil {
			w.file.Close()
			return fmt.Errorf("failed to load index: %w", err)
		}
		log.Debug().
			Str("job_id", w.jobID).
			Int("records", w.index.Count()).
			Int("pending", w.index.CountPending()).
			Msg("Loaded existing WAL")
	}

	return nil
}

// Append writes event to disk with fsync
func (w *walImpl) Append(ctx context.Context, event *jobv1.JobEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return fmt.Errorf("WAL is closed")
	}

	// Get current file position (before write)
	offset, err := w.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get file position: %w", err)
	}

	// Use event's sequence if set, otherwise use internal sequence
	sequence := event.Sequence
	if sequence == 0 {
		sequence = w.nextSequence
		w.nextSequence++
	} else if sequence >= w.nextSequence {
		// Update next sequence if event has higher sequence
		w.nextSequence = sequence + 1
	}

	// Write record to file
	record, err := w.appendRecord(sequence, event)
	if err != nil {
		return fmt.Errorf("failed to append record: %w", err)
	}

	// Fsync for durability
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("failed to fsync: %w", err)
	}

	// Add to index
	w.index.Add(walRecord{
		sequence:  sequence,
		offset:    offset,
		length:    record.length,
		status:    RecordPending,
		timestamp: time.Now().UnixMilli(),
	})

	log.Debug().
		Str("job_id", w.jobID).
		Int64("sequence", sequence).
		Int64("offset", offset).
		Msg("Event appended to WAL")

	return nil
}

// Start begins async sender goroutine
func (w *walImpl) Start(ctx context.Context, sender EventSender) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isStarted {
		return fmt.Errorf("WAL already started")
	}

	w.sender = newAsyncSender(w, sender, w.cfg)
	go w.sender.sendLoop(ctx)
	w.isStarted = true

	log.Info().
		Str("job_id", w.jobID).
		Msg("WAL async sender started")

	return nil
}

// Flush blocks until all pending events are sent or context is cancelled
func (w *walImpl) Flush(ctx context.Context) error {
	log.Info().
		Str("job_id", w.jobID).
		Msg("Flushing WAL, waiting for all events to be sent")

	// Trigger immediate send attempt (interrupts retry backoff)
	w.mu.RLock()
	if w.sender != nil {
		w.sender.triggerFlush()
	}
	w.mu.RUnlock()

	// Poll every 100ms to check if all events are sent
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		w.mu.RLock()
		pending := w.index.CountPending()
		total := w.index.Count()
		sent := w.index.CountSent()
		hasSender := w.sender != nil
		w.mu.RUnlock()

		if pending == 0 {
			log.Info().
				Str("job_id", w.jobID).
				Int("total_events", total).
				Int("sent", sent).
				Msg("All WAL events sent successfully")
			return nil
		}

		log.Debug().
			Str("job_id", w.jobID).
			Int("pending", pending).
			Int("sent", sent).
			Int("total", total).
			Msg("Waiting for pending events to be sent")

		// Periodically trigger flush to keep sender active
		if hasSender {
			w.mu.RLock()
			if w.sender != nil {
				w.sender.triggerFlush()
			}
			w.mu.RUnlock()
		}

		select {
		case <-ticker.C:
			// Continue polling
		case <-ctx.Done():
			return fmt.Errorf("flush cancelled: %d events still pending: %w", pending, ctx.Err())
		}
	}
}

// Stop flushes pending events and stops async sender
func (w *walImpl) Stop(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.sender != nil {
		w.sender.stop()
		w.sender = nil
	}

	if w.file != nil {
		if err := w.file.Close(); err != nil {
			log.Error().Err(err).Str("job_id", w.jobID).Msg("Failed to close WAL file")
			return fmt.Errorf("failed to close file: %w", err)
		}
		w.file = nil
	}

	log.Info().
		Str("job_id", w.jobID).
		Int("total_records", w.index.Count()).
		Int("sent", w.index.CountSent()).
		Int("pending", w.index.CountPending()).
		Msg("WAL stopped")

	return nil
}

// Archive compresses WAL file and moves to archive directory
func (w *walImpl) Archive(ctx context.Context, archiveDir string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return fmt.Errorf("WAL must be stopped before archiving")
	}

	// Use configured archive dir if not specified
	if archiveDir == "" {
		archiveDir = w.cfg.ArchiveDir
	}

	// Ensure archive directory exists
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	// Archive the WAL file
	if err := archiveWAL(w.walPath, archiveDir, w.jobID); err != nil {
		return fmt.Errorf("failed to archive WAL: %w", err)
	}

	log.Info().
		Str("job_id", w.jobID).
		Str("archive_dir", archiveDir).
		Msg("WAL archived")

	return nil
}

// readRecordAt reads a record from the file at the given offset
func (w *walImpl) readRecordAt(offset int64) (*jobv1.JobEvent, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.file == nil {
		return nil, fmt.Errorf("WAL is closed")
	}

	record, err := readRecordAt(w.file, offset)
	if err != nil {
		return nil, err
	}

	return record, nil
}
