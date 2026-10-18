package wal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/telemetry"
)

// Sentinel errors. The transport adapter wraps its errors with ErrPermanent
// or ErrLeaseLost so the wal package stays transport-agnostic.
var (
	// ErrPermanent marks an error that retrying cannot fix.
	ErrPermanent = errors.New("permanent publish error")

	// ErrLeaseLost marks that the job lease was lost; publishing must stop.
	ErrLeaseLost = errors.New("job lease lost")

	// ErrAckMismatch is returned when the acknowledgement does not match the
	// batch that was sent.
	ErrAckMismatch = fmt.Errorf("%w: acknowledgement mismatch", ErrPermanent)

	// ErrWALLocked is returned when another open WAL holds the file lock.
	ErrWALLocked = errors.New("WAL is locked by another process")

	errWALClosed = errors.New("WAL is closed")
)

// WAL provides durable event persistence with async retry
type WAL interface {
	// Append stamps the event with the WAL attempt and writes it to disk
	// (synchronous, with fsync)
	Append(ctx context.Context, event *jobv1.JobEvent) error

	// Start begins async sender goroutine
	// The sender retries transient failures with capped exponential backoff
	// and stops on a permanent error or lease loss.
	Start(ctx context.Context, sender EventSender) error

	// Flush blocks until all pending events are acknowledged, the sticky error
	// is set (returned immediately), or ctx is done.
	Flush(ctx context.Context) error

	// Err returns the sticky publish error, if any.
	Err() error

	// Pending returns the number of unacknowledged records.
	Pending() int

	// Acked returns the highest acknowledged covered sequence.
	Acked() int64

	// Stop makes one final best-effort send, stops the sender, closes the file
	// and releases the lock.
	Stop(ctx context.Context) error

	// Discard stops the sender without sending more, closes the file, deletes
	// it (or moves it to <WALDir>/failed when keep is set) and releases the lock.
	Discard(keep bool) error

	// Archive compresses a stopped WAL file and moves it to the archive directory
	// Uses zstd level 3 compression (~70% reduction)
	Archive(ctx context.Context, archiveDir string) error
}

// Ack is the server's acknowledgement of a published batch.
type Ack struct {
	// Attempt is the job attempt the events were recorded against.
	Attempt int32
	// Through is the last covered sequence committed by the request.
	Through int64
}

// EventSender sends events to the server
// This interface allows decoupling WAL from transport mechanism
type EventSender interface {
	// Send transmits one batch and returns the server's acknowledgement.
	// Errors wrapping ErrLeaseLost or ErrPermanent stop the sender; any other
	// error is treated as transient and retried.
	Send(ctx context.Context, events []*jobv1.JobEvent) (Ack, error)
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

	// FlushPollInterval is how often the Flush method checks if all events are sent
	FlushPollInterval time.Duration

	// RetryBackoff configures exponential backoff for failed sends
	RetryBackoff BackoffConfig

	// ArchiveOnComplete enables automatic archiving after job completion
	ArchiveOnComplete bool

	// Metrics receives WAL and publish metrics. Nil disables recording.
	Metrics *telemetry.WorkerMetrics
}

// metrics returns the configured instruments or no-op instruments.
func (c *WALConfig) metrics() *telemetry.WorkerMetrics {
	if c == nil || c.Metrics == nil {
		return noopMetrics
	}
	return c.Metrics
}

var noopMetrics = telemetry.NoopWorkerMetrics()

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
		FlushPollInterval: 100 * time.Millisecond,
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
	mu      sync.RWMutex
	cfg     *WALConfig
	jobID   string
	jobUUID uuid.UUID
	attempt int32
	file    *os.File // holds the flock until closed
	index   *walIndex
	sender  *asyncSender

	nextSequence int64
	walPath      string
	isStarted    bool

	acked   int64
	err     error
	errCh   chan struct{} // closed when err is first set
	errOnce sync.Once
}

// NewWAL creates a new WAL for the given job and attempt at
// <WALDir>/<jobID>/<attempt>.wal. The file is locked exclusively until Stop,
// Discard or Archive. An existing file for the same (job, attempt) is a stale
// crash leftover and is recreated, because attempts are never reused.
func NewWAL(cfg *WALConfig, jobID string, attempt int32) (WAL, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	jobUUID, err := uuid.Parse(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job id %q: %w", jobID, err)
	}
	if attempt < 1 {
		return nil, fmt.Errorf("invalid attempt %d", attempt)
	}

	// Set defaults for zero-valued fields
	if cfg.FlushPollInterval == 0 {
		cfg.FlushPollInterval = 100 * time.Millisecond
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}

	jobDir := filepath.Join(cfg.WALDir, jobID)
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}
	if err := os.MkdirAll(cfg.ArchiveDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create archive directory: %w", err)
	}

	w := &walImpl{
		cfg:          cfg,
		jobID:        jobID,
		jobUUID:      jobUUID,
		attempt:      attempt,
		walPath:      walFilePath(cfg.WALDir, jobID, attempt),
		index:        newWALIndex(),
		nextSequence: 1,
		errCh:        make(chan struct{}),
	}

	if err := w.openAndLock(); err != nil {
		return nil, err
	}

	log.Info().
		Str("job_id", jobID).
		Int32("attempt", attempt).
		Str("wal_path", w.walPath).
		Msg("WAL initialized")

	return w, nil
}

func walFilePath(walDir, jobID string, attempt int32) string {
	return filepath.Join(walDir, jobID, fmt.Sprintf("%d.wal", attempt))
}

// openAndLock opens the WAL file, takes the lock and writes a fresh header.
func (w *walImpl) openAndLock() error {
	f, err := os.OpenFile(w.walPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open WAL file: %w", err)
	}
	if err := tryLockFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to lock %s: %w", w.walPath, err)
	}
	w.file = f

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to stat WAL file: %w", err)
	}

	if info.Size() > 0 {
		// A file claiming another job or attempt means the path is wrong.
		header := make([]byte, headerSize)
		if _, rerr := io.ReadFull(f, header); rerr == nil {
			if id, att, derr := decodeHeader(header); derr == nil && (id != w.jobUUID || att != w.attempt) {
				_ = f.Close()
				return fmt.Errorf("WAL header mismatch at %s: file has job=%s attempt=%d, expected job=%s attempt=%d",
					w.walPath, id, att, w.jobUUID, w.attempt)
			}
		}
		log.Warn().
			Str("job_id", w.jobID).
			Int32("attempt", w.attempt).
			Int64("bytes", info.Size()).
			Msg("Recreating stale WAL file left by a previous process")
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to truncate stale WAL: %w", err)
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to seek: %w", err)
	}
	if err := w.writeHeader(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to sync header: %w", err)
	}
	return nil
}

// Append writes event to disk with fsync
func (w *walImpl) Append(ctx context.Context, event *jobv1.JobEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return errWALClosed
	}

	// Seek to end of file to ensure we always append after the last record,
	// even if the async sender has moved the file pointer via readRecordAt.
	offset, err := w.file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to get file position: %w", err)
	}

	event.Attempt = w.attempt

	// Use event's sequence if set, otherwise use internal sequence
	sequence := event.Sequence
	if sequence == 0 {
		sequence = w.nextSequence
		w.nextSequence++
	} else if sequence >= w.nextSequence {
		w.nextSequence = sequence + 1
	}

	record, err := w.appendRecord(sequence, event)
	if err != nil {
		return fmt.Errorf("failed to append record: %w", err)
	}

	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("failed to fsync: %w", err)
	}

	w.index.Add(walRecord{
		sequence:  sequence,
		offset:    offset,
		length:    record.length,
		status:    RecordPending,
		timestamp: time.Now().UnixMilli(),
	})

	return nil
}

// Start begins async sender goroutine
func (w *walImpl) Start(ctx context.Context, sender EventSender) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isStarted {
		return fmt.Errorf("WAL already started")
	}

	w.sender = newAsyncSender(ctx, w, sender, w.cfg)
	go w.sender.sendLoop()
	w.isStarted = true

	log.Info().Str("job_id", w.jobID).Msg("WAL async sender started")

	return nil
}

// setErr records the first sticky error and wakes waiting Flush callers.
func (w *walImpl) setErr(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
	w.errOnce.Do(func() { close(w.errCh) })

	log.Error().
		Err(err).
		Str("job_id", w.jobID).
		Int32("attempt", w.attempt).
		Int("pending", w.index.CountPending()).
		Msg("WAL publishing stopped")
}

// Err returns the sticky publish error, if any
func (w *walImpl) Err() error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.err
}

// Pending returns the number of unacknowledged records
func (w *walImpl) Pending() int {
	return w.index.CountPending()
}

// Acked returns the highest acknowledged covered sequence
func (w *walImpl) Acked() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.acked
}

func (w *walImpl) setAcked(through int64) {
	w.mu.Lock()
	if through > w.acked {
		w.acked = through
	}
	w.mu.Unlock()
}

// Flush blocks until all pending events are acknowledged
func (w *walImpl) Flush(ctx context.Context) error {
	w.mu.RLock()
	if w.sender != nil {
		w.sender.triggerFlush()
	}
	w.mu.RUnlock()

	ticker := time.NewTicker(w.cfg.FlushPollInterval)
	defer ticker.Stop()

	for {
		if err := w.Err(); err != nil {
			return err
		}
		pending := w.index.CountPending()
		if pending == 0 {
			return nil
		}

		select {
		case <-ticker.C:
		case <-w.errCh:
		case <-ctx.Done():
			return fmt.Errorf("flush cancelled: %d events still pending: %w", pending, ctx.Err())
		}
	}
}

// takeSender detaches the sender so it can be stopped without holding w.mu
// (the sender goroutine needs w.mu to read records).
func (w *walImpl) takeSender() *asyncSender {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.sender
	w.sender = nil
	return s
}

// Stop flushes pending events once and stops async sender
func (w *walImpl) Stop(ctx context.Context) error {
	if s := w.takeSender(); s != nil {
		s.stop(false)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		if err != nil {
			log.Error().Err(err).Str("job_id", w.jobID).Msg("Failed to close WAL file")
			return fmt.Errorf("failed to close file: %w", err)
		}
	}

	log.Info().
		Str("job_id", w.jobID).
		Int("total_records", w.index.Count()).
		Int("sent", w.index.CountSent()).
		Int("pending", w.index.CountPending()).
		Msg("WAL stopped")

	return nil
}

// Discard stops the sender without sending more, then deletes the file or
// moves it to <WALDir>/failed when keep is set, and releases the lock.
func (w *walImpl) Discard(keep bool) error {
	if s := w.takeSender(); s != nil {
		s.stop(true)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	m := w.cfg.metrics()
	var opErr error
	if keep {
		opErr = moveToFailed(w.cfg.WALDir, w.walPath, w.jobID, w.attempt)
	} else if err := os.Remove(w.walPath); err == nil {
		// Only deletions count; a move to failed/ is not a deletion.
		m.WALFailedDeleted.Add(context.Background(), 1)
	} else if !errors.Is(err, os.ErrNotExist) {
		opErr = fmt.Errorf("failed to remove WAL: %w", err)
	}
	m.WALPendingRecords.Record(context.Background(), 0)

	if w.file != nil {
		if err := w.file.Close(); err != nil && opErr == nil {
			opErr = fmt.Errorf("failed to close file: %w", err)
		}
		w.file = nil
	}
	_ = os.Remove(filepath.Dir(w.walPath)) // only succeeds when empty

	log.Info().
		Str("job_id", w.jobID).
		Int32("attempt", w.attempt).
		Bool("kept", keep).
		Int("pending", w.index.CountPending()).
		Msg("WAL discarded")

	return opErr
}

// Archive compresses WAL file and moves to archive directory
func (w *walImpl) Archive(ctx context.Context, archiveDir string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return fmt.Errorf("WAL must be stopped before archiving")
	}

	if archiveDir == "" {
		archiveDir = w.cfg.ArchiveDir
	}
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	if err := archiveWAL(w.walPath, archiveDir, w.jobID, w.attempt); err != nil {
		return fmt.Errorf("failed to archive WAL: %w", err)
	}
	_ = os.Remove(filepath.Dir(w.walPath)) // only succeeds when empty

	log.Info().
		Str("job_id", w.jobID).
		Str("archive_dir", archiveDir).
		Msg("WAL archived")

	return nil
}

// readRecordAt reads a record from the file at the given offset
func (w *walImpl) readRecordAt(offset int64) (*jobv1.JobEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil, errWALClosed
	}

	return readRecordAt(w.file, offset)
}
