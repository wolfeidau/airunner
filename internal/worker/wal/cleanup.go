package wal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const failedDirName = "failed"

// CleanupReport summarises a CleanupStale run.
type CleanupReport struct {
	LegacyDeleted int // legacy flat files deleted
	Deleted       int // stale per-attempt files deleted
	Moved         int // stale files moved to failed/
	SkippedLocked int // files held by a live process
	PrunedFailed  int // files removed from failed/
	Errors        int // non-fatal errors (logged)
}

// moveToFailed moves walPath to <walDir>/failed/<job>-<attempt>.wal and resets
// its mtime so retention counts from the move.
func moveToFailed(walDir, walPath, jobID string, attempt int32) error {
	failedDir := filepath.Join(walDir, failedDirName)
	if err := os.MkdirAll(failedDir, 0755); err != nil {
		return fmt.Errorf("failed to create failed directory: %w", err)
	}
	dst := filepath.Join(failedDir, fmt.Sprintf("%s-%d.wal", jobID, attempt))
	if err := os.Rename(walPath, dst); err != nil {
		return fmt.Errorf("failed to move WAL to failed: %w", err)
	}
	now := time.Now()
	_ = os.Chtimes(dst, now, now)
	return nil
}

// CleanupStale removes WAL files left behind by dead processes. It is meant
// to run once at worker startup. Files locked by a live process are never
// touched. Legacy flat <job>.wal files cannot prove attempt identity and are
// deleted. With keepFailed > 0, stale files move to <WALDir>/failed and are
// pruned once older than keepFailed; with keepFailed == 0 they are deleted and
// failed/ is emptied.
//
// When cfg.Metrics is set, worker.wal.failed_deleted increases by the number of
// WAL files removed from disk: LegacyDeleted + Deleted + PrunedFailed. Files
// moved to failed/ are not deletions and are counted when pruned later.
func CleanupStale(cfg *WALConfig, keepFailed time.Duration) (CleanupReport, error) {
	var report CleanupReport
	defer func() {
		cfg.metrics().WALFailedDeleted.Add(context.Background(),
			int64(report.LegacyDeleted+report.Deleted+report.PrunedFailed))
	}()

	entries, err := os.ReadDir(cfg.WALDir)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return report, fmt.Errorf("failed to read WAL directory: %w", err)
	}

	for _, entry := range entries {
		path := filepath.Join(cfg.WALDir, entry.Name())
		switch {
		case entry.Name() == failedDirName:
			continue
		case !entry.IsDir():
			if strings.HasSuffix(entry.Name(), ".wal") {
				if err := os.Remove(path); err != nil {
					log.Warn().Err(err).Str("path", path).Msg("Failed to delete legacy WAL")
					report.Errors++
					continue
				}
				log.Info().Str("path", path).Msg("Deleted legacy WAL file")
				report.LegacyDeleted++
			}
		default:
			cleanupJobDir(cfg, entry.Name(), keepFailed, &report)
			_ = os.Remove(path) // only succeeds when empty
		}
	}

	pruneFailed(cfg, keepFailed, &report)

	log.Info().
		Int("legacy_deleted", report.LegacyDeleted).
		Int("deleted", report.Deleted).
		Int("moved", report.Moved).
		Int("skipped_locked", report.SkippedLocked).
		Int("pruned_failed", report.PrunedFailed).
		Int("errors", report.Errors).
		Msg("WAL cleanup complete")

	return report, nil
}

func cleanupJobDir(cfg *WALConfig, jobID string, keepFailed time.Duration, report *CleanupReport) {
	dir := filepath.Join(cfg.WALDir, jobID)
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("Failed to read WAL job directory")
		report.Errors++
		return
	}

	for _, f := range files {
		name, ok := strings.CutSuffix(f.Name(), ".wal")
		if f.IsDir() || !ok {
			continue
		}
		attempt, err := strconv.ParseInt(name, 10, 32)
		if err != nil || attempt < 1 {
			continue
		}
		cleanupFile(cfg, jobID, int32(attempt), keepFailed, report)
	}
}

func cleanupFile(cfg *WALConfig, jobID string, attempt int32, keepFailed time.Duration, report *CleanupReport) {
	path := walFilePath(cfg.WALDir, jobID, attempt)
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Failed to open WAL for cleanup")
		report.Errors++
		return
	}
	defer f.Close()

	if err := tryLockFile(f); err != nil {
		if errors.Is(err, ErrWALLocked) {
			report.SkippedLocked++
			return
		}
		log.Warn().Err(err).Str("path", path).Msg("Failed to lock WAL for cleanup")
		report.Errors++
		return
	}

	pending := -1
	if id, perr := uuid.Parse(jobID); perr == nil {
		w := &walImpl{file: f, index: newWALIndex(), jobID: jobID, jobUUID: id, attempt: attempt, nextSequence: 1}
		if lerr := w.loadIndex(); lerr != nil {
			log.Warn().Err(lerr).Str("path", path).Msg("Failed to load stale WAL index")
		} else {
			pending = w.index.CountPending()
		}
	}

	action := "deleted"
	if keepFailed > 0 {
		err = moveToFailed(cfg.WALDir, path, jobID, attempt)
		action = "moved to failed"
	} else {
		err = os.Remove(path)
	}
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Failed to clean up stale WAL")
		report.Errors++
		return
	}
	if keepFailed > 0 {
		report.Moved++
	} else {
		report.Deleted++
	}

	log.Warn().
		Str("job_id", jobID).
		Int32("attempt", attempt).
		Int("pending", pending).
		Str("action", action).
		Msg("Cleaned up stale WAL")
}

func pruneFailed(cfg *WALConfig, keepFailed time.Duration, report *CleanupReport) {
	dir := filepath.Join(cfg.WALDir, failedDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn().Err(err).Str("dir", dir).Msg("Failed to read failed WAL directory")
			report.Errors++
		}
		return
	}

	cutoff := time.Now().Add(-keepFailed)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			report.Errors++
			continue
		}
		if keepFailed > 0 && !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			log.Warn().Err(err).Str("file", e.Name()).Msg("Failed to prune failed WAL")
			report.Errors++
			continue
		}
		report.PrunedFailed++
	}
}
