package wal

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
)

// archiveWAL compresses WAL file with zstd and deletes original
func archiveWAL(walPath, archiveDir, jobID string) error {
	// Open source file
	src, err := os.Open(walPath)
	if err != nil {
		return fmt.Errorf("failed to open WAL file: %w", err)
	}
	defer src.Close()

	// Create archive path
	archivePath := filepath.Join(archiveDir, jobID+".wal.zst")

	// Create destination file
	dst, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}
	defer dst.Close()

	// Create zstd encoder (level 3 = SpeedDefault)
	enc, err := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		os.Remove(archivePath)
		return fmt.Errorf("failed to create encoder: %w", err)
	}
	defer enc.Close()

	// Stream compress
	written, err := io.Copy(enc, src)
	if err != nil {
		os.Remove(archivePath)
		return fmt.Errorf("failed to compress: %w", err)
	}

	enc.Close()
	dst.Close()

	// Log compression stats
	srcInfo, err := src.Stat()
	if err != nil {
		log.Warn().Err(err).Msg("failed to stat source file")
		return nil
	}
	dstInfo, err := os.Stat(archivePath)
	if err != nil {
		log.Warn().Err(err).Msg("failed to stat archive file")
		return nil
	}
	ratio := (1.0 - float64(dstInfo.Size())/float64(srcInfo.Size())) * 100

	log.Info().
		Str("job_id", jobID).
		Int64("original", srcInfo.Size()).
		Int64("compressed", dstInfo.Size()).
		Float64("ratio", ratio).
		Int64("written", written).
		Msg("WAL archived")

	// Delete original
	if err := os.Remove(walPath); err != nil {
		log.Warn().
			Err(err).
			Str("path", walPath).
			Msg("failed to delete original WAL file")
	}

	return nil
}

// CleanupArchive removes WAL archives older than retentionDays
func CleanupArchive(archiveDir string, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)

	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read archive directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".zst" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			log.Warn().Err(err).Str("name", entry.Name()).Msg("failed to get entry info")
			continue
		}
		if info.ModTime().Before(cutoffTime) {
			filePath := filepath.Join(archiveDir, entry.Name())
			if err := os.Remove(filePath); err != nil {
				log.Warn().
					Err(err).
					Str("path", filePath).
					Msg("failed to remove old archive")
				continue
			}

			log.Debug().
				Str("path", filePath).
				Msg("removed old archive")
		}
	}

	return nil
}
