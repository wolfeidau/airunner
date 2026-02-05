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

// ArchiveCleanupError indicates the archive was created successfully but cleanup failed
type ArchiveCleanupError struct {
	ArchivePath string
	WALPath     string
	CleanupErr  error
}

func (e *ArchiveCleanupError) Error() string {
	return fmt.Sprintf("archive created at %s but failed to cleanup WAL file %s: %v",
		e.ArchivePath, e.WALPath, e.CleanupErr)
}

func (e *ArchiveCleanupError) Unwrap() error {
	return e.CleanupErr
}

// archiveWAL compresses a WAL file using zstd and moves it to the archive directory
func archiveWAL(walPath, archiveDir, jobID string) error {
	// Open source WAL file
	src, err := os.Open(walPath)
	if err != nil {
		return fmt.Errorf("failed to open WAL: %w", err)
	}
	defer src.Close()

	// Get source file info for stats
	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat WAL: %w", err)
	}
	originalSize := srcInfo.Size()

	// Create archive file
	archivePath := filepath.Join(archiveDir, fmt.Sprintf("%s.wal.zst", jobID))
	dst, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}
	defer dst.Close()

	// Create zstd encoder (level 3 = SpeedDefault, good balance of compression and speed)
	enc, err := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return fmt.Errorf("failed to create encoder: %w", err)
	}
	defer enc.Close()

	// Stream compress
	written, err := io.Copy(enc, src)
	if err != nil {
		// Ensure proper cleanup order
		if closeErr := enc.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close encoder during error cleanup")
		}
		if closeErr := dst.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close destination during error cleanup")
		}
		os.Remove(archivePath) // Clean up partial file
		return fmt.Errorf("failed to compress: %w", err)
	}

	// Close encoder to flush
	if err := enc.Close(); err != nil {
		if closeErr := dst.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close destination during encoder close error cleanup")
		}
		os.Remove(archivePath)
		return fmt.Errorf("failed to close encoder: %w", err)
	}

	// Close destination file
	if err := dst.Close(); err != nil {
		os.Remove(archivePath)
		return fmt.Errorf("failed to close archive: %w", err)
	}

	// Get compressed file size for stats
	dstInfo, err := os.Stat(archivePath)
	if err != nil {
		return fmt.Errorf("failed to stat archive: %w", err)
	}
	compressedSize := dstInfo.Size()

	// Calculate compression ratio
	ratio := 0.0
	if originalSize > 0 {
		ratio = (1.0 - float64(compressedSize)/float64(originalSize)) * 100
	}

	log.Info().
		Str("job_id", jobID).
		Int64("original_bytes", originalSize).
		Int64("compressed_bytes", compressedSize).
		Float64("compression_ratio_pct", ratio).
		Int64("written", written).
		Str("archive_path", archivePath).
		Msg("WAL archived with zstd compression")

	// Delete original WAL file
	if err := os.Remove(walPath); err != nil {
		log.Warn().
			Err(err).
			Str("wal_path", walPath).
			Str("archive_path", archivePath).
			Msg("Failed to delete original WAL after archiving")
		// Return custom error to indicate partial success
		return &ArchiveCleanupError{
			ArchivePath: archivePath,
			WALPath:     walPath,
			CleanupErr:  err,
		}
	}

	return nil
}

// CleanupArchive removes archived WAL files older than the retention period
func CleanupArchive(archiveDir string, retentionDays int) error {
	if retentionDays <= 0 {
		log.Debug().Msg("Archive cleanup disabled (retentionDays <= 0)")
		return nil
	}

	// Check if archive directory exists
	if _, err := os.Stat(archiveDir); os.IsNotExist(err) {
		log.Debug().Str("archive_dir", archiveDir).Msg("Archive directory does not exist, nothing to clean")
		return nil
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)

	log.Debug().
		Str("archive_dir", archiveDir).
		Int("retention_days", retentionDays).
		Time("cutoff_time", cutoffTime).
		Msg("Starting archive cleanup")

	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		return fmt.Errorf("failed to read archive directory: %w", err)
	}

	deletedCount := 0
	deletedBytes := int64(0)

	for _, entry := range entries {
		// Skip directories
		if entry.IsDir() {
			continue
		}

		// Only process .zst files (compressed WAL archives)
		if filepath.Ext(entry.Name()) != ".zst" {
			continue
		}

		// Get file info
		info, err := entry.Info()
		if err != nil {
			log.Warn().
				Err(err).
				Str("file", entry.Name()).
				Msg("Failed to get file info, skipping")
			continue
		}

		// Check if file is older than retention period
		if info.ModTime().Before(cutoffTime) {
			filePath := filepath.Join(archiveDir, entry.Name())
			fileSize := info.Size()

			if err := os.Remove(filePath); err != nil {
				log.Warn().
					Err(err).
					Str("file", filePath).
					Msg("Failed to delete old archive file")
				continue
			}

			deletedCount++
			deletedBytes += fileSize

			log.Debug().
				Str("file", entry.Name()).
				Int64("size_bytes", fileSize).
				Time("mod_time", info.ModTime()).
				Msg("Deleted old archive file")
		}
	}

	if deletedCount > 0 {
		log.Info().
			Str("archive_dir", archiveDir).
			Int("deleted_files", deletedCount).
			Int64("deleted_bytes", deletedBytes).
			Float64("deleted_mb", float64(deletedBytes)/(1024*1024)).
			Msg("Archive cleanup completed")
	} else {
		log.Debug().
			Str("archive_dir", archiveDir).
			Msg("No old archives to delete")
	}

	return nil
}

// decompressArchive decompresses a zstd-compressed WAL archive
// This is useful for debugging and manual inspection
//
//nolint:unused // Utility function for future debugging/CLI tools
func decompressArchive(archivePath, outputPath string) error {
	// Open compressed file
	src, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer src.Close()

	// Create output file
	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output: %w", err)
	}
	defer dst.Close()

	// Create zstd decoder
	dec, err := zstd.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create decoder: %w", err)
	}
	defer dec.Close()

	// Decompress
	written, err := io.Copy(dst, dec)
	if err != nil {
		dst.Close()
		os.Remove(outputPath)
		return fmt.Errorf("failed to decompress: %w", err)
	}

	log.Info().
		Str("archive_path", archivePath).
		Str("output_path", outputPath).
		Int64("decompressed_bytes", written).
		Msg("Archive decompressed successfully")

	return nil
}
