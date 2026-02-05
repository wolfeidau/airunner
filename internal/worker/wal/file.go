package wal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/minio/crc64nvme"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// WAL file format constants
	walMagic   = "ARWAL001"
	walVersion = uint32(1)
	headerSize = 16 // 8 bytes magic + 4 bytes version + 4 bytes reserved

	// Record status values
	RecordPending uint8 = 1
	RecordSent    uint8 = 2
	RecordFailed  uint8 = 3
)

// walRecord represents a record's metadata in the index
type walRecord struct {
	sequence  int64
	offset    int64
	length    int64
	status    uint8
	timestamp int64
}

// writeHeader writes the WAL file header
func (w *walImpl) writeHeader() error {
	header := make([]byte, headerSize)

	// Magic number (8 bytes)
	copy(header[0:8], walMagic)

	// Version (4 bytes)
	binary.LittleEndian.PutUint32(header[8:12], walVersion)

	// Reserved (4 bytes) - for future use
	binary.LittleEndian.PutUint32(header[12:16], 0)

	// Write header
	if _, err := w.file.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// appendRecord marshals event and writes binary record to file
func (w *walImpl) appendRecord(sequence int64, event *jobv1.JobEvent) (*walRecord, error) {
	// Marshal event to protobuf
	payload, err := proto.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	// Build binary record
	recordBytes := buildRecord(sequence, RecordPending, payload)

	// Get current position
	offset, err := w.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to get position: %w", err)
	}

	// Write record
	n, err := w.file.Write(recordBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write record: %w", err)
	}

	return &walRecord{
		sequence:  sequence,
		offset:    offset,
		length:    int64(n),
		status:    RecordPending,
		timestamp: time.Now().UnixMilli(),
	}, nil
}

// buildRecord constructs a binary record with CRC64
//
// Record format (total: 32 + payload_len bytes):
// - Length (4 bytes, uint32) - total record length including this field
// - Sequence (8 bytes, int64) - event sequence number
// - Status (1 byte, uint8) - RecordPending/RecordSent/RecordFailed
// - Reserved (3 bytes) - padding for alignment
// - Timestamp (8 bytes, int64) - Unix milliseconds
// - Payload (variable) - protobuf-encoded JobEvent
// - CRC64 (8 bytes, uint64) - CRC64-NVME checksum of all preceding fields (excluding length and CRC)
func buildRecord(sequence int64, status uint8, payload []byte) []byte {
	// Total: 4(length) + 8(seq) + 1(status) + 3(reserved) + 8(timestamp) + N(payload) + 8(CRC) = 32 + N
	//nolint:gosec // len(payload) is always positive and bounded by validation
	totalLength := uint32(32 + len(payload))
	buf := new(bytes.Buffer)

	// Write fields (everything before CRC)
	// binary.Write to bytes.Buffer never errors, so we can safely ignore
	_ = binary.Write(buf, binary.LittleEndian, totalLength)
	_ = binary.Write(buf, binary.LittleEndian, sequence)
	buf.WriteByte(status)
	buf.Write([]byte{0, 0, 0}) // Reserved padding
	_ = binary.Write(buf, binary.LittleEndian, time.Now().UnixMilli())
	buf.Write(payload)

	// Compute CRC64 over all data (excluding CRC field itself)
	// CRC is computed starting from byte 4 (after length field)
	crc := computeCRC64(buf.Bytes()[4:])

	// Append CRC64
	_ = binary.Write(buf, binary.LittleEndian, crc)

	return buf.Bytes()
}

// computeCRC64 computes CRC64-NVME checksum
func computeCRC64(data []byte) uint64 {
	h := crc64nvme.New()
	h.Write(data)
	return h.Sum64()
}

// readRecordAt reads and validates a record at the given offset
func readRecordAt(file *os.File, offset int64) (*jobv1.JobEvent, error) {
	// Seek to offset
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	// Read length field (4 bytes)
	var length uint32
	if err := binary.Read(file, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	// Validate length is reasonable (min 32 bytes, max 10MB)
	if length < 32 || length > 10*1024*1024 {
		return nil, fmt.Errorf("invalid record length: %d", length)
	}

	// Read rest of record (length includes the 4-byte length field)
	recordData := make([]byte, length)
	binary.LittleEndian.PutUint32(recordData[0:4], length)

	if _, err := io.ReadFull(file, recordData[4:]); err != nil {
		return nil, fmt.Errorf("failed to read record: %w", err)
	}

	// Extract CRC64 (last 8 bytes)
	storedCRC := binary.LittleEndian.Uint64(recordData[len(recordData)-8:])

	// Compute CRC64 over data (excluding length field and CRC field)
	dataForCRC := recordData[4 : len(recordData)-8]
	computedCRC := computeCRC64(dataForCRC)

	// Validate CRC
	if storedCRC != computedCRC {
		return nil, fmt.Errorf("CRC64 mismatch: stored=%x computed=%x", storedCRC, computedCRC)
	}

	// Parse fields
	// Skipping: sequence (8), status (1), reserved (3), timestamp (8) = 20 bytes
	payloadStart := 4 + 20            // Skip length(4) + metadata(20)
	payloadEnd := len(recordData) - 8 // Exclude CRC
	payload := recordData[payloadStart:payloadEnd]

	// Unmarshal event
	var event jobv1.JobEvent
	if err := proto.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return &event, nil
}

// loadIndex scans the WAL file and builds the in-memory index
func (w *walImpl) loadIndex() error {
	// Seek to start of file
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	// Read and validate header
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(w.file, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Validate magic
	magic := string(header[0:8])
	if magic != walMagic {
		return fmt.Errorf("invalid magic: %s", magic)
	}

	// Validate version
	version := binary.LittleEndian.Uint32(header[8:12])
	if version != walVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}

	// Scan records
	recordCount := 0
	corruptionCount := 0

	for {
		// Get current offset
		offset, err := w.file.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("failed to get position: %w", err)
		}

		// Read length field
		var length uint32
		if err := binary.Read(w.file, binary.LittleEndian, &length); err != nil {
			if err == io.EOF {
				break // End of file
			}
			log.Warn().
				Err(err).
				Int64("offset", offset).
				Msg("Failed to read record length, truncating WAL")
			// Truncate at corruption point
			if truncErr := w.file.Truncate(offset); truncErr != nil {
				log.Warn().Err(truncErr).Msg("Failed to truncate WAL")
			}
			break
		}

		// Validate length
		if length < 32 || length > 10*1024*1024 {
			log.Warn().
				Uint32("length", length).
				Int64("offset", offset).
				Msg("Invalid record length, truncating WAL")
			if truncErr := w.file.Truncate(offset); truncErr != nil {
				log.Warn().Err(truncErr).Msg("Failed to truncate WAL")
			}
			break
		}

		// Read rest of record
		recordData := make([]byte, length-4) // Already read 4 bytes (length)
		if _, err := io.ReadFull(w.file, recordData); err != nil {
			log.Warn().
				Err(err).
				Int64("offset", offset).
				Msg("Failed to read record data, truncating WAL")
			if truncErr := w.file.Truncate(offset); truncErr != nil {
				log.Warn().Err(truncErr).Msg("Failed to truncate WAL")
			}
			break
		}

		// Extract fields
		//nolint:gosec // Converting uint64 to int64 is safe here - sequence is always positive
		sequence := int64(binary.LittleEndian.Uint64(recordData[0:8]))
		status := recordData[8]
		//nolint:gosec // Converting uint64 to int64 is safe here - timestamp is always positive
		timestamp := int64(binary.LittleEndian.Uint64(recordData[12:20]))

		// Verify CRC64
		storedCRC := binary.LittleEndian.Uint64(recordData[len(recordData)-8:])
		computedCRC := computeCRC64(recordData[:len(recordData)-8])

		if storedCRC != computedCRC {
			log.Warn().
				Int64("offset", offset).
				Int64("sequence", sequence).
				Str("stored_crc", fmt.Sprintf("%x", storedCRC)).
				Str("computed_crc", fmt.Sprintf("%x", computedCRC)).
				Msg("CRC mismatch, truncating WAL")
			if truncErr := w.file.Truncate(offset); truncErr != nil {
				log.Warn().Err(truncErr).Msg("Failed to truncate WAL")
			}
			corruptionCount++
			break
		}

		// Add to index
		w.index.Add(walRecord{
			sequence:  sequence,
			offset:    offset,
			length:    int64(length),
			status:    status,
			timestamp: timestamp,
		})

		recordCount++

		// Update next sequence
		if sequence >= w.nextSequence {
			w.nextSequence = sequence + 1
		}
	}

	if corruptionCount > 0 {
		log.Warn().
			Str("job_id", w.jobID).
			Int("corrupted_records", corruptionCount).
			Msg("WAL corruption detected and truncated")
	}

	log.Debug().
		Str("job_id", w.jobID).
		Int("records", recordCount).
		Int64("next_sequence", w.nextSequence).
		Msg("WAL index loaded")

	return nil
}
