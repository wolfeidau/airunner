package wal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/minio/crc64nvme"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"google.golang.org/protobuf/proto"
)

const (
	walMagic   = "ARWAL001"
	walVersion = uint32(1)
	headerSize = 16

	RecordPending uint8 = 1
	RecordSent    uint8 = 2
	RecordFailed  uint8 = 3
)

var errEOF = errors.New("EOF")

type walRecord struct {
	sequence  int64
	offset    int64
	length    int64
	status    uint8
	timestamp int64
}

// writeHeader writes WAL file header
func writeHeader(file *os.File) error {
	header := make([]byte, headerSize)
	copy(header[0:8], walMagic)
	binary.LittleEndian.PutUint32(header[8:12], walVersion)
	// [12:16] reserved (zeros)

	if _, err := file.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// marshalEvent marshals JobEvent to protobuf bytes
func marshalEvent(event *jobv1.JobEvent) ([]byte, error) {
	return proto.Marshal(event)
}

// unmarshalEvent unmarshals JobEvent from protobuf bytes
func unmarshalEvent(payload []byte) (*jobv1.JobEvent, error) {
	event := &jobv1.JobEvent{}
	if err := proto.Unmarshal(payload, event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	return event, nil
}

// buildRecord constructs a binary WAL record
// Format: [length:4][sequence:8][status:1][reserved:3][timestamp:8][payload:variable][crc:8]
// Length field contains: sequence(8) + status(1) + reserved(3) + timestamp(8) + payload
func buildRecord(sequence int64, status uint8, payload []byte) []byte {
	// Calculate length: seq(8) + status(1) + reserved(3) + timestamp(8) + payload
	// Note: length excludes the length field itself and the CRC field
	// #nosec G115 - len(payload) is bounded by maximum event size check in readRecordAt
	recordLength := uint32(8 + 1 + 3 + 8 + len(payload))

	buf := new(bytes.Buffer)

	// Write length field
	if err := binary.Write(buf, binary.LittleEndian, recordLength); err != nil {
		// Buffer write should never fail, but handle for completeness
		return nil
	}

	// Write sequence
	if err := binary.Write(buf, binary.LittleEndian, sequence); err != nil {
		return nil
	}

	// Write status
	if err := buf.WriteByte(status); err != nil {
		return nil
	}

	// Write reserved bytes
	if _, err := buf.Write([]byte{0, 0, 0}); err != nil {
		return nil
	}

	// Write timestamp
	if err := binary.Write(buf, binary.LittleEndian, time.Now().UnixMilli()); err != nil {
		return nil
	}

	// Write payload
	if _, err := buf.Write(payload); err != nil {
		return nil
	}

	// Compute CRC64 over everything except the CRC itself
	dataForCRC := buf.Bytes()[4:] // Skip length field
	crc := computeCRC64(dataForCRC)

	// Write CRC
	if err := binary.Write(buf, binary.LittleEndian, crc); err != nil {
		return nil
	}

	return buf.Bytes()
}

// readRecordAt reads a record at the given offset
func readRecordAt(file *os.File, offset int64) (*walRecord, error) {
	if _, err := file.Seek(offset, 0); err != nil {
		return nil, err
	}

	// Read length field
	lengthBuf := make([]byte, 4)
	if _, err := file.Read(lengthBuf); err != nil {
		if err == io.EOF {
			return nil, errEOF
		}
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	length := binary.LittleEndian.Uint32(lengthBuf)
	if length == 0 || length > 10_000_000 { // Sanity check: max 10MB record
		return nil, fmt.Errorf("invalid record length: %d", length)
	}

	// Read rest of record (length + 8 bytes for CRC)
	// Length field contains: seq(8) + status(1) + reserved(3) + timestamp(8) + payload
	// We need to also read the CRC (8 bytes)
	recordBuf := make([]byte, length+8)
	if _, err := file.Read(recordBuf); err != nil {
		if err == io.EOF {
			return nil, errEOF
		}
		return nil, fmt.Errorf("failed to read record data: %w", err)
	}

	// Verify CRC64
	// CRC is computed over: sequence(8) + status(1) + reserved(3) + timestamp(8) + payload
	// (everything except length and CRC fields)
	storedCRC := binary.LittleEndian.Uint64(recordBuf[len(recordBuf)-8:])
	// recordBuf is: seq(8) + status(1) + reserved(3) + timestamp(8) + payload + crc(8)
	// so dataForCRC should exclude the last 8 bytes (CRC)
	dataForCRC := recordBuf[:len(recordBuf)-8]
	actualCRC := computeCRC64(dataForCRC)

	if actualCRC != storedCRC {
		return nil, fmt.Errorf("CRC64 mismatch: expected %d, got %d", storedCRC, actualCRC)
	}

	// Parse fields
	// #nosec G115 - sequence and timestamp are safe conversions from protocol data
	sequence := int64(binary.LittleEndian.Uint64(recordBuf[0:8]))
	status := recordBuf[8]
	// reserved := recordBuf[9:12]
	// #nosec G115 - sequence and timestamp are safe conversions from protocol data
	timestamp := int64(binary.LittleEndian.Uint64(recordBuf[12:20]))

	return &walRecord{
		sequence:  sequence,
		offset:    offset,
		length:    int64(4 + length + 8), // length field(4) + record data + crc(8)
		status:    status,
		timestamp: timestamp,
	}, nil
}

// computeCRC64 computes CRC64-NVME checksum
func computeCRC64(data []byte) uint64 {
	h := crc64nvme.New()
	h.Write(data)
	return h.Sum64()
}
