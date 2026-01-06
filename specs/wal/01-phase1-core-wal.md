# Phase 1: Core WAL Package Implementation

[← README](README.md) | [← Architecture](00-architecture.md) | [Phase 2 →](02-phase2-integration.md)

## Goal

Implement the core WAL package with durable file persistence, CRC64-NVME checksums, async retry logic, and zstd compression.

**Estimated Duration**: 16-20 hours

## Prerequisites

- Go 1.21+
- Understanding of Write-Ahead Logs
- Familiarity with binary file formats
- Knowledge of protobuf serialization

## Success Criteria

- [ ] WAL package compiles without errors
- [ ] Can create WAL file with header
- [ ] Can append events with fsync
- [ ] CRC64-NVME checksums verify correctly
- [ ] Can load existing WAL and build index
- [ ] Async sender retries with exponential backoff
- [ ] Archives compress with zstd (70% reduction)
- [ ] Cleanup removes files older than retention

## Implementation Steps

### Step 1: Add Dependencies

Add required libraries to `go.mod`:

```bash
go get github.com/minio/crc64nvme@latest
go get github.com/klauspost/compress@latest
```

**Verify**:
```bash
grep "minio/crc64nvme" go.mod
grep "klauspost/compress" go.mod
```

Expected output:
```
github.com/minio/crc64nvme v1.1.1
github.com/klauspost/compress v1.18.2
```

### Step 2: Create WAL Interface (`wal.go`)

**File**: `internal/worker/wal/wal.go`

Create the main WAL interface and configuration:

```go
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
```

Implement `walImpl` struct with:
- `mu sync.RWMutex` for thread safety
- `file *os.File` for WAL file handle
- `index *walIndex` for tracking sent/unsent records
- `sender *asyncSender` for background retry

**Key Methods**:
- `NewWAL(cfg, jobID)` - Create WAL, open/create file, load index
- `openOrCreate()` - Open existing WAL or create new with header
- `Append(ctx, event)` - Write record with fsync
- `Start(ctx, sender)` - Start async sender goroutine
- `Stop(ctx)` - Flush pending, stop sender, close file

**Verification**:
```bash
cd internal/worker/wal
go build
```

Should compile without errors.

### Step 3: Implement Binary File Format (`file.go`)

**File**: `internal/worker/wal/file.go`

Implement binary record format with CRC64-NVME:

```go
package wal

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "io"
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

type walRecord struct {
    sequence  int64
    offset    int64
    length    int64
    status    uint8
    timestamp int64
}
```

**Key Functions**:

1. `writeHeader()` - Write magic + version to new file
2. `appendRecord(event)` - Marshal event, build record, write with CRC64
3. `buildRecord(sequence, status, payload)` - Construct binary record
4. `readRecordAt(offset)` - Read and validate record with CRC64
5. `loadIndex()` - Scan file, build index, handle corruption
6. `computeCRC64(data)` - Compute CRC64-NVME checksum

**Record Construction**:
```go
func buildRecord(sequence int64, status uint8, payload []byte) []byte {
    totalLength := uint32(28 + len(payload))
    buf := new(bytes.Buffer)

    binary.Write(buf, binary.LittleEndian, totalLength)
    binary.Write(buf, binary.LittleEndian, sequence)
    buf.WriteByte(status)
    buf.Write([]byte{0, 0, 0}) // Reserved
    binary.Write(buf, binary.LittleEndian, time.Now().UnixMilli())
    buf.Write(payload)

    // CRC64 over all data except CRC field
    crc := computeCRC64(buf.Bytes()[4:])
    binary.Write(buf, binary.LittleEndian, crc)

    return buf.Bytes()
}
```

**CRC64 Computation**:
```go
func computeCRC64(data []byte) uint64 {
    h := crc64nvme.New()
    h.Write(data)
    return h.Sum64()
}
```

**Verification**:
```bash
cd internal/worker/wal
go test -run TestBuildRecord
```

Create a simple test:
```go
func TestBuildRecord(t *testing.T) {
    payload := []byte("test event")
    record := buildRecord(42, RecordPending, payload)

    // Verify length
    length := binary.LittleEndian.Uint32(record[0:4])
    assert.Equal(t, uint32(28+len(payload)), length)

    // Verify sequence
    sequence := binary.LittleEndian.Int64(record[4:12])
    assert.Equal(t, int64(42), sequence)

    // Verify CRC64
    crc := binary.LittleEndian.Uint64(record[len(record)-8:])
    assert.NotZero(t, crc)
}
```

### Step 4: Implement In-Memory Index (`index.go`)

**File**: `internal/worker/wal/index.go`

Track which records are sent vs pending:

```go
package wal

import "sync"

type walIndex struct {
    mu      sync.RWMutex
    records []walRecord
}

func newWALIndex() *walIndex {
    return &walIndex{
        records: make([]walRecord, 0, 1000),
    }
}

func (idx *walIndex) Add(rec walRecord) {
    idx.mu.Lock()
    defer idx.mu.Unlock()
    idx.records = append(idx.records, rec)
}

func (idx *walIndex) GetUnsent() []walRecord {
    idx.mu.RLock()
    defer idx.mu.RUnlock()

    var unsent []walRecord
    for _, rec := range idx.records {
        if rec.status == RecordPending {
            unsent = append(unsent, rec)
        }
    }
    return unsent
}

func (idx *walIndex) MarkSent(recs []walRecord) {
    idx.mu.Lock()
    defer idx.mu.Unlock()

    toMark := make(map[int64]bool)
    for _, rec := range recs {
        toMark[rec.sequence] = true
    }

    for i := range idx.records {
        if toMark[idx.records[i].sequence] {
            idx.records[i].status = RecordSent
        }
    }
}
```

**Additional Methods**:
- `MarkFailed(recs)` - Mark as failed
- `Count()` - Total records
- `CountPending()` - Pending count
- `CountSent()` - Sent count
- `CountFailed()` - Failed count

**Verification**:
```bash
go test -run TestWALIndex
```

### Step 5: Implement Async Sender (`sender.go`)

**File**: `internal/worker/wal/sender.go`

Background goroutine with retry logic:

```go
package wal

import (
    "context"
    "fmt"
    "time"

    "github.com/rs/zerolog/log"
    jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

type asyncSender struct {
    wal    *walImpl
    sender EventSender
    cfg    *WALConfig

    stopCh chan struct{}
    doneCh chan struct{}
}

func newAsyncSender(wal *walImpl, sender EventSender, cfg *WALConfig) *asyncSender {
    return &asyncSender{
        wal:    wal,
        sender: sender,
        cfg:    cfg,
        stopCh: make(chan struct{}),
        doneCh: make(chan struct{}),
    }
}

func (s *asyncSender) sendLoop(ctx context.Context) {
    defer close(s.doneCh)

    ticker := time.NewTicker(s.cfg.FlushInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            s.trySend(ctx)

        case <-s.stopCh:
            s.trySend(ctx) // Final flush
            return

        case <-ctx.Done():
            return
        }
    }
}
```

**Retry Logic**:
```go
func (s *asyncSender) trySend(ctx context.Context) {
    unsent := s.wal.index.GetUnsent()
    if len(unsent) == 0 {
        return
    }

    events, validRecords, _ := s.readRecords(unsent)

    // Exponential backoff retry
    var sendErr error
    interval := s.cfg.RetryBackoff.InitialInterval

    for {
        sendErr = s.sender.Send(ctx, events)
        if sendErr == nil {
            break // Success
        }

        // Wait with exponential backoff
        select {
        case <-time.After(interval):
            interval = time.Duration(float64(interval) * s.cfg.RetryBackoff.Multiplier)
            if interval > s.cfg.RetryBackoff.MaxInterval {
                interval = s.cfg.RetryBackoff.MaxInterval
            }
        case <-ctx.Done():
            return
        case <-s.stopCh:
            return
        }
    }

    if sendErr == nil {
        s.wal.index.MarkSent(validRecords)
    } else {
        s.wal.index.MarkFailed(validRecords)
    }
}
```

**Verification**:
```bash
go test -run TestAsyncSender
```

### Step 6: Implement Archive with Zstd (`archive.go`)

**File**: `internal/worker/wal/archive.go`

Compress and archive WAL files:

```go
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

func archiveWAL(walPath, archiveDir, jobID string) error {
    src, err := os.Open(walPath)
    if err != nil {
        return fmt.Errorf("failed to open WAL: %w", err)
    }
    defer src.Close()

    archivePath := filepath.Join(archiveDir, fmt.Sprintf("%s.wal.zst", jobID))
    dst, err := os.Create(archivePath)
    if err != nil {
        return fmt.Errorf("failed to create archive: %w", err)
    }
    defer dst.Close()

    // Create zstd encoder (level 3 = SpeedDefault)
    enc, err := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedDefault))
    if err != nil {
        return fmt.Errorf("failed to create encoder: %w", err)
    }
    defer enc.Close()

    // Stream compress
    written, err := io.Copy(enc, src)
    if err != nil {
        return fmt.Errorf("failed to compress: %w", err)
    }

    enc.Close()
    dst.Close()

    // Log compression stats
    srcInfo, _ := src.Stat()
    dstInfo, _ := os.Stat(archivePath)
    ratio := (1.0 - float64(dstInfo.Size())/float64(srcInfo.Size())) * 100

    log.Info().
        Str("job_id", jobID).
        Int64("original", srcInfo.Size()).
        Int64("compressed", dstInfo.Size()).
        Float64("ratio", ratio).
        Msg("WAL archived")

    // Delete original
    os.Remove(walPath)

    return nil
}
```

**Cleanup Function**:
```go
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
        return err
    }

    for _, entry := range entries {
        if entry.IsDir() || filepath.Ext(entry.Name()) != ".zst" {
            continue
        }

        info, _ := entry.Info()
        if info.ModTime().Before(cutoffTime) {
            filePath := filepath.Join(archiveDir, entry.Name())
            os.Remove(filePath)
        }
    }

    return nil
}
```

**Verification**:
```bash
# Create test WAL
echo "test data" > /tmp/test.wal

# Compress
go run -c 'package main; import "github.com/wolfeidau/airunner/internal/worker/wal"; wal.archiveWAL("/tmp/test.wal", "/tmp", "test-job")'

# Check compressed file exists
ls -lh /tmp/test-job.wal.zst

# Verify compression ratio
zstd -l /tmp/test-job.wal.zst
```

### Step 7: Build and Test WAL Package

**Build**:
```bash
cd internal/worker/wal
go build
```

Should compile without errors.

**Basic Integration Test**:
```go
func TestWALIntegration(t *testing.T) {
    // Create temp directories
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

    // Create WAL
    w, err := NewWAL(cfg, "test-job")
    require.NoError(t, err)

    // Mock sender
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
            Sequence: int64(i),
            EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
        }
        err = w.Append(context.Background(), event)
        require.NoError(t, err)
    }

    // Wait for async sender to process
    time.Sleep(500 * time.Millisecond)

    // Stop WAL
    err = w.Stop(context.Background())
    require.NoError(t, err)

    // Verify events sent
    assert.Len(t, sentEvents, 10)

    // Archive
    err = w.Archive(context.Background(), archiveDir)
    require.NoError(t, err)

    // Verify archive exists
    archivePath := filepath.Join(archiveDir, "test-job.wal.zst")
    _, err = os.Stat(archivePath)
    assert.NoError(t, err)
}
```

Run test:
```bash
go test -v -run TestWALIntegration
```

## Verification Commands

### 1. Build WAL Package
```bash
cd internal/worker/wal
go build
echo $?  # Should output 0
```

### 2. Run Unit Tests
```bash
go test -v ./...
```

### 3. Check Dependencies
```bash
go list -m github.com/minio/crc64nvme
go list -m github.com/klauspost/compress
```

### 4. Inspect WAL File Format
```bash
# Create sample WAL
# ... run worker ...

# Dump header
hexdump -C ~/.airunner/wal/<job-id>.wal | head -n 2
# Should see: "ARWAL001" magic

# Check file size
ls -lh ~/.airunner/wal/<job-id>.wal
```

### 5. Test Compression
```bash
# Check archive
ls -lh ~/.airunner/archive/*.wal.zst

# Decompress and verify
zstd -d ~/.airunner/archive/<job-id>.wal.zst -o /tmp/decompressed.wal
hexdump -C /tmp/decompressed.wal | head
```

## Troubleshooting

### Build Errors

**Error**: `undefined: crc64nvme`
```bash
go get github.com/minio/crc64nvme@latest
go mod tidy
```

**Error**: `undefined: zstd`
```bash
go get github.com/klauspost/compress@latest
go mod tidy
```

### Runtime Errors

**Error**: "failed to create WAL directory"
```bash
# Ensure directory is writable
chmod 755 ~/.airunner
mkdir -p ~/.airunner/wal
```

**Error**: "CRC64 mismatch"
- WAL file corrupted
- Truncate at corruption point automatically handled
- Check disk health

## Next Phase

Proceed to [Phase 2: Worker Integration](02-phase2-integration.md) to integrate the WAL into the worker command.

---

[← README](README.md) | [← Architecture](00-architecture.md) | [Phase 2 →](02-phase2-integration.md)
