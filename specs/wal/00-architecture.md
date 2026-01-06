# WAL Architecture and Design

[← README](README.md) | [Phase 1 →](01-phase1-core-wal.md)

## Summary

The Write-Ahead Log (WAL) provides durable event persistence for airunner workers, ensuring zero data loss during network failures. Events are written to disk with fsync before acknowledgment, then asynchronously retried with exponential backoff until the server confirms receipt.

## Goals

1. **Zero Data Loss**: Events survive worker crashes and network failures
2. **Transparent Integration**: Minimal changes to existing worker code
3. **Local Archiving**: 30-day retention for debugging and compliance
4. **Efficient Storage**: Zstd compression reduces archive size by ~70%
5. **Simple Operation**: No external dependencies (Redis, Kafka, etc.)

## Design Decisions

### 1. Durability Guarantee: Fsync Per Event

**Decision**: Call `fsync()` after every event write to WAL

**Rationale**:
- Provides absolute durability guarantee (survives power loss, kernel panic)
- ~5% overhead acceptable for critical event persistence
- Alternative (batched fsync every 100ms) risks losing 100ms of events on crash

**Trade-offs**:
- ✅ Zero data loss on worker crash
- ✅ Simple recovery (just replay WAL)
- ❌ 5ms fsync latency per event on SSD
- ❌ Higher disk I/O

**Performance Impact**:
```
Typical job: 10 events/sec
Fsync latency: 5ms per event (SSD)
Total overhead: 10 * 5ms = 50ms/sec = 5%
```

### 2. Checksum: CRC64-NVME (MinIO Library)

**Decision**: Use CRC64-NVME via `github.com/minio/crc64nvme`

**Rationale**:
- Stronger corruption detection than CRC32 (2^64 vs 2^32 collision resistance)
- Hardware-accelerated (SIMD instructions: SSE4.2, AVX-512)
- 10-20x faster than Go stdlib
- Events can be up to 200KB - need strong checksums for large payloads

**Comparison**:

| Checksum | Collision Resistance | Performance | Overhead |
|----------|---------------------|-------------|----------|
| CRC32 | 1 in 4 billion | ~3 GB/s | 4 bytes |
| CRC64-stdlib | 1 in 18 quintillion | ~500 MB/s | 8 bytes |
| **CRC64-NVME** | **1 in 18 quintillion** | **~10 GB/s (AVX-512)** | **8 bytes** |

**Code**:
```go
import "github.com/minio/crc64nvme"

func computeCRC64(data []byte) uint64 {
    h := crc64nvme.New()
    h.Write(data)
    return h.Sum64()
}
```

### 3. Compression: Zstd Level 3 for Archives Only

**Decision**: Compress WAL files only when archiving (not during active write)

**Rationale**:
- Active WAL needs fast writes (no compression overhead)
- Easy debugging (can inspect active WAL with hex editor)
- Archives compress well (70% reduction for text/protobuf)
- Zstd level 3 provides good balance of speed and compression ratio

**Compression Levels**:

| Level | Ratio | Speed | Use Case |
|-------|-------|-------|----------|
| 1 (Fastest) | ~50% | Very fast | High job throughput |
| **3 (Default)** | **~70%** | **Fast** | **Recommended** |
| 7 (Better) | ~80% | Medium | Low job throughput |
| 19 (Best) | ~90% | Slow | Maximum space savings |

**Space Savings**:
```
Without compression:
  100 jobs/day × 2 MB/job × 30 days = 6 GB

With zstd level 3:
  100 jobs/day × 0.6 MB/job × 30 days = 1.8 GB

Savings: 4.2 GB (70% reduction)
```

### 4. Retry Policy: Infinite with Exponential Backoff

**Decision**: Retry failed sends forever with exponential backoff (1s → 60s max)

**Rationale**:
- Network failures are usually transient (~30 seconds based on user report)
- Better to keep retrying than to give up and lose events
- Exponential backoff prevents overwhelming the server
- Worker can be restarted to clear stuck retries if needed

**Backoff Strategy**:
```go
Initial interval: 1 second
Max interval: 60 seconds
Multiplier: 2.0
Randomization: 50% jitter (prevent thundering herd)

Timeline:
  Attempt 1: immediate
  Attempt 2: ~1s later (0.5-1.5s with jitter)
  Attempt 3: ~2s later (1-3s)
  Attempt 4: ~4s later (2-6s)
  Attempt 5: ~8s later (4-12s)
  Attempt 6: ~16s later (8-24s)
  Attempt 7: ~32s later (16-48s)
  Attempt 8+: ~60s later (30-90s) [max interval reached]
```

### 5. File Format: Binary Length-Prefixed Protobuf

**Decision**: Custom binary format with length-prefixed protobuf payloads

**Rationale**:
- Self-describing (magic header identifies file type)
- Efficient (binary, not text)
- Protobuf already used for job events
- Length prefix allows seeking to specific records
- CRC64 checksum detects corruption

**Alternative Considered**: JSON Lines format
- ❌ 3-5x larger file size
- ❌ Slower to parse
- ✅ Human-readable (but can use hex dump for binary too)

## Binary File Format Specification

### File Structure

```
[Header: 16 bytes]
  Magic: "ARWAL001" (8 bytes)
  Version: 1 (4 bytes)
  Reserved: 4 bytes (zeros)

[Record 1]
[Record 2]
...
[Record N]
```

### Record Structure

```
[Length: uint32] (4 bytes) - total record length excluding this field
[Sequence: int64] (8 bytes) - event sequence number
[Status: uint8] (1 byte) - 1=pending, 2=sent, 3=failed
[Reserved: 3 bytes] (zeros - for future use)
[Timestamp: int64] (8 bytes) - Unix milliseconds
[Payload: variable] - protobuf-serialized JobEvent
[CRC64: uint64] (8 bytes) - CRC64-NVME checksum of all preceding fields

Total metadata overhead: 32 bytes per record
```

### Record Status Values

| Value | Name | Meaning |
|-------|------|---------|
| 1 | `RecordPending` | Event written to WAL, not yet sent to server |
| 2 | `RecordSent` | Event successfully sent and acknowledged by server |
| 3 | `RecordFailed` | Event failed after all retries (manual intervention needed) |

### Example Record Breakdown

For a 2KB protobuf event:

```
Byte Range  | Field        | Value
------------|--------------|---------------------------
0-3         | Length       | 2060 (0x080C in hex)
4-11        | Sequence     | 42
12          | Status       | 1 (pending)
13-15       | Reserved     | 0x000000
16-23       | Timestamp    | 1704067200000 (2024-01-01)
24-2083     | Payload      | <2060 bytes protobuf>
2084-2091   | CRC64        | 0xABCDEF1234567890

Total size: 2092 bytes
```

### CRC64 Computation

The CRC64 checksum is computed over all fields **except** the CRC64 field itself:

```go
// Data to checksum: everything after Length field, before CRC64
dataForCRC := record[4:len(record)-8]

// Compute CRC64-NVME
h := crc64nvme.New()
h.Write(dataForCRC)
crc := h.Sum64()
```

This protects against:
- Bit flips during write
- Disk corruption
- Incomplete writes (truncated records)

## Data Flow Architecture

### Event Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│ Worker Process                                                       │
│                                                                       │
│  ┌─────────────┐                                                     │
│  │ Job         │                                                     │
│  │ Execution   │                                                     │
│  └──────┬──────┘                                                     │
│         │ OutputData events                                          │
│         ↓                                                             │
│  ┌─────────────┐                                                     │
│  │ Event       │  Batches events (50 items or 256KB)                │
│  │ Batcher     │                                                     │
│  └──────┬──────┘                                                     │
│         │ onFlush callback                                           │
│         ↓                                                             │
│  ┌─────────────┐                                                     │
│  │ WAL.Append()│  ← NEW: Write to disk with fsync                   │
│  │             │    (~5ms latency)                                   │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         ↓                                                             │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │ WAL File on Disk                                        │        │
│  │ ~/.airunner/wal/<job-id>.wal                            │        │
│  │                                                          │        │
│  │ [Header][Record 1][Record 2]...[Record N]               │        │
│  │  ↑                                                       │        │
│  │  └─ fsync after each append                             │        │
│  └──────┬──────────────────────────────────────────────────┘        │
│         │                                                             │
│         │ Async read (100ms interval)                                │
│         ↓                                                             │
│  ┌─────────────┐                                                     │
│  │ Async       │  Background goroutine                               │
│  │ Sender      │  Retries with exponential backoff                  │
│  └──────┬──────┘                                                     │
│         │                                                             │
└─────────┼─────────────────────────────────────────────────────────┘
          │
          │ gRPC stream (Connect RPC)
          ↓
┌─────────────────────────────────────────────────────────────────────┐
│ Server                                                               │
│                                                                       │
│  ┌─────────────┐                                                     │
│  │ PublishJob  │                                                     │
│  │ Events RPC  │                                                     │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         ↓                                                             │
│  ┌─────────────┐                                                     │
│  │ PostgreSQL  │                                                     │
│  │ job_events  │                                                     │
│  │ table       │                                                     │
│  └─────────────┘                                                     │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Recovery Flow (Worker Restart)

```
Worker starts
    ↓
Job dequeued
    ↓
Create WAL
    ↓
Check if WAL file exists for this job_id
    ↓
    ├─ YES: Load existing WAL
    │   ↓
    │   Scan all records
    │   ↓
    │   Build in-memory index
    │   ↓
    │   Identify PENDING records
    │   ↓
    │   Async sender will replay these
    │
    └─ NO: Create new WAL
        ↓
        Write header
        ↓
        Ready for new events
```

## Component Architecture

### 1. WAL Interface

**File**: `internal/worker/wal/wal.go`

```go
type WAL interface {
    // Append writes event to disk (synchronous, with fsync)
    Append(ctx context.Context, event *jobv1.JobEvent) error

    // Start begins async sender goroutine
    Start(ctx context.Context, sender EventSender) error

    // Stop flushes pending events and stops async sender
    Stop(ctx context.Context) error

    // Archive compresses WAL file and moves to archive directory
    Archive(ctx context.Context, archiveDir string) error
}

type EventSender interface {
    Send(ctx context.Context, events []*jobv1.JobEvent) error
}
```

**Responsibilities**:
- Durable persistence of events to disk
- Lifecycle management (start/stop)
- Archival with compression

### 2. walImpl (Implementation)

**File**: `internal/worker/wal/wal.go`

**State**:
```go
type walImpl struct {
    mu sync.RWMutex

    cfg      *WALConfig
    jobID    string
    file     *os.File      // WAL file handle
    filePath string

    index  *walIndex      // In-memory sent/unsent tracking
    sender *asyncSender   // Background retry goroutine

    stopCh   chan struct{}
    stopOnce sync.Once     // Idempotent stop
}
```

**Thread Safety**:
- All public methods acquire `mu` lock
- Protects concurrent access from EventBatcher and AsyncSender
- `stopOnce` ensures Stop() is idempotent

### 3. walIndex (In-Memory Index)

**File**: `internal/worker/wal/index.go`

**Purpose**: Track which records have been sent vs pending

**State**:
```go
type walIndex struct {
    mu      sync.RWMutex
    records []walRecord
}

type walRecord struct {
    sequence  int64  // Event sequence number
    offset    int64  // File offset where record starts
    length    int64  // Record length (for seeking)
    status    uint8  // pending/sent/failed
    timestamp int64  // When record was written
}
```

**Operations**:
- `Add(rec)` - Add new record to index
- `GetUnsent()` - Return all pending records
- `MarkSent(recs)` - Mark records as successfully sent
- `MarkFailed(recs)` - Mark records as failed after retry exhaustion

### 4. asyncSender (Retry Engine)

**File**: `internal/worker/wal/sender.go`

**Purpose**: Background goroutine that retries failed sends

**Flow**:
```go
func (s *asyncSender) sendLoop(ctx context.Context) {
    ticker := time.NewTicker(100 * time.Millisecond)

    for {
        select {
        case <-ticker.C:
            // Try to send pending records
            unsent := s.wal.index.GetUnsent()
            if len(unsent) == 0 {
                continue
            }

            // Read events from WAL
            events := s.readRecords(unsent)

            // Send with exponential backoff
            err := s.sendWithRetry(ctx, events)
            if err == nil {
                s.wal.index.MarkSent(unsent)
            } else {
                s.wal.index.MarkFailed(unsent)
            }

        case <-s.stopCh:
            // Final flush before exit
            s.trySend(ctx)
            return
        }
    }
}
```

**Retry Logic**:
- Infinite retry with exponential backoff
- Initial interval: 1s
- Max interval: 60s
- Multiplier: 2.0
- Gives up only on context cancellation or explicit stop

### 5. Archive with Zstd Compression

**File**: `internal/worker/wal/archive.go`

**Flow**:
```go
func archiveWAL(walPath, archiveDir, jobID string) error {
    // Open source WAL
    src, _ := os.Open(walPath)

    // Create compressed archive
    dst, _ := os.Create(filepath.Join(archiveDir, jobID + ".wal.zst"))

    // Create zstd encoder (level 3)
    enc, _ := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedDefault))

    // Stream compress
    io.Copy(enc, src)

    // Delete original
    os.Remove(walPath)
}
```

**Cleanup**:
```go
func CleanupArchive(archiveDir string, retentionDays int) error {
    cutoffTime := time.Now().AddDate(0, 0, -retentionDays)

    // Scan archive directory
    entries, _ := os.ReadDir(archiveDir)

    for _, entry := range entries {
        info, _ := entry.Info()

        // Delete files older than retention
        if info.ModTime().Before(cutoffTime) {
            os.Remove(filepath.Join(archiveDir, entry.Name()))
        }
    }
}
```

## Integration Architecture

### Worker Integration Point

**File**: `cmd/cli/internal/commands/worker.go`

**Before WAL**:
```go
eventStream := clients.Events.PublishJobEvents(ctx)

batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
    return eventStream.Send(&jobv1.PublishJobEventsRequest{
        TaskToken: taskToken,
        Events:    []*jobv1.JobEvent{event},
    })
})
```

**After WAL**:
```go
eventStream := clients.Events.PublishJobEvents(ctx)

// Create WAL
jobWAL, _ := wal.NewWAL(wal.DefaultConfig(), job.JobId)
defer jobWAL.Stop(ctx)

// Wrap stream as EventSender
sender := &grpcEventSender{stream: eventStream, taskToken: taskToken}

// Start async sender
jobWAL.Start(ctx, sender)

// Batcher writes to WAL instead of direct send
batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
    return jobWAL.Append(ctx, event)  // Write to WAL with fsync
})
```

### grpcEventSender Adapter

```go
type grpcEventSender struct {
    stream    *connect.ClientStreamForClient[...]
    taskToken string
}

func (s *grpcEventSender) Send(ctx context.Context, events []*jobv1.JobEvent) error {
    return s.stream.Send(&jobv1.PublishJobEventsRequest{
        TaskToken: s.taskToken,
        Events:    events,
    })
}
```

This adapter allows the WAL to send events through the existing gRPC stream without changes to the server or protocol.

## Configuration

### WALConfig

```go
type WALConfig struct {
    WALDir            string        // Active WAL storage
    ArchiveDir        string        // Compressed archives
    RetentionDays     int           // Archive cleanup threshold
    FlushInterval     time.Duration // Async sender poll interval
    RetryBackoff      BackoffConfig
    ArchiveOnComplete bool          // Archive after job completion
}
```

### Default Configuration

```go
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

## Error Handling

### WAL Write Failures

**Scenario**: Disk full during `WAL.Append()`

**Behavior**:
- Return error to EventBatcher
- EventBatcher propagates error to JobExecutor
- Job execution fails
- Job remains in queue for retry

**Why**: Cannot guarantee durability without disk space

### Network Failures

**Scenario**: Server unreachable during event send

**Behavior**:
- Async sender retries with exponential backoff
- Events remain in WAL with status=PENDING
- Worker continues processing job
- Events eventually sent when network recovers

**Recovery**:
- Network recovers after 30 seconds → events sent successfully
- Worker crashes before send → next worker replays WAL on restart

### Corruption Detection

**Scenario**: Corrupt record detected via CRC64 mismatch

**Behavior**:
```go
actualCRC := computeCRC64(recordData)
if actualCRC != storedCRC {
    // Truncate WAL at this point
    w.file.Truncate(offset)

    // Log corruption
    log.Error().
        Int64("offset", offset).
        Uint64("expected_crc", storedCRC).
        Uint64("actual_crc", actualCRC).
        Msg("Corrupt WAL record - truncated")

    // Stop loading index
    break
}
```

**Result**: WAL truncated at first corrupt record, events after corruption lost

## Performance Characteristics

### Write Path Latency

```
EventBatcher.AddOutput()
    ↓ (buffer until flush trigger)
EventBatcher.onFlush()
    ↓
WAL.Append()
    ↓ Marshal protobuf (~100 µs)
    ↓ Write to file (~50 µs)
    ↓ Compute CRC64 (~10 µs for 2KB, using SIMD)
    ↓ fsync() (~5ms on SSD)
    ↓
Return to EventBatcher

Total: ~5.2ms per batch (dominated by fsync)
```

### Read Path (Async Sender)

```
AsyncSender tick (every 100ms)
    ↓
GetUnsent() (read index, ~1 µs)
    ↓
readRecordAt() for each unsent record
    ↓ seek (~100 µs)
    ↓ read (~50 µs per 2KB)
    ↓ unmarshal protobuf (~100 µs)
    ↓ verify CRC64 (~10 µs)
    ↓
Send batch to server (network latency)

Total: ~1ms + network latency per batch
```

### Memory Usage

```
Per job:
  walImpl struct: ~200 bytes
  walIndex: ~40 bytes per record
  Typical job with 1,000 events: 40KB

100 concurrent jobs: ~4MB total (negligible)
```

### Disk Usage

```
Active WAL (per job):
  1,000 events × 2KB = 2MB
  Deleted after job completion (if archiving)

Archives (30 days):
  100 jobs/day × 0.6MB (compressed) × 30 days = 1.8GB
```

## Security Considerations

### File Permissions

WAL files created with mode `0600` (owner read/write only):
```go
file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
```

### Sensitive Data

Job events may contain:
- Command arguments (could include secrets)
- Environment variables (could include API keys)
- Output (could include credentials)

**Mitigation**:
- WAL files protected by OS file permissions
- Archives compressed (not encrypted)
- Retention limited to 30 days

**Future Enhancement**: Optional encryption at rest using age or NaCl

## Dependencies

```go
require (
    github.com/minio/crc64nvme v1.1.1          // CRC64-NVME checksums
    github.com/klauspost/compress v1.18.2      // Zstd compression
    google.golang.org/protobuf                 // Event serialization
    github.com/rs/zerolog                      // Logging
)
```

---

[← README](README.md) | [Phase 1 →](01-phase1-core-wal.md)
