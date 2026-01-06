# Phase 3: Testing and Validation

[← README](README.md) | [← Phase 2](02-phase2-integration.md) | [Operations →](operations-runbook.md)

## Goal

Implement comprehensive tests for the WAL system including unit tests, integration tests, and chaos tests to verify durability guarantees.

**Estimated Duration**: 8-10 hours

## Prerequisites

- Phase 1 and 2 completed
- Worker integrated with WAL
- Understanding of Go testing patterns

## Success Criteria

- [ ] Unit tests cover all WAL components
- [ ] Integration tests verify end-to-end flow
- [ ] Network failure recovery test passes
- [ ] Worker crash recovery test passes
- [ ] Corruption recovery test passes
- [ ] Archive compression test passes
- [ ] Test coverage >80%

## Test Structure

```
internal/worker/wal/
├── wal_test.go              # Unit tests for WAL core
├── file_test.go             # Binary format tests
├── index_test.go            # Index operations tests
├── sender_test.go           # Async sender tests
├── archive_test.go          # Archive/compression tests
└── integration_test.go      # End-to-end integration tests
```

## Unit Tests

### 1. WAL Core Tests (`wal_test.go`)

```go
package wal

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestNewWAL(t *testing.T) {
    walDir := t.TempDir()
    cfg := &WALConfig{WALDir: walDir}

    w, err := NewWAL(cfg, "test-job")
    require.NoError(t, err)
    defer w.Stop(context.Background())

    // Verify file created
    assert.FileExists(t, filepath.Join(walDir, "test-job.wal"))
}

func TestWALAppend(t *testing.T) {
    walDir := t.TempDir()
    cfg := &WALConfig{WALDir: walDir}

    w, err := NewWAL(cfg, "test-job")
    require.NoError(t, err)
    defer w.Stop(context.Background())

    // Append event
    event := &jobv1.JobEvent{
        Sequence:  1,
        EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
    }

    err = w.Append(context.Background(), event)
    require.NoError(t, err)

    // Verify index updated
    impl := w.(*walImpl)
    assert.Equal(t, 1, impl.index.Count())
}

func TestWALReload(t *testing.T) {
    walDir := t.TempDir()
    cfg := &WALConfig{WALDir: walDir}

    // Create WAL and append events
    w1, _ := NewWAL(cfg, "test-job")
    w1.Append(context.Background(), &jobv1.JobEvent{Sequence: 1})
    w1.Append(context.Background(), &jobv1.JobEvent{Sequence: 2})
    w1.Stop(context.Background())

    // Reopen WAL
    w2, err := NewWAL(cfg, "test-job")
    require.NoError(t, err)
    defer w2.Stop(context.Background())

    // Verify events loaded
    impl := w2.(*walImpl)
    assert.Equal(t, 2, impl.index.Count())
}
```

### 2. Binary Format Tests (`file_test.go`)

```go
func TestBuildRecord(t *testing.T) {
    payload := []byte("test event payload")
    record := buildRecord(42, RecordPending, payload)

    // Verify length (excluding length field itself)
    length := binary.LittleEndian.Uint32(record[0:4])
    assert.Equal(t, uint32(28+len(payload)), length)

    // Verify sequence
    sequence := binary.LittleEndian.Int64(record[4:12])
    assert.Equal(t, int64(42), sequence)

    // Verify status
    assert.Equal(t, RecordPending, record[12])

    // Verify CRC64 at end
    crc := binary.LittleEndian.Uint64(record[len(record)-8:])
    assert.NotZero(t, crc)
}

func TestCRC64Validation(t *testing.T) {
    payload := []byte("test")
    record := buildRecord(1, RecordPending, payload)

    // Corrupt the payload
    record[20] ^= 0xFF

    // Try to read - should detect corruption
    walDir := t.TempDir()
    cfg := &WALConfig{WALDir: walDir}
    w, _ := NewWAL(cfg, "test-job")
    impl := w.(*walImpl)

    // Write corrupted record manually
    impl.file.Write(record)
    impl.file.Sync()

    // Try to read - should fail
    _, _, err := impl.readRecordAt(headerSize)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "CRC64 mismatch")
}

func TestLargePayload(t *testing.T) {
    // Test with 200KB payload (max event size)
    payload := make([]byte, 200*1024)
    for i := range payload {
        payload[i] = byte(i % 256)
    }

    record := buildRecord(1, RecordPending, payload)

    // Verify record built correctly
    length := binary.LittleEndian.Uint32(record[0:4])
    assert.Equal(t, uint32(28+len(payload)), length)

    // Verify CRC64 computed (tests SIMD performance)
    crc := binary.LittleEndian.Uint64(record[len(record)-8:])
    assert.NotZero(t, crc)
}
```

### 3. Index Tests (`index_test.go`)

```go
func TestIndexOperations(t *testing.T) {
    idx := newWALIndex()

    // Add records
    idx.Add(walRecord{sequence: 1, status: RecordPending})
    idx.Add(walRecord{sequence: 2, status: RecordPending})
    idx.Add(walRecord{sequence: 3, status: RecordSent})

    // Test counts
    assert.Equal(t, 3, idx.Count())
    assert.Equal(t, 2, idx.CountPending())
    assert.Equal(t, 1, idx.CountSent())

    // Get unsent
    unsent := idx.GetUnsent()
    assert.Len(t, unsent, 2)

    // Mark as sent
    idx.MarkSent(unsent)
    assert.Equal(t, 0, idx.CountPending())
    assert.Equal(t, 3, idx.CountSent())
}
```

## Integration Tests

### 4. End-to-End Integration Test (`integration_test.go`)

```go
func TestWALIntegrationWithMockSender(t *testing.T) {
    walDir := t.TempDir()
    archiveDir := t.TempDir()

    cfg := &WALConfig{
        WALDir:        walDir,
        ArchiveDir:    archiveDir,
        FlushInterval: 50 * time.Millisecond,
        RetryBackoff: BackoffConfig{
            InitialInterval: 50 * time.Millisecond,
            MaxInterval:     500 * time.Millisecond,
            Multiplier:      2.0,
        },
    }

    // Create WAL
    w, err := NewWAL(cfg, "test-job")
    require.NoError(t, err)

    // Mock sender that succeeds
    var sentEvents []*jobv1.JobEvent
    sender := &mockEventSender{
        sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
            sentEvents = append(sentEvents, events...)
            return nil
        },
    }

    // Start async sender
    err = w.Start(context.Background(), sender)
    require.NoError(t, err)

    // Append 100 events
    for i := 0; i < 100; i++ {
        event := &jobv1.JobEvent{
            Sequence:  int64(i + 1),
            EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
        }
        err = w.Append(context.Background(), event)
        require.NoError(t, err)
    }

    // Wait for async sender to process
    time.Sleep(200 * time.Millisecond)

    // Stop WAL
    err = w.Stop(context.Background())
    require.NoError(t, err)

    // Verify all events sent
    assert.Len(t, sentEvents, 100)

    // Archive
    err = w.Archive(context.Background(), archiveDir)
    require.NoError(t, err)

    // Verify archive exists
    archivePath := filepath.Join(archiveDir, "test-job.wal.zst")
    info, err := os.Stat(archivePath)
    require.NoError(t, err)

    // Verify compression (should be smaller than original)
    originalSize := int64(100 * 2048) // Estimate
    assert.Less(t, info.Size(), originalSize)
}
```

### 5. Network Failure Recovery Test

```go
func TestNetworkFailureRecovery(t *testing.T) {
    walDir := t.TempDir()
    cfg := &WALConfig{
        WALDir:        walDir,
        FlushInterval: 50 * time.Millisecond,
    }

    w, _ := NewWAL(cfg, "test-job")

    // Mock sender that fails first 3 times, then succeeds
    attemptCount := 0
    var sentEvents []*jobv1.JobEvent
    sender := &mockEventSender{
        sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
            attemptCount++
            if attemptCount <= 3 {
                return fmt.Errorf("network error")
            }
            sentEvents = append(sentEvents, events...)
            return nil
        },
    }

    w.Start(context.Background(), sender)

    // Append events
    for i := 0; i < 10; i++ {
        w.Append(context.Background(), &jobv1.JobEvent{Sequence: int64(i + 1)})
    }

    // Wait for retries to succeed
    time.Sleep(1 * time.Second)

    w.Stop(context.Background())

    // Verify all events eventually sent
    assert.Len(t, sentEvents, 10)
    assert.Greater(t, attemptCount, 3, "Should have retried")
}
```

### 6. Worker Crash Recovery Test

```go
func TestWorkerCrashRecovery(t *testing.T) {
    walDir := t.TempDir()
    cfg := &WALConfig{WALDir: walDir}

    // Simulate first worker
    w1, _ := NewWAL(cfg, "test-job")

    // Append events but DON'T start sender (simulate crash before send)
    for i := 0; i < 10; i++ {
        w1.Append(context.Background(), &jobv1.JobEvent{Sequence: int64(i + 1)})
    }

    // DON'T call Stop() - simulate crash
    w1.(*walImpl).file.Close()

    // Simulate second worker (restart)
    w2, err := NewWAL(cfg, "test-job")
    require.NoError(t, err)

    // Verify unsent events loaded
    impl := w2.(*walImpl)
    assert.Equal(t, 10, impl.index.CountPending())

    // Start sender
    var sentEvents []*jobv1.JobEvent
    sender := &mockEventSender{
        sendFunc: func(ctx context.Context, events []*jobv1.JobEvent) error {
            sentEvents = append(sentEvents, events...)
            return nil
        },
    }

    w2.Start(context.Background(), sender)
    time.Sleep(200 * time.Millisecond)
    w2.Stop(context.Background())

    // Verify events replayed
    assert.Len(t, sentEvents, 10)
}
```

## Chaos Tests

### 7. SIGKILL During Send

**Manual test** (run in terminal):

```bash
#!/bin/bash
# Test worker crash during event send

# Start worker in background
./bin/airunner-cli worker --server=https://localhost:8080 &
WORKER_PID=$!

# Submit job
./bin/airunner-cli submit https://github.com/example/repo

# Wait 2 seconds (job starts executing)
sleep 2

# Kill worker with SIGKILL (no cleanup)
kill -9 $WORKER_PID

# Restart worker
./bin/airunner-cli worker --server=https://localhost:8080 &

# Wait for recovery
sleep 5

# Check logs for "Loaded WAL index" and "pending_events>0"
grep "Loaded WAL index" ~/.airunner/logs/worker.log

# Verify events replayed
grep "Successfully sent records" ~/.airunner/logs/worker.log
```

### 8. Disk Full Test

```go
func TestDiskFullHandling(t *testing.T) {
    // Create small RAM disk (1MB)
    // (Platform-specific - Linux example)
    if runtime.GOOS != "linux" {
        t.Skip("Disk full test requires Linux")
    }

    tmpDir := "/tmp/ramdisk-test"
    os.MkdirAll(tmpDir, 0755)
    defer os.RemoveAll(tmpDir)

    // Mount 1MB ramdisk
    cmd := exec.Command("mount", "-t", "tmpfs", "-o", "size=1M", "tmpfs", tmpDir)
    err := cmd.Run()
    if err != nil {
        t.Skip("Could not mount ramdisk (requires sudo)")
    }
    defer exec.Command("umount", tmpDir).Run()

    cfg := &WALConfig{WALDir: tmpDir}
    w, _ := NewWAL(cfg, "test-job")

    // Try to append large events until disk full
    largePayload := make([]byte, 100*1024) // 100KB per event

    var appendErr error
    for i := 0; i < 100; i++ {
        event := &jobv1.JobEvent{
            Sequence: int64(i + 1),
            EventData: &jobv1.JobEvent_OutputBatch{
                OutputBatch: &jobv1.OutputBatchEvent{
                    Outputs: []*jobv1.OutputItem{{Output: largePayload}},
                },
            },
        }
        appendErr = w.Append(context.Background(), event)
        if appendErr != nil {
            break // Disk full expected
        }
    }

    // Verify error is about disk space
    assert.Error(t, appendErr)
    assert.Contains(t, appendErr.Error(), "no space")
}
```

## Performance Tests

### 9. Fsync Latency Benchmark

```go
func BenchmarkWALAppend(b *testing.B) {
    walDir := b.TempDir()
    cfg := &WALConfig{WALDir: walDir}
    w, _ := NewWAL(cfg, "bench-job")
    defer w.Stop(context.Background())

    event := &jobv1.JobEvent{
        Sequence:  1,
        EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        event.Sequence = int64(i + 1)
        w.Append(context.Background(), event)
    }
}

// Expected: ~5ms per append (fsync dominated)
```

### 10. CRC64 Performance Benchmark

```go
func BenchmarkCRC64Computation(b *testing.B) {
    sizes := []int{1024, 10 * 1024, 100 * 1024, 200 * 1024}

    for _, size := range sizes {
        b.Run(fmt.Sprintf("%dKB", size/1024), func(b *testing.B) {
            data := make([]byte, size)
            rand.Read(data)

            b.ResetTimer()
            b.SetBytes(int64(size))

            for i := 0; i < b.N; i++ {
                computeCRC64(data)
            }
        })
    }
}

// Expected with SIMD:
// 1KB:   ~1 µs   (~1 GB/s)
// 10KB:  ~5 µs   (~2 GB/s)
// 100KB: ~20 µs  (~5 GB/s)
// 200KB: ~20 µs  (~10 GB/s with AVX-512)
```

## Running All Tests

```bash
# Unit tests
go test -v ./internal/worker/wal/...

# Integration tests
go test -v -run Integration ./internal/worker/wal/...

# Benchmarks
go test -bench=. -benchmem ./internal/worker/wal/...

# Coverage report
go test -coverprofile=coverage.out ./internal/worker/wal/...
go tool cover -html=coverage.out
```

## CI/CD Integration

**GitHub Actions example**:

```yaml
name: WAL Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run WAL tests
        run: |
          go test -v -race -coverprofile=coverage.out ./internal/worker/wal/...

      - name: Check coverage
        run: |
          go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | \
          awk '{if ($1 < 80) exit 1}'

      - name: Run benchmarks
        run: |
          go test -bench=. -benchmem ./internal/worker/wal/...
```

## Next Steps

Proceed to [Operations Runbook](operations-runbook.md) for monitoring and troubleshooting guidance.

---

[← README](README.md) | [← Phase 2](02-phase2-integration.md) | [Operations →](operations-runbook.md)
