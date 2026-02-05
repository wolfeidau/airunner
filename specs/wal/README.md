# Write-Ahead Log (WAL) Event Persistence

[Architecture](00-architecture.md) | [Phase 1 →](01-phase1-core-wal.md)

## Overview

This specification covers the implementation of a Write-Ahead Log (WAL) system for durable event persistence in airunner workers. The WAL ensures zero data loss during network failures by persisting events to disk before acknowledgment and asynchronously retrying failed sends until success.

**Problem Statement**: Workers currently lose job output events when network failures occur during event publishing. Stream closure errors are logged but don't prevent job completion, resulting in jobs marked as COMPLETED even though output events were never persisted to the server.

**Solution**: Implement a WAL that durably persists events to disk with fsync before acknowledging success, then asynchronously retries failed sends with exponential backoff until the server confirms receipt.

## Prerequisites

- Go 1.21+
- Understanding of Write-Ahead Logs and durability guarantees
- Familiarity with `internal/worker/event_batcher.go` batching logic
- Understanding of Connect RPC streaming clients
- Knowledge of protobuf serialization and binary file formats

## Quick Start

1. Read [Architecture](00-architecture.md) for design decisions, file format, and integration points
2. Implement [Phase 1: Core WAL Package](01-phase1-core-wal.md) - WAL interface, file format, async sender
3. Implement [Phase 2: Worker Integration](02-phase2-integration.md) - Integrate WAL into worker command
4. Implement [Phase 3: Testing & Validation](03-phase3-testing.md) - Unit tests, integration tests, chaos testing
5. Review [Operations Runbook](operations-runbook.md) for monitoring and debugging

## File Navigation

| File | Purpose | Estimated Duration |
|------|---------|-------------------|
| [00-architecture.md](00-architecture.md) | Design decisions, file format spec, diagrams | Reference |
| [01-phase1-core-wal.md](01-phase1-core-wal.md) | Core WAL package implementation | 16-20 hours |
| [02-phase2-integration.md](02-phase2-integration.md) | Worker integration and configuration | 4-6 hours |
| [03-phase3-testing.md](03-phase3-testing.md) | Testing strategy and validation | 8-10 hours |
| [operations-runbook.md](operations-runbook.md) | Monitoring, troubleshooting, debugging | Reference |

## Architecture Overview

### Current Event Flow (BEFORE)

```
Job Execution
    ↓
EventBatcher (buffers up to 50 items or 256KB)
    ↓
onFlush callback → eventStream.Send()  ← FAILURE POINT
    ↓
Server: PublishJobEvents() → PostgreSQL

Problem: If stream.Send() fails, events are lost
```

### Proposed Event Flow (AFTER)

```
Job Execution
    ↓
EventBatcher (buffers up to 50 items or 256KB)
    ↓
WAL.Append() [SYNC with fsync] ← NEW: Durability guarantee
    ↓
[WAL File on Disk] ← Survives worker crashes
    ↓
AsyncSender (background goroutine) ← NEW: Retry logic
    ↓
eventStream.Send() with exponential backoff
    ↓
Server: PublishJobEvents() → PostgreSQL
    ↓
AsyncSender marks WAL record as SENT

On worker restart: Replay PENDING records from WAL
```

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Durability** | Fsync after every event | Zero data loss on crash (~5% overhead acceptable) |
| **Retention** | 30-day archive | Balance of debugging utility and disk usage (~1.8GB/100 jobs compressed) |
| **File Format** | Binary length-prefixed protobuf | Efficient, self-describing, CRC64-NVME validated |
| **Checksum** | CRC64-NVME (MinIO library) | Hardware-accelerated, stronger corruption detection (2^64 vs 2^32) |
| **Compression** | Zstd level 3 for archives only | 70% space savings, fast decompression, active WAL stays uncompressed |
| **Retry Policy** | Infinite with exponential backoff | Never give up on transient failures (1s → 60s max) |
| **Rollout** | Always enabled | Mandatory for all workers (no feature flag) |
| **Integration Point** | Between EventBatcher and stream | Minimal changes, transparent to execution logic |

## Files to Create

### Core WAL Package (`internal/worker/wal/`)

| File | Purpose | Lines |
|------|---------|-------|
| `wal.go` | WAL interface and main implementation | ~350 |
| `file.go` | Binary file format (header, records, CRC32) | ~200 |
| `sender.go` | Async sender with retry logic | ~250 |
| `index.go` | In-memory index for sent/unsent tracking | ~150 |
| `archive.go` | Archive and cleanup utilities | ~100 |
| `wal_test.go` | Unit tests | ~400 |
| `integration_test.go` | Integration tests | ~300 |

### Integration Points

| File | Changes | Purpose |
|------|---------|---------|
| `cmd/cli/internal/commands/worker.go` | +80 lines | WAL creation, lifecycle, integration |
| `cmd/cli/internal/commands/types.go` | +5 lines | WAL configuration in Globals |
| `internal/telemetry/metrics.go` | +15 lines | WAL metrics (appends, retries, failures) |

### Examples

| File | Purpose |
|------|---------|
| `examples/wal/wal_interface.go` | WAL and EventSender interfaces |
| `examples/wal/file_format.go` | Binary file format specification |
| `examples/wal/sender_example.go` | Async sender pattern |
| `examples/integration/worker_integration.go` | Worker integration example |

## Success Criteria

- [ ] Zero "unexpected EOF" errors result in data loss
- [ ] 30-second network outages recover automatically (events replayed from WAL)
- [ ] Worker crashes during send replay unsent events on restart
- [ ] <5% performance overhead on happy path (fsync latency)
- [ ] Archive cleanup maintains 30-day retention
- [ ] WAL metrics visible in telemetry dashboard (appends, retries, failures)
- [ ] All unit tests passing (WAL operations, file format, index)
- [ ] All integration tests passing (network failure, crash recovery, corruption)
- [ ] Chaos tests pass (SIGKILL during send, disk full, WAL corruption)

## Performance Impact

### Happy Path Overhead

- **Fsync latency**: 5ms per event on SSD
- **Typical job**: 10 events/sec = 50ms/sec = **5% overhead**
- **Memory**: 40 bytes per event × 1,000 events = 40KB per job (negligible)

### Disk Space Requirements

**Without compression**:
- Per job: ~2 MB (1,000 events × 2KB average)
- 30-day archive: 100 jobs/day × 2 MB × 30 days = 6 GB

**With zstd compression (level 3)**:
- Per job compressed: ~0.6 MB (70% reduction)
- 30-day archive: 100 jobs/day × 0.6 MB × 30 days = **1.8 GB**
- **Savings**: 4.2 GB (70% reduction)

**Recommendation**: Zstd compression reduces storage requirements significantly while maintaining fast decompression

## Rollout Plan

The WAL will be **always enabled** (mandatory for all workers immediately).

### Pre-deployment Checklist

- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Chaos tests completed (kill worker, corrupt WAL, network partition)
- [ ] Performance benchmarks showing <5% overhead
- [ ] Disk space monitoring configured
- [ ] Archive cleanup tested with old files

### Deployment Steps

1. Deploy updated `airunner-cli` binary to all workers
2. Workers will create `~/.airunner/wal/` directory on first job
3. Monitor metrics for WAL operation (appends, retries, failures)
4. Verify no "Failed to close event stream" errors result in data loss
5. After 30 days, verify archive cleanup is working

### Rollback Plan

If critical issues are discovered:

- Revert to previous `airunner-cli` binary
- WAL files will remain on disk (no data loss)
- Can manually replay events using `airunner-cli wal replay` tool (future enhancement)

## Related Documentation

- [EventBatcher Design](../../internal/worker/event_batcher.go) - Event batching and buffering
- [Worker Command](../../cmd/cli/internal/commands/worker.go) - Worker job execution loop
- [Job Events Service](../../internal/server/job_event.go) - Server-side event publishing

## Future Enhancements (Post-MVP)

1. **CLI inspection tools**:
   ```bash
   airunner-cli wal dump <job-id>.wal.zst           # Decompress and dump
   airunner-cli wal replay <job-id>.wal.zst --server=https://...
   airunner-cli wal cleanup --older-than=30d
   airunner-cli wal stats                            # Show archive stats
   ```

2. **Remote sync**: Optional sync of archived WALs to S3/GCS for centralized debugging

3. **Batch fsync optimization**: Group fsyncs every 100ms (<1% overhead but risks 100ms of events on crash)

4. **Compression level tuning**: Allow configuring zstd level (1-19) based on disk space vs CPU trade-off

---

[Architecture](00-architecture.md) | [Phase 1 →](01-phase1-core-wal.md)
