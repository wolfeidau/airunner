# WAL Operations Runbook

[← README](README.md) | [← Phase 3](03-phase3-testing.md) | [Architecture](00-architecture.md)

## Overview

This runbook provides operational guidance for monitoring, troubleshooting, and maintaining the WAL system in production.

## Monitoring

### Key Metrics

Monitor these metrics for WAL health:

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `wal.appends.total` | Total WAL appends | N/A (counter) |
| `wal.append.duration` | Append latency (ms) | p99 > 10ms |
| `wal.pending.events` | Unsent events in WAL | > 1000 for >5min |
| `wal.retries.total` | Retry attempts | Rate > 10/sec |
| `wal.failures.total` | Failed after retries | > 0 |
| `wal.archive.size.bytes` | Archive directory size | > 90% disk |

### Health Checks

**WAL Directory Size**:
```bash
du -sh ~/.airunner/wal/
```

**Archive Directory Size**:
```bash
du -sh ~/.airunner/archive/
```

**Pending Events Count**:
```bash
# Count .wal files (each is a job with pending events)
ls -1 ~/.airunner/wal/*.wal 2>/dev/null | wc -l
```

**Compression Ratio**:
```bash
# Check recent archives
ls -lh ~/.airunner/archive/ | tail -5
```

## Common Issues

### 1. High Append Latency

**Symptoms**:
- `wal.append.duration` p99 > 10ms
- Jobs taking longer than expected

**Diagnosis**:
```bash
# Check disk I/O
iostat -x 1 5

# Check disk latency
sudo iotop -o

# Check filesystem type
df -T ~/.airunner/wal/
```

**Causes**:
- Slow disk (HDD instead of SSD)
- Disk nearly full (>90%)
- I/O congestion

**Resolution**:
```bash
# Move WAL to faster disk
mkdir -p /mnt/ssd/airunner/wal
ln -s /mnt/ssd/airunner/wal ~/.airunner/wal

# Clean up old archives
find ~/.airunner/archive/ -name '*.wal.zst' -mtime +30 -delete
```

### 2. Pending Events Not Sending

**Symptoms**:
- `wal.pending.events` stays high
- `wal.retries.total` increasing
- Jobs complete but events missing in UI

**Diagnosis**:
```bash
# Check worker logs
tail -f ~/.airunner/logs/worker.log | grep -E "Failed to send|retrying"

# Check network connectivity
curl -v https://api.example.com/health

# Check for rate limiting
grep "429" ~/.airunner/logs/worker.log
```

**Resolution**:
```bash
# If network issue - wait for recovery
# WAL will automatically retry

# If rate limiting - adjust retry backoff
# Edit worker config to increase initial interval

# If permanent failure - manual replay needed
# (see Manual Event Replay section)
```

### 3. Disk Full

**Symptoms**:
- `wal.append` failures
- Error logs: "no space left on device"
- Jobs failing immediately

**Diagnosis**:
```bash
df -h ~/.airunner/

# Check which directory is large
du -sh ~/.airunner/*
```

**Resolution**:
```bash
# Emergency: Delete oldest archives
find ~/.airunner/archive/ -name '*.wal.zst' -mtime +7 -delete

# Long-term: Increase retention cleanup frequency
# or move to larger disk
```

### 4. Corrupt WAL Files

**Symptoms**:
- Error logs: "CRC64 mismatch"
- Worker crashes on startup
- Events missing

**Diagnosis**:
```bash
# Check WAL file
hexdump -C ~/.airunner/wal/<job-id>.wal | head -n 5

# Should see "ARWAL001" at start
# If not, file is corrupt
```

**Resolution**:
```bash
# WAL automatically truncates at corruption point
# Events after corruption are lost

# If critical, attempt manual recovery:
# 1. Backup corrupt file
cp ~/.airunner/wal/<job-id>.wal /tmp/backup.wal

# 2. Try to read valid records manually
# (custom tool needed - see Manual Recovery section)
```

### 5. Archive Cleanup Not Running

**Symptoms**:
- Archive directory growing indefinitely
- Disk usage increasing

**Diagnosis**:
```bash
# Check oldest archive
ls -lt ~/.airunner/archive/ | tail -5

# Check if cleanup is configured
grep "RetentionDays" ~/.airunner/config.yaml
```

**Resolution**:
```bash
# Manual cleanup
./bin/airunner-cli wal cleanup --older-than=30d

# Or with find
find ~/.airunner/archive/ -name '*.wal.zst' -mtime +30 -delete
```

## Troubleshooting Procedures

### Debug Logging

Enable debug logging for WAL:

```bash
# Set log level
export AIRUNNER_LOG_LEVEL=debug

# Run worker
./bin/airunner-cli worker --server=https://...
```

Look for:
```
DBG WAL created job_id=...
DBG Appending record sequence=... offset=...
DBG Flushing output batch start_seq=... end_seq=...
DBG Attempting to send unsent records unsent_count=...
DBG Successfully sent records count=...
```

### Inspect WAL File

**Dump header**:
```bash
hexdump -C ~/.airunner/wal/<job-id>.wal | head -n 2
```

Expected output:
```
00000000  41 52 57 41 4c 30 30 31  01 00 00 00 00 00 00 00  |ARWAL001........|
         ^^^^^^^^^^^^^^^^^^^^^^^^^
         "ARWAL001" magic
```

**Count records**:
```bash
# Estimate: (file_size - 16) / avg_record_size
FILE_SIZE=$(stat -f%z ~/.airunner/wal/<job-id>.wal)
echo "$(( ($FILE_SIZE - 16) / 2048 )) records (estimate)"
```

### Inspect Archive

**Decompress archive**:
```bash
zstd -d ~/.airunner/archive/<job-id>.wal.zst -o /tmp/decompressed.wal
```

**Check compression ratio**:
```bash
zstd -l ~/.airunner/archive/<job-id>.wal.zst
```

Example output:
```
Compressed Size: 600 KB
Decompressed Size: 2000 KB
Ratio: 30.0% (70% reduction)
```

### Network Failure Simulation

**Test retry logic**:

Terminal 1 - Start worker:
```bash
./bin/airunner-cli worker --server=https://localhost:8080
```

Terminal 2 - Block network:
```bash
# macOS
echo "block drop proto tcp to any port 8080" | sudo pfctl -f -

# Linux (iptables)
sudo iptables -A OUTPUT -p tcp --dport 8080 -j DROP

# Wait 30 seconds

# Unblock
sudo pfctl -d  # macOS
sudo iptables -F  # Linux
```

**Verify**:
- Worker logs show "Failed to send events - retrying"
- After unblock: "Successfully sent records"
- Events appear in UI with correct sequence

## Manual Operations

### Manual Event Replay

If events are stuck in FAILED status:

```bash
# 1. Stop worker
pkill airunner-cli

# 2. Find failed WAL files
ls -lh ~/.airunner/wal/

# 3. Use manual replay tool (future enhancement)
./bin/airunner-cli wal replay <job-id>.wal --server=https://...
```

### Force Archive Cleanup

```bash
# Delete all archives older than 7 days
find ~/.airunner/archive/ -name '*.wal.zst' -mtime +7 -exec rm {} \;

# Verify
ls -lh ~/.airunner/archive/
```

### Recover Disk Space

```bash
# 1. Stop worker
pkill airunner-cli

# 2. Archive all active WAL files
for wal in ~/.airunner/wal/*.wal; do
    job_id=$(basename "$wal" .wal)
    zstd "$wal" -o ~/.airunner/archive/"$job_id".wal.zst
    rm "$wal"
done

# 3. Restart worker
./bin/airunner-cli worker --server=https://...
```

### Migrate WAL Directory

```bash
# 1. Stop worker
pkill airunner-cli

# 2. Copy WAL files to new location
cp -r ~/.airunner/wal /mnt/ssd/airunner/wal
cp -r ~/.airunner/archive /mnt/ssd/airunner/archive

# 3. Update symlinks
rm -rf ~/.airunner/wal ~/.airunner/archive
ln -s /mnt/ssd/airunner/wal ~/.airunner/wal
ln -s /mnt/ssd/airunner/archive ~/.airunner/archive

# 4. Restart worker
./bin/airunner-cli worker --server=https://...
```

## Performance Tuning

### Reduce Fsync Latency

**Option 1: Use faster disk**
- Move WAL to NVMe SSD
- Expected: 5ms → 1ms fsync latency

**Option 2: Batch fsync (NOT RECOMMENDED)**
- Risks losing 100ms of events on crash
- Only for non-critical environments

### Adjust Retry Backoff

If experiencing server rate limiting:

```go
// Increase initial interval
RetryBackoff: BackoffConfig{
    InitialInterval: 5 * time.Second,  // Was 1s
    MaxInterval:     120 * time.Second, // Was 60s
    Multiplier:      2.0,
}
```

### Tune Compression Level

For CPU-constrained workers:

```go
// Use faster compression (less CPU, larger files)
enc, _ := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedFastest))
```

For disk-constrained workers:

```go
// Use better compression (more CPU, smaller files)
enc, _ := zstd.NewWriter(dst, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
```

## Monitoring Dashboard

**Grafana Dashboard Example**:

```yaml
panels:
  - title: "WAL Append Latency"
    metric: wal.append.duration
    visualization: time_series
    thresholds:
      - value: 10
        color: yellow
      - value: 20
        color: red

  - title: "Pending Events"
    metric: wal.pending.events
    visualization: gauge
    thresholds:
      - value: 100
        color: green
      - value: 1000
        color: yellow
      - value: 10000
        color: red

  - title: "Retry Rate"
    metric: rate(wal.retries.total[5m])
    visualization: graph

  - title: "Archive Size"
    metric: wal.archive.size.bytes
    visualization: gauge
    thresholds:
      - value: 5_000_000_000  # 5GB
        color: green
      - value: 10_000_000_000 # 10GB
        color: yellow
      - value: 20_000_000_000 # 20GB
        color: red
```

## Alert Rules

**Prometheus Alert Rules**:

```yaml
groups:
  - name: wal_alerts
    rules:
      - alert: WALHighLatency
        expr: histogram_quantile(0.99, wal_append_duration_seconds) > 0.01
        for: 5m
        annotations:
          summary: "WAL append latency is high"
          description: "p99 latency {{ $value }}s > 10ms"

      - alert: WALPendingEvents
        expr: wal_pending_events > 1000
        for: 5m
        annotations:
          summary: "Many pending events in WAL"
          description: "{{ $value }} events not sent"

      - alert: WALDiskFull
        expr: (wal_archive_size_bytes / disk_total_bytes) > 0.9
        for: 1m
        annotations:
          summary: "WAL archive disk nearly full"
          description: "{{ $value | humanizePercentage }} used"

      - alert: WALFailedEvents
        expr: increase(wal_failures_total[5m]) > 0
        annotations:
          summary: "Events failed after all retries"
          description: "{{ $value }} events permanently failed"
```

## Backup and Recovery

### Backup Strategy

**Option 1: Include in worker backup**
```bash
# Backup WAL and archive directories
tar -czf worker-backup.tar.gz ~/.airunner/wal ~/.airunner/archive

# Upload to S3
aws s3 cp worker-backup.tar.gz s3://backups/airunner/$(date +%Y%m%d)/
```

**Option 2: Continuous sync**
```bash
# Rsync archives to central storage
rsync -avz ~/.airunner/archive/ backup-server:/mnt/airunner-archives/
```

### Disaster Recovery

**Scenario**: Worker machine lost, need to recover events

1. **Restore archives**:
```bash
aws s3 sync s3://backups/airunner/latest/ ~/.airunner/archive/
```

2. **Decompress needed archives**:
```bash
for archive in ~/.airunner/archive/*.wal.zst; do
    zstd -d "$archive" -o ~/.airunner/wal/$(basename "$archive" .zst)
done
```

3. **Replay events**:
```bash
./bin/airunner-cli wal replay --all --server=https://...
```

## Related Documentation

- [README](README.md) - WAL overview and quick start
- [Architecture](00-architecture.md) - Design decisions and file format
- [Phase 1](01-phase1-core-wal.md) - Core implementation
- [Phase 2](02-phase2-integration.md) - Worker integration
- [Phase 3](03-phase3-testing.md) - Testing strategy

---

[← README](README.md) | [← Phase 3](03-phase3-testing.md) | [Architecture](00-architecture.md)
