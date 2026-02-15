# WAL Execution Isolation Problem

## Problem Statement

The current WAL implementation has a critical design flaw for CI worker scenarios: WAL files are keyed by **job ID only**, which causes events from different executions of the same job to be mixed together when a job is retried.

**Discovery Context**: Found during code review discussion on 2026-01-07 when analyzing worker restart behavior.

## Current Incorrect Behavior

### Scenario: Job Retry After Worker Crash

```
Timeline:
1. Worker dequeues job-123 (execution #1)
   - Creates WAL file: ~/.airunner/wal/job-123.wal
   - Job starts executing, writes 50 events to WAL

2. Worker crashes (OOM kill, network partition, etc.)
   - WAL file remains on disk with 50 events (PENDING status)
   - Job visibility timeout expires

3. Job-123 re-queued by server (execution #2)
   - Different worker (or same worker restarted) picks up job-123
   - Calls NewWAL("job-123")
   - ❌ WRONG: Finds old job-123.wal from execution #1
   - ❌ WRONG: Loads 50 old events and marks them PENDING
   - ❌ WRONG: New execution starts, writes fresh events
   - ❌ WRONG: Async sender uploads MIXED events from execution #1 + #2
```

### Code References

**WAL creation** (`cmd/cli/internal/commands/worker.go:146`):
```go
jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId)  // ❌ Uses job ID only
```

**WAL file path** (`internal/worker/wal/wal.go:138`):
```go
walPath: filepath.Join(cfg.WALDir, fmt.Sprintf("%s.wal", jobID)),  // ❌ Not unique per execution
```

**Recovery logic** (`internal/worker/wal/wal.go:158-189`):
```go
func (w *walImpl) openOrCreate() error {
    fileExists := false
    if _, err := os.Stat(w.walPath); err == nil {
        fileExists = true  // ❌ Finds old WAL from previous execution
    }

    if !fileExists {
        // New file - write header
    } else {
        // ❌ Loads old index from crashed execution
        if err := w.loadIndex(); err != nil {
            return fmt.Errorf("failed to load index: %w", err)
        }
    }
}
```

## Correct Behavior for CI Workers

CI jobs are **ephemeral and stateless**. Each execution should be completely isolated:

1. ✅ **Fresh execution = fresh WAL**: Job retry starts with clean state
2. ✅ **Zero data loss**: Old WAL from crashed execution still uploads its events
3. ✅ **No event mixing**: Events from execution #1 never mix with execution #2
4. ✅ **Server receives all events**: Both executions' events reach the server (server deduplicates if needed)

### Expected Timeline

```
Timeline:
1. Worker dequeues job-123 (execution #1, task-token-abc)
   - Creates WAL: ~/.airunner/wal/job-123_abc.wal
   - Job crashes after writing 50 events

2. Background process OR next worker startup:
   - Discovers orphaned WAL: job-123_abc.wal
   - Uploads remaining PENDING events from execution #1
   - Archives/deletes WAL after successful upload

3. Job-123 re-queued (execution #2, task-token-xyz)
   - Worker dequeues with NEW task token
   - Creates fresh WAL: ~/.airunner/wal/job-123_xyz.wal
   - ✅ CORRECT: Clean state, no old events
```

## Design Options

### Option A: Task Token in Filename ⭐ **RECOMMENDED**

**Description**: Use the task token (unique per job dequeue) in the WAL filename.

**Implementation**:
```go
// worker.go:146
jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId, taskToken)

// wal.go:138
walPath: filepath.Join(cfg.WALDir, fmt.Sprintf("%s_%s.wal", jobID, sanitize(taskToken))),
```

**WAL filenames**:
```
~/.airunner/wal/job-123_dGFzay10b2tlbi1hYmM.wal  (execution #1)
~/.airunner/wal/job-123_dGFzay10b2tlbi14eXo.wal  (execution #2)
```

**Orphaned WAL handling** (use BOTH approaches):
1. **Worker startup scan** (blocking, critical for previous session recovery):
   ```go
   // BEFORE entering job processing loop
   // Uploads WALs orphaned from PREVIOUS worker sessions
   log.Info().Msg("Scanning for orphaned WAL files from previous sessions...")
   if err := wal.UploadOrphanedWALs(ctx, walDir, clients); err != nil {
       log.Error().Err(err).Msg("Failed to upload orphaned WALs during startup")
       // Don't fail startup, just log
   }
   ```

2. **Background goroutine** (continuous, handles crashes during current session):
   ```go
   // In worker.Run(), AFTER startup scan
   // Uploads WALs orphaned during CURRENT worker session (if worker crashes mid-job)
   go func() {
       ticker := time.NewTicker(5 * time.Minute)
       defer ticker.Stop()
       for {
           select {
           case <-ctx.Done():
               return
           case <-ticker.C:
               if err := wal.UploadOrphanedWALs(ctx, walDir, clients); err != nil {
                   log.Warn().Err(err).Msg("Background orphan scan failed")
               }
           }
       }
   }()
   ```

**Cleanup strategy**:
- Delete WAL after successful upload
- Keep failed WALs for 7 days for manual debugging
- Archive cleanup runs every 30 days

**Pros**:
- ✅ Task token already exists, no new data needed
- ✅ Guaranteed unique per execution
- ✅ HMAC-signed token prevents tampering
- ✅ Server can correlate events with execution via task token

**Cons**:
- ❌ Task token is base64-encoded (long filenames: ~50-70 chars, mitigated with hash-based sanitization)
- ❌ Need to sanitize task token for filesystem safety (URL-safe base64 + length limits)
- ❌ Need to handle orphaned WAL upload logic (requires minor server-side changes)

**Security note**: Task token contains job ID and receipt handle, but is HMAC-signed and time-limited (visibility timeout).

---

### Option B: Timestamp in Filename

**Description**: Use ISO8601 timestamp at job start.

**Implementation**:
```go
timestamp := time.Now().Format("20060102T150405")
walPath := filepath.Join(cfg.WALDir, fmt.Sprintf("%s_%s.wal", jobID, timestamp))
```

**WAL filenames**:
```
~/.airunner/wal/job-123_20260107T040900.wal
~/.airunner/wal/job-123_20260107T041530.wal
```

**Pros**:
- ✅ Human-readable filenames
- ✅ Easy to sort by execution time
- ✅ No sanitization needed

**Cons**:
- ❌ **Clock skew risk**: Two workers with misaligned clocks could create same filename
- ❌ **Collision on retry**: Fast retry (<1 second) could reuse same timestamp
- ❌ Server cannot correlate events with execution (timestamp != task token)
- ❌ Need to handle orphaned WAL upload logic

---

### Option C: Execution Counter from Server

**Description**: Server tracks execution count, passes it in job metadata.

**Implementation**:
```go
// Server adds to Job proto
message Job {
    string job_id = 1;
    int32 execution_number = 10;  // NEW: 1, 2, 3, ...
}

// Worker uses it
walPath := filepath.Join(cfg.WALDir, fmt.Sprintf("%s_exec%d.wal", job.JobId, job.ExecutionNumber))
```

**WAL filenames**:
```
~/.airunner/wal/job-123_exec1.wal
~/.airunner/wal/job-123_exec2.wal
```

**Pros**:
- ✅ Short, clean filenames
- ✅ Guaranteed unique
- ✅ Easy to understand execution sequence

**Cons**:
- ❌ **Requires server-side changes**: DB schema migration, job store updates
- ❌ **Larger scope**: 3-4 packages affected (proto, server, store, worker)
- ❌ Need to handle orphaned WAL upload logic
- ❌ More complex deployment (requires server + worker rollout coordination)

---

### Option D: No Recovery, Delete Old WAL ⚠️ **DATA LOSS**

**Description**: On worker startup, delete any existing WAL for the job ID.

**Implementation**:
```go
// worker.go:146
walPath := filepath.Join(cfg.WALDir, fmt.Sprintf("%s.wal", job.JobId))
os.Remove(walPath)  // Delete old WAL if exists
jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId)
```

**Pros**:
- ✅ Simplest implementation (no code changes needed)
- ✅ No orphaned WAL handling logic

**Cons**:
- ❌ **DATA LOSS**: Events from crashed execution are permanently lost
- ❌ **Defeats WAL purpose**: Zero-data-loss guarantee broken
- ❌ **Not acceptable for production**: Violates durability requirements

---

## Recommendation: Option A (Task Token)

**Rationale**:

1. **Minimal server-side changes**: Only requires optional proto field for orphaned event handling
2. **Guaranteed uniqueness**: Task token is unique per dequeue operation
3. **Existing data**: No new fields needed, task token already available
4. **Auditability**: Server logs can correlate events with task token
5. **Acceptable trade-offs**: Longer filenames and sanitization are minor compared to data loss
6. **Robust recovery**: Both startup and background scanning ensures no events lost

**Implementation complexity**: Medium (10-14 hours total)
- Modify `NewWAL()` signature to accept task token (3-4 hours)
- Add filename sanitization helper with hash-based length limiting
- Implement orphaned WAL scanner and uploader (4-6 hours)
- Add server-side support for orphaned event upload (1-2 hours)
- Update tests and integration testing (3-4 hours)

**Deployment risk**: Low
- Backward compatible (old WAL files without token remain, get uploaded on next scan)
- Minor proto addition (optional `source` field)
- Server change is backward compatible (task token still works normally)
- Gradual rollout safe

## Implementation Plan

### Phase 1: Add Task Token to WAL Filename (3-4 hours)

**Changes**:

1. **Update NewWAL signature** (`internal/worker/wal/wal.go:117`):
```go
func NewWAL(cfg *WALConfig, jobID string, taskToken string) (WAL, error) {
    // Sanitize task token for filesystem
    safeToken := sanitizeForFilename(taskToken)

    walPath := filepath.Join(cfg.WALDir, fmt.Sprintf("%s_%s.wal", jobID, safeToken))
    // ... rest of implementation
}

func sanitizeForFilename(token string) string {
    // Task tokens are base64-encoded and may contain /, +, =
    // Use URL-safe base64 encoding replacements
    safe := strings.NewReplacer(
        "/", "-",
        "+", "_",
        "=", "",
    ).Replace(token)

    // Limit length to avoid filesystem limits (255 chars on most systems)
    // If token is too long, hash to fixed 22-character string
    if len(safe) > 200 {
        h := sha256.Sum256([]byte(token))
        return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h[:16])
    }

    return safe
}
```

2. **Update worker command** (`cmd/cli/internal/commands/worker.go:146`):
```go
jobWAL, err := wal.NewWAL(wal.DefaultConfig(), job.JobId, taskToken)
```

3. **Update all tests** to pass task token parameter.

**Success criteria**:
- [ ] WAL files created with format: `{job-id}_{sanitized-token}.wal`
- [ ] Multiple executions of same job create separate WAL files
- [ ] Long tokens (>200 chars) are hashed to 22-character strings
- [ ] Token sanitization handles `/`, `+`, `=` characters
- [ ] All tests passing

---

### Phase 2: Server-Side Support for Orphaned Events (1-2 hours)

**Problem**: Orphaned WAL files have expired task tokens that fail HMAC validation.

**Solution**: Allow orphaned event upload using job ID + source tag instead of task token.

**Changes**:

1. **Update proto** (`api/job/v1/job.proto`):
```protobuf
message PublishJobEventsRequest {
    string task_token = 1;
    repeated JobEvent events = 2;

    // NEW: Optional fields for orphaned WAL recovery
    string job_id = 3;  // Used when task_token is empty (orphaned recovery)
    string source = 4;  // Tag: "orphaned-wal-recovery" vs "" (normal execution)
}
```

2. **Update server** (`internal/server/job_event.go:~30-60`):
```go
func (s *jobEventsService) PublishJobEvents(
    ctx context.Context,
    stream *connect.BidiStream[jobv1.PublishJobEventsRequest, jobv1.PublishJobEventsResponse],
) error {
    // First message establishes identity
    req, err := stream.Receive()
    if err != nil {
        return fmt.Errorf("failed to receive initial request: %w", err)
    }

    var jobID string
    var isOrphanedRecovery bool

    if req.TaskToken != "" {
        // Normal execution - validate task token
        tokenData, err := s.tokenSvc.ValidateTaskToken(req.TaskToken)
        if err != nil {
            return connect.NewError(connect.CodeUnauthenticated,
                fmt.Errorf("invalid task token: %w", err))
        }
        jobID = tokenData.JobID
        isOrphanedRecovery = false

    } else if req.JobId != "" && req.Source == "orphaned-wal-recovery" {
        // Orphaned WAL recovery - accept job ID directly without token validation
        jobID = req.JobId
        isOrphanedRecovery = true

        log.Info().
            Str("job_id", jobID).
            Str("source", req.Source).
            Msg("Accepting orphaned WAL events without task token")

        // TODO: Add authorization check - only allow workers to upload orphaned events

    } else {
        return connect.NewError(connect.CodeInvalidArgument,
            fmt.Errorf("either task_token or (job_id + source='orphaned-wal-recovery') required"))
    }

    // Continue with event processing...
    // Tag events with source for observability
    for _, event := range req.Events {
        if isOrphanedRecovery {
            // Server can tag these events for deduplication or special handling
            log.Debug().
                Str("job_id", jobID).
                Int64("sequence", event.Sequence).
                Msg("Received orphaned event")
        }
    }
}
```

3. **Add metrics** (`internal/telemetry/metrics.go`):
```go
var (
    orphanedEventsUploadedTotal = promauto.NewCounter(prometheus.CounterOpts{
        Name: "wal_orphaned_events_uploaded_total",
        Help: "Total number of events uploaded from orphaned WAL files",
    })

    orphanedEventsUploadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "wal_orphaned_upload_errors_total",
        Help: "Errors uploading orphaned WAL events",
    }, []string{"reason"})
)
```

**Success criteria**:
- [ ] Proto updated with optional `job_id` and `source` fields
- [ ] Server accepts events with empty task token + job_id + source tag
- [ ] Server validates task token when present (existing behavior)
- [ ] Server logs orphaned event uploads separately
- [ ] Metrics track orphaned event uploads
- [ ] Tests verify both normal and orphaned upload paths

---

### Phase 3: Orphaned WAL Upload Scanner (4-6 hours)

**Add orphaned WAL scanner**:

```go
// internal/worker/wal/orphan.go (NEW FILE)

package wal

import (
    "context"
    "path/filepath"
    "strings"
    "time"

    "github.com/rs/zerolog/log"
)

// UploadOrphanedWALs scans WAL directory and uploads events from abandoned executions
// Uses job ID + source tag instead of task token (task tokens expire)
func UploadOrphanedWALs(ctx context.Context, walDir string, client *client.Clients) error {
    entries, err := os.ReadDir(walDir)
    if err != nil {
        return fmt.Errorf("failed to read WAL directory: %w", err)
    }

    for _, entry := range entries {
        // Skip non-WAL files
        if !strings.HasSuffix(entry.Name(), ".wal") {
            continue
        }

        // Parse filename: {job-id}_{token}.wal
        parts := strings.Split(entry.Name(), "_")
        if len(parts) != 2 {
            log.Warn().Str("file", entry.Name()).Msg("Invalid WAL filename format, skipping")
            continue
        }

        jobID := parts[0]

        // Check if WAL is old enough to be considered orphaned (5 minutes)
        info, err := entry.Info()
        if err != nil {
            continue
        }

        if time.Since(info.ModTime()) < 5*time.Minute {
            // Recent WAL, likely still in use
            continue
        }

        log.Info().
            Str("job_id", jobID).
            Str("wal_file", entry.Name()).
            Msg("Found orphaned WAL, uploading events")

        // Open WAL and upload pending events (no task token, uses job ID)
        walPath := filepath.Join(walDir, entry.Name())
        if err := uploadWALEvents(ctx, walPath, jobID, client); err != nil {
            log.Error().
                Err(err).
                Str("wal_file", entry.Name()).
                Msg("Failed to upload orphaned WAL events")
            continue
        }

        // Delete WAL after successful upload
        if err := os.Remove(walPath); err != nil {
            log.Warn().
                Err(err).
                Str("wal_file", entry.Name()).
                Msg("Failed to delete orphaned WAL after upload")
        }
    }

    return nil
}

// uploadWALEvents loads a WAL file and uploads all pending events
// Uses job ID + source tag (no task token, since orphaned token is expired)
func uploadWALEvents(ctx context.Context, walPath, jobID string, client *client.Clients) error {
    // This is a read-only operation - open WAL, read events, send them
    // Do NOT modify the WAL file itself

    // Open WAL in read-only mode
    w := &walImpl{
        walPath: walPath,
        jobID:   jobID,
        index:   newWALIndex(),
    }

    file, err := os.Open(walPath)
    if err != nil {
        return fmt.Errorf("failed to open WAL: %w", err)
    }
    defer file.Close()

    w.file = file

    // Load index
    if err := w.loadIndex(); err != nil {
        return fmt.Errorf("failed to load index: %w", err)
    }

    // Get all pending events
    pending := w.index.GetUnsent()
    if len(pending) == 0 {
        log.Debug().Str("wal_file", walPath).Msg("No pending events in orphaned WAL")
        return nil
    }

    // Read events
    events := make([]*jobv1.JobEvent, 0, len(pending))
    for _, rec := range pending {
        event, err := w.readRecord(rec)
        if err != nil {
            log.Warn().
                Err(err).
                Int64("sequence", rec.sequence).
                Msg("Failed to read event, skipping")
            continue
        }
        events = append(events, event)
    }

    if len(events) == 0 {
        return fmt.Errorf("failed to read any events from WAL")
    }

    // Create stream for orphaned event upload
    // NOTE: No task token - using job ID + source tag instead
    stream := client.Events.PublishJobEvents(ctx)
    defer stream.CloseRequest()

    // Send events with orphaned recovery marker
    err = stream.Send(&jobv1.PublishJobEventsRequest{
        TaskToken: "",  // Empty = orphaned recovery mode
        JobId:     jobID,
        Source:    "orphaned-wal-recovery",  // Tag for server identification
        Events:    events,
    })

    if err != nil {
        return fmt.Errorf("failed to send events: %w", err)
    }

    // Wait for server acknowledgment
    if _, err := stream.Receive(); err != nil && err != io.EOF {
        return fmt.Errorf("failed to receive ack: %w", err)
    }

    log.Info().
        Str("job_id", jobID).
        Int("event_count", len(events)).
        Msg("Successfully uploaded orphaned WAL events")

    return nil
}
```

**Integrate into worker** (`cmd/cli/internal/commands/worker.go`):

**IMPORTANT**: Use BOTH startup scan AND background goroutine for complete coverage.

```go
func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
    // ... existing setup ...

    // PHASE 1: Startup scan (blocking, critical)
    // Uploads WALs orphaned from PREVIOUS worker sessions
    // This ensures old events don't get stuck forever
    log.Info().Msg("Scanning for orphaned WAL files from previous sessions...")
    if err := wal.UploadOrphanedWALs(ctx, wal.DefaultConfig().WALDir, clients); err != nil {
        // Don't fail startup, but log prominently
        log.Error().Err(err).Msg("Failed to upload orphaned WALs during startup")
    }

    // PHASE 2: Background goroutine (continuous)
    // Uploads WALs orphaned during CURRENT worker session (if worker crashes mid-job)
    // Runs every 5 minutes to catch WALs that become orphaned after startup
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                if err := wal.UploadOrphanedWALs(ctx, wal.DefaultConfig().WALDir, clients); err != nil {
                    log.Warn().Err(err).Msg("Background orphan scan failed")
                }
            }
        }
    }()

    // Start worker loop
    for { /* ... */ }
}
```

**Success criteria**:
- [ ] Startup scan runs BEFORE worker enters job processing loop
- [ ] Background scanner runs every 5 minutes WITHOUT blocking job processing
- [ ] Orphaned WALs detected after 5 minutes of inactivity
- [ ] Events from orphaned WALs uploaded using job ID (no task token)
- [ ] Server accepts orphaned events with `source="orphaned-wal-recovery"`
- [ ] WAL files deleted after successful upload
- [ ] Failed uploads logged but don't crash worker
- [ ] Metrics track orphaned file count, event count, upload duration

---

### Phase 4: Testing (3-4 hours)

**Unit tests**:
```go
func TestWAL_UniqueFilenamePerExecution(t *testing.T) {
    // Same job ID, different tokens = different WAL files
}

func TestWAL_SanitizeTaskToken(t *testing.T) {
    // Verify /, +, = handled correctly
    // Verify long tokens (>200 chars) are hashed to 22 chars
}

func TestWAL_SanitizeTaskToken_Collisions(t *testing.T) {
    // Verify different tokens don't produce same hash (very rare)
}

func TestOrphanedWAL_Upload(t *testing.T) {
    // Create old WAL, run scanner, verify events uploaded
    // Verify upload uses job_id + source tag (no task token)
}

func TestOrphanedWAL_SkipsRecentFiles(t *testing.T) {
    // Recent WAL (<5 min) should not be considered orphaned
}

func TestServer_AcceptsOrphanedEvents(t *testing.T) {
    // Verify server accepts events with empty token + job_id + source
}

func TestServer_RejectsInvalidOrphanedEvents(t *testing.T) {
    // Verify server rejects events with empty token but no job_id or wrong source
}
```

**Integration test**:
```bash
# 1. Start job with token-abc
# 2. Write 50 events
# 3. Kill worker (SIGKILL)
# 4. Restart worker with same job but token-xyz
# 5. Verify job-123_abc.wal still exists
# 6. Verify job-123_xyz.wal created fresh
# 7. Wait 6 minutes
# 8. Verify orphan scanner uploads events from job-123_abc.wal
# 9. Verify job-123_abc.wal deleted
```

**Success criteria**:
- [ ] All unit tests passing
- [ ] Integration test shows clean separation between executions
- [ ] No data loss in chaos scenarios (100 job retries, random kills)
- [ ] Server correctly routes orphaned events by job ID
- [ ] Metrics show orphaned upload counts and durations

---

## Migration Strategy

**Existing deployments** with old WAL format (`job-123.wal`):

1. **No breaking changes**: Old WAL files remain valid
2. **Gradual migration**: Next time job-123 runs, creates `job-123_{token}.wal`
3. **Cleanup old format**: Orphan scanner uploads events from `job-123.wal` (no token)
4. **Grace period**: After 30 days, all workers upgraded, all old WALs processed

**Rollout plan**:
1. Deploy Phase 1 + 2 together to workers
2. Monitor for orphaned WAL uploads in logs
3. After 7 days, verify no old-format WALs remain
4. After 30 days, archive cleanup removes ancient files

---

## Monitoring & Alerts

**Metrics to add**:
- `wal_orphaned_files_scanned_total` - Count of orphaned WALs discovered during scans
- `wal_orphaned_events_uploaded_total` - Count of events from orphaned WALs
- `wal_orphaned_upload_duration_seconds` - Histogram of upload durations
- `wal_orphaned_upload_errors_total{reason}` - Count of failed uploads by reason (network, parse, server)
- `wal_filename_sanitization_collisions_total` - Track hash collisions (should be near zero)
- `wal_filename_length_bytes` - Histogram of WAL filename lengths

**Alerts**:
- **High orphan count**: >10 orphaned WALs found in 1 hour (indicates worker instability)
- **Upload failures**: >5 orphan upload failures in 1 hour (indicates network/server issues)
- **Old orphaned WAL**: Any orphaned WAL >30 minutes old (indicates scanner issues)
- **Disk usage**: WAL directory >80% full (indicates cleanup issues)

**Dashboards**:
- WAL file count by age (detect accumulation)
- Orphan upload success rate
- Time-to-upload for orphaned WALs

---

## Decisions Made (Previously Open Questions)

### 1. ✅ Orphan scan strategy - BOTH startup + background
   - **Decision**: Use BOTH startup scan (blocking) AND background goroutine (async)
   - **Rationale**:
     - Startup scan handles WALs from PREVIOUS worker sessions (critical)
     - Background scan handles WALs orphaned DURING current session (rare but possible)
     - Provides complete coverage for all failure scenarios

### 2. ✅ Orphan age threshold - 5 minutes
   - **Decision**: 5 minutes
   - **Rationale**: Visibility timeout is 5+ minutes, crashed job won't be retried immediately
   - **Implementation**: Check `time.Since(info.ModTime()) < 5*time.Minute`

### 3. ✅ Orphan upload sender - Job ID + Source tag (no task token)
   - **Decision**: Use empty task token + job_id + source="orphaned-wal-recovery"
   - **Rationale**:
     - Task tokens expire after visibility timeout (HMAC-signed, time-limited)
     - Orphaned WAL's token is always expired and invalid
     - Server can accept events with job ID + source tag for orphaned recovery
     - Clear separation: normal execution vs recovery mode
     - Server can tag orphaned events for observability and deduplication
   - **Implementation**:
     - Add optional `job_id` and `source` fields to `PublishJobEventsRequest` proto
     - Server validates: (task_token != "") OR (job_id != "" AND source == "orphaned-wal-recovery")
     - Orphan uploader sends with empty task_token, uses job_id + source

### 4. ✅ Disk space limits - Monitor and alert
   - **Decision**: Add disk space monitoring, alert at 80% full
   - **Emergency**: Delete oldest WAL files if >90% full
   - **Implementation**: Add `wal_directory_disk_usage_percent` metric

### 5. ✅ Archive vs Delete - Delete after successful upload
   - **Decision**: Delete after successful upload (events already in server DB)
   - **Rationale**: No need to keep duplicate data, save disk space
   - **Implementation**: `os.Remove(walPath)` after successful `uploadWALEvents()`

---

## References

- **Original WAL spec**: `specs/wal/README.md`
- **Code review findings**: Code review on 2026-01-07 (see PR discussion)
- **Worker integration**: `cmd/cli/internal/commands/worker.go:146`
- **WAL implementation**: `internal/worker/wal/wal.go:117-193`
- **File format spec**: `specs/wal/00-architecture.md`

---

## Next Steps

### Immediate Actions

1. **Implement Phase 1**: Task token in filename with hash-based sanitization (3-4 hours)
2. **Implement Phase 2**: Server-side support for orphaned events (1-2 hours)
3. **Implement Phase 3**: Orphaned WAL scanner with startup + background scans (4-6 hours)
4. **Implement Phase 4**: Testing - unit, integration, chaos (3-4 hours)
5. **Deploy**: Gradual rollout to workers (server first, then workers)
6. **Monitor**: Track orphan metrics for 7 days

### Deployment Order

1. **Deploy server changes first** (proto + orphaned event handling)
   - Backward compatible: doesn't break existing workers
   - Enables orphaned event upload capability
2. **Deploy worker changes second** (task token in filename + orphan scanner)
   - Workers can now create unique WAL files per execution
   - Orphan scanner can upload to new server endpoint
3. **Monitor for 7 days**:
   - Verify orphaned WAL uploads working
   - Check for filename collisions (should be zero)
   - Validate disk space usage stable
   - Review event deduplication (if any)

### Success Criteria

- [ ] Zero event mixing between job executions
- [ ] Zero data loss on worker crashes
- [ ] Orphaned WALs uploaded within 5-10 minutes
- [ ] WAL directory disk usage stable (<50%)
- [ ] No filename collisions
- [ ] Server logs show orphaned uploads separately
- [ ] Metrics dashboard shows orphan upload rate and duration

**Estimated total effort**: 3-4 + 1-2 + 4-6 + 3-4 = **11-16 hours**

(Revised from original 8-12 hour estimate to account for server-side changes and comprehensive testing)
