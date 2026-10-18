# Example: fenced lease lock and publish transaction

[← README](../README.md) | [← Schema](schema.md) | [Bounded sweeps →](bounded-sweeps.md)

Source of truth: [job_store.go](../../../internal/store/postgres/job_store.go)

These are excerpts, trimmed with `// ...`. If they differ from the source, the source wins. The reasoning is in [00-architecture.md](../00-architecture.md#leases-and-fencing) and [04a-phase4a-fencing.md](../04a-phase4a-fencing.md).

## Outline

Every token operation (renew, publish, complete, release) follows the same shape:

1. Decode and verify the task token (HMAC). No database access yet.
2. Begin a READ COMMITTED transaction and set `lock_timeout` and `statement_timeout` to 5s.
3. `SELECT ... FOR UPDATE` the job row, scoped to the caller's org.
4. After the lock is held, sample `clock_timestamp()` once.
5. Check state, receipt, queue, leasing principal and expiry. Any failure is `ErrLeaseLost`.
6. Do the whole mutation in this transaction. Acknowledge only after commit.

## lockLeaseRow, part 1: lock the row

`now()` is frozen at transaction start, so it is never used to judge expiry. A cancelled job is reported as `ErrJobCancelled` before the lease checks, so any holder of an old token learns the job was cancelled.

```go
const fenceTimeoutSQL = `SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '5s'`

func lockLeaseRow(ctx context.Context, tx pgx.Tx, caller store.Caller, tt *taskToken) (*leaseRow, error) {
	if _, err := tx.Exec(ctx, fenceTimeoutSQL); err != nil {
		return nil, mapPostgresError(err)
	}
	// ...
	err := tx.QueryRow(ctx, `
		SELECT state, queue, receipt_handle::text, leased_by::text, visibility_until,
		       attempt, max_attempts, last_event_sequence
		FROM jobs
		WHERE org_id = $1 AND job_id = $2
		FOR UPDATE
	`, caller.OrgID, tt.JobID).Scan(&state, &queue, &receipt, &leasedBy, &visibilityUntil, &attempt, &maxAttempts, &lastSeq)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: no matching lease", store.ErrLeaseLost)
		}
		return nil, mapPostgresError(err)
	}

	if state == int32(jobv1.JobState_JOB_STATE_CANCELLED) {
		return nil, store.ErrJobCancelled
	}
	// ...
```

## lockLeaseRow, part 2: validate after the lock

Equality counts as expired (`visibility_until > opTime` must hold). The error text never says which check failed.

```go
	var opTime time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&opTime); err != nil {
		return nil, mapPostgresError(err)
	}

	if state != int32(jobv1.JobState_JOB_STATE_RUNNING) ||
		receipt == nil || *receipt != tt.ReceiptHandle ||
		queue != tt.Queue ||
		leasedBy == nil || *leasedBy != caller.PrincipalID.String() ||
		visibilityUntil == nil || !visibilityUntil.After(opTime) {
		return nil, fmt.Errorf("%w: no matching lease", store.ErrLeaseLost)
	}

	return &leaseRow{attempt: attempt, lastEventSequence: lastSeq, operationTime: opTime}, nil
}
```

## publishEvents: contiguous append under the lock

The attempt comes from the locked row, never from the request. A request is all-or-nothing: any rejection returns before `Commit`, and the deferred `Rollback` discards every insert.

```go
	tx, row, err := s.lockLease(queryCtx, caller, tt)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(queryCtx)) }()

	prepared, err := prepareEvents(events, row.attempt)
	if err != nil {
		return nil, 0, err
	}

	last := row.lastEventSequence
	var acked int64
	var inserted []*jobv1.JobEvent

	for i, p := range prepared {
		switch {
		case p.start == last+1:
			_, err := tx.Exec(queryCtx, `
				INSERT INTO job_events (job_id, attempt, sequence, end_sequence, timestamp, event_type, event_payload)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, tt.JobID, row.attempt, p.start, p.end, p.event.Timestamp.AsTime(), p.event.EventType, p.payload)
			// ...
			last = p.end
			inserted = append(inserted, p.event)
		case p.start <= last:
			if err := s.checkReplay(queryCtx, tx, tt.JobID, row.attempt, i, p); err != nil {
				return nil, 0, err
			}
		default:
			return nil, 0, fmt.Errorf("%w: event %d starts at sequence %d but next expected is %d",
				store.ErrInvalidArgument, i, p.start, last+1)
		}
		acked = max(acked, p.end)
	}
```

## publishEvents: advance the prefix and commit

`last_event_sequence` moves in the same transaction as the inserts. The acknowledgement is built only after `Commit` returns.

```go
	if last != row.lastEventSequence {
		if _, err := tx.Exec(queryCtx,
			`UPDATE jobs SET last_event_sequence = $1 WHERE org_id = $2 AND job_id = $3`,
			last, caller.OrgID, tt.JobID); err != nil {
			return nil, 0, mapPostgresError(err)
		}
	}

	if err := tx.Commit(queryCtx); err != nil {
		return nil, 0, mapPostgresError(err)
	}
	// ...
	return &store.PublishResult{Attempt: row.attempt, AcknowledgedThroughSequence: acked}, len(inserted), nil
```

## checkReplay: identical retries are no-ops

A start at or below the committed prefix must match a stored row byte for byte. No stored row at that start means the record overlaps a committed range.

```go
	err := tx.QueryRow(ctx, `
		SELECT end_sequence, event_payload FROM job_events
		WHERE job_id = $1 AND attempt = $2 AND sequence = $3
	`, jobID, attempt, p.start).Scan(&storedEnd, &storedPayload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: event %d sequence %d overlaps committed events", store.ErrInvalidArgument, idx, p.start)
		}
		return mapPostgresError(err)
	}

	if storedEnd != p.end || !bytes.Equal(storedPayload, p.payload) {
		return fmt.Errorf("%w: event %d sequence %d differs from the committed event", store.ErrConflict, idx, p.start)
	}
```

[← README](../README.md) | [← Schema](schema.md) | [Bounded sweeps →](bounded-sweeps.md)
