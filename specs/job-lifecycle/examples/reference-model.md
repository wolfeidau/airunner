# Example: reference model commands, invariants and differential replay

[← README](../README.md) | [← Authz interceptor](authz-interceptor.md) | [Contract test skeleton →](contract-test-skeleton.md)

Source of truth: [model.go](../../../internal/store/storetest/model.go), [commands.go](../../../internal/store/storetest/commands.go), [property_test.go](../../../internal/store/storetest/property_test.go) and [differential_integration_test.go](../../../internal/store/postgres/differential_integration_test.go)

These are excerpts, trimmed with `// ...`. If they differ from the source, the source wins. What the model covers and what it does not is in [00-architecture.md](../00-architecture.md#reference-model-and-differential-replay).

## Run it

```bash
# Model, boundary histories and 500 seeds x 200 commands. No Docker.
go test -race ./internal/store/storetest/...

# Longer exploration. Not a phase gate; ordinary runs replay the saved corpus.
go test ./internal/store/storetest -run='^$' -fuzz='^FuzzJobContract$' -fuzztime=60s

# Differential replay against a PostgreSQL testcontainer (200 histories of 60 commands).
go test -tags integration -race -run TestDifferentialReplay ./internal/store/postgres/

# Replay more or longer histories, or only your pinned regression seeds.
go test -tags integration -run TestDifferentialReplay -replay.histories=1000 -replay.length=100 ./internal/store/postgres/
go test -tags integration -run TestDifferentialReplay -replay.histories=0 ./internal/store/postgres/
```

To pin a failure, add the seed printed in the failure message to `regressionSeeds` in the differential test.

## Commands

Identities and time are explicit inputs. Time is an integer in a caller-defined unit; there is no wall clock.

```go
const (
	KindEnqueue  CommandKind = "enqueue"
	KindAcquire  CommandKind = "acquire"
	KindRenew    CommandKind = "renew"
	KindRelease  CommandKind = "release"
	KindComplete CommandKind = "complete"
	KindPublish  CommandKind = "publish"
	KindExpire   CommandKind = "expire"
	KindCancel   CommandKind = "cancel"
	KindList     CommandKind = "list"
)

// Acquire leases up to Max oldest eligible jobs; Receipts must be fresh.
type Acquire struct {
	Caller   Caller
	Queue    string
	Max      int
	Receipts []Receipt
	Now      int64
	Lease    int64
}

// Expire is the reaper: it reclaims every lease with deadline <= Now.
type Expire struct{ Now int64 }
```

## The fence the model checks

The model's fence is written independently of the SQL. Equality is expired (`now >= j.deadline`), and an empty receipt never matches.

```go
func (m *Model) fence(c Caller, h JobHandle, r Receipt, now int64) (*job, bool) {
	j, ok := m.jobs[h]
	if !ok || j.org != c.Org || j.state != Running || j.receipt != r || r == "" ||
		j.leasePrin != c.Principal || now >= j.deadline {
		return nil, false
	}
	return j, true
}
```

## Invariants checked after every command

`Model.CheckInvariants` runs after every `Apply`, including rejected commands. In addition, `Apply` records a violation if a rejected command changed the snapshot.

| Invariant | Check in `CheckInvariants` |
|---|---|
| Terminal states never reopen | previous state terminal and current state different |
| Attempts are monotonic | attempt decreased |
| Attempts are bounded | `attempt > maxAttempts` |
| Attempt equals acquisitions | `attempt != acquisitions[h]` |
| Lease fields set if and only if RUNNING | `(state == Running) != leased`, and RUNNING needs principal, receipt and `attempt > 0` |
| Records are contiguous from 1 per attempt | each record starts at the previous end + 1 |
| `lastSeq` equals the covered prefix | `lastSeq != covered` |
| Rejected commands change nothing | `Snapshot()` before and after are equal |

```go
		if (j.state == Running) != leased {
			return fmt.Errorf("%s: state %s with lease=%v", h, j.state, leased)
		}
		// ...
		if j.lastSeq != covered {
			return fmt.Errorf("%s: lastSeq %d != covered %d", h, j.lastSeq, covered)
		}
```

## Property test and fuzz target

```go
func TestPropertyGeneratedHistories(t *testing.T) {
	total := map[OutcomeKind]int{}
	for seed := int64(1); seed <= 500; seed++ {
		for k, v := range runHistory(t, seed, 200) {
			total[k] += v
		}
	}
	// The generator must exercise both accepted and rejected paths.
	for _, k := range []OutcomeKind{OK, LeaseLost, Conflict, NotFound, Invalid, Precondition} {
		require.Positive(t, total[k], "no %s outcomes generated", k)
	}
}
```

## Differential replay: mapping model time to the database

One model time unit is 3 seconds. Before each command, every RUNNING job's `visibility_until` is rewritten so that a model offset of zero is already expired when the operation runs. The adapter maps handles to real IDs and tokens and never computes expected results.

```go
const replayTimeScale = 3
// ...
	_, err := e.js.pool.Exec(context.Background(), `
		UPDATE jobs SET visibility_until = clock_timestamp() + make_interval(secs => d.secs)
		FROM unnest($1::text[], $2::float8[]) AS d(id, secs)
		WHERE jobs.job_id = d.id::uuid AND jobs.state = 2`, ids, secs)
```

[← README](../README.md) | [← Authz interceptor](authz-interceptor.md) | [Contract test skeleton →](contract-test-skeleton.md)
