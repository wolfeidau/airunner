# Example: contract test skeleton

[← README](../README.md) | [← Reference model](reference-model.md)

Source of truth: [postgrestest.go](../../../internal/store/postgres/postgrestest/postgrestest.go), [telemetrytest.go](../../../internal/telemetry/telemetrytest/telemetrytest.go) and [job_store_metrics_integration_test.go](../../../internal/store/postgres/job_store_metrics_integration_test.go)

Unlike the other examples, this is a new skeleton assembled from those helpers, not a copy of one file. It compiles against the current helper signatures (checked with `go vet -tags integration`). If a helper changes, the helper wins. The test strategy is in [00-architecture.md](../00-architecture.md#verification-limits).

## Why this shape

- **Isolated database per test.** `postgrestest.NewStores` takes a fresh database from the shared testcontainer, runs migrations and returns the pool. Do not reuse the Compose database for tests.
- **Seeded org.** `postgrestest.SeedOrg` creates one org with a user principal (role `user`) and a worker principal (role `worker`).
- **Deterministic time.** Move a lease with SQL against `clock_timestamp()` instead of sleeping, and call `ReapExpired` directly. An unstarted store has no background reaper to race the assertion.
- **Metrics through a ManualReader.** `telemetrytest.New` wraps an OpenTelemetry `ManualReader`. Assert counters with `Sum` and bounded attributes only.
- **Build tag.** Files that need Docker carry `//go:build integration`; plain `go test` skips them.

## Helper: a metered store on the isolated database

`postgrestest.NewStores` builds a store without metrics, so build a second store on the same pool. Leave it unstarted so the reaper and retention loops stay off. Token operations, `ReapExpired` and `SweepRetention` need only the pool. Streams need a started store.

```go
//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/postgres"
	"github.com/wolfeidau/airunner/internal/store/postgres/postgrestest"
	"github.com/wolfeidau/airunner/internal/telemetry/telemetrytest"
	"go.opentelemetry.io/otel/attribute"
)

func newMeteredStore(t *testing.T, s *postgrestest.Stores) (*postgres.JobStore, *telemetrytest.Harness) {
	t.Helper()
	h := telemetrytest.New(t)
	js, err := postgres.NewJobStore(s.Pool, &postgres.JobStoreConfig{
		TokenSigningSecret:  []byte("test-secret-key-min-32-bytes-long"),
		LeaseReaperInterval: time.Hour,
		Metrics:             h.Metrics,
	})
	require.NoError(t, err)
	return js, h
}
```

## Test: redelivery fences the old token

This is the shape of every contract test: arrange through the public store API, move time with SQL, act, then assert the outcome, the stored state and the metric.

```go
func TestContract_RedeliveryFencesOldToken(t *testing.T) {
	ctx := context.Background()
	stores := postgrestest.NewStores(t)
	fx := postgrestest.SeedOrg(t, stores)
	js, h := newMeteredStore(t, stores)

	_, err := js.EnqueueJob(ctx, fx.User, &jobv1.EnqueueJobRequest{
		RequestId: "skeleton-1",
		Queue:     "default",
		JobParams: &jobv1.JobParams{Repository: "https://github.com/test/skeleton", Command: "echo"},
	})
	require.NoError(t, err)

	first, err := js.DequeueJobs(ctx, fx.Worker, "default", 1, 300)
	require.NoError(t, err)
	require.Len(t, first, 1)
	jobID, oldToken := first[0].Job.JobId, first[0].TaskToken

	// Expire the lease in the database, then reap it explicitly.
	_, err = stores.Pool.Exec(ctx,
		`UPDATE jobs SET visibility_until = clock_timestamp() - INTERVAL '1 second' WHERE job_id = $1`, jobID)
	require.NoError(t, err)
	n, err := js.ReapExpired(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// The old token is fenced even though its signature is valid.
	_, err = js.UpdateJobVisibility(ctx, fx.Worker, oldToken, 60)
	require.ErrorIs(t, err, store.ErrLeaseLost)

	// The next acquisition is attempt 2 with a new token.
	second, err := js.DequeueJobs(ctx, fx.Worker, "default", 1, 300)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.EqualValues(t, 2, second[0].Job.Attempt)
	require.NotEqual(t, oldToken, second[0].TaskToken)

	require.EqualValues(t, 1, h.Sum(t, "jobs.redelivered"))
	require.EqualValues(t, 1, h.Sum(t, "jobs.lease_lost", attribute.String("operation", "renew")))
}
```

## Extending it

| To cover | Add |
|---|---|
| Publish contract | `js.PublishEvents(ctx, fx.Worker, token, events)` with `Attempt` set to the leased attempt and a non-nil `Timestamp`. Assert `store.ErrConflict` for changed content and `store.ErrInvalidArgument` for a gap |
| Completion gate | `js.CompleteJob(ctx, fx.Worker, token, &jobv1.JobResult{JobId: jobID, Success: true}, finalSeq)`. A wrong `finalSeq` returns `store.ErrInvalidArgument` and leaves the job RUNNING |
| Org boundary | `postgrestest.SeedOrg` twice. A call by org B's caller on org A's job returns `store.ErrJobNotFound` (cancel, stream) or `store.ErrLeaseLost` (token operations) |
| Retention | Set `updated_at` back with SQL, then `js.SweepRetention(ctx, 10)` and assert `RetentionReport` |
| Lock races | Hold `SELECT ... FOR UPDATE` in a second transaction as a barrier. Do not use sleeps |
| Differential replay | Add the operation to `replayEnabled` and the adapter in `differential_integration_test.go` |

Run it:

```bash
go test -tags integration -race -run 'TestContract_' ./internal/store/postgres/
```

[← README](../README.md) | [← Reference model](reference-model.md)
