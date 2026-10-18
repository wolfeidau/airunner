package lease

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/airunner/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

var errTransient = errors.New("transient")

func noJitter() float64 { return 0.5 }

func TestMargin(t *testing.T) {
	require.Equal(t, 3*time.Second, margin(30*time.Second))
	require.Equal(t, 6*time.Minute, margin(time.Hour))
}

func TestNormalCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			calls.Add(1)
			return d, nil
		}, 30*time.Second, WithJitter(noJitter))
		go c.Run(t.Context())
		time.Sleep(100*time.Second + time.Millisecond)
		// immediate + every 10s => 11 calls by t=100s
		require.EqualValues(t, 11, calls.Load())
		require.Greater(t, c.Remaining(), 15*time.Second)
		c.Stop()
		c.Stop()
		require.NoError(t, c.Err())
		<-c.Done()
	})
}

func TestJitterBounds(t *testing.T) {
	for _, j := range []float64{0, 0.9999999} {
		synctest.Test(t, func(t *testing.T) {
			var calls atomic.Int32
			c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
				calls.Add(1)
				return d, nil
			}, 30*time.Second, WithJitter(func() float64 { return j }))
			go c.Run(t.Context())
			time.Sleep(100 * time.Second)
			if j == 0 {
				require.EqualValues(t, 14, calls.Load()) // 7.5s cadence: t=0..97.5
			} else {
				require.EqualValues(t, 9, calls.Load()) // 12.5s cadence: t=0..100
			}
			c.Stop()
		})
	}
}

func TestTransientRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			if n := calls.Add(1); n >= 2 && n <= 4 {
				return 0, errTransient
			}
			return d, nil
		}, 30*time.Second, WithJitter(noJitter))
		go c.Run(t.Context())
		time.Sleep(60 * time.Second)
		require.NoError(t, c.Err())
		select {
		case <-c.Done():
			t.Fatal("aborted")
		default:
		}
		c.Stop()
	})
}

func TestRepeatedFailuresAbortAtDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			if calls.Add(1) == 1 {
				return d, nil // sent at t0 => deadline t0+27s
			}
			return 0, errTransient
		}, 30*time.Second, WithJitter(noJitter))
		start := time.Now()
		go c.Run(t.Context())
		<-c.Done()
		require.Equal(t, 27*time.Second, time.Since(start))
		require.ErrorIs(t, c.Err(), ErrBudgetExhausted)
		require.Zero(t, c.Remaining())
		c.Stop()
	})
}

func TestErrLostAbortsImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			if calls.Add(1) == 1 {
				return d, nil
			}
			return 0, errors.Join(errors.New("rpc"), ErrLost)
		}, 30*time.Second, WithJitter(noJitter))
		start := time.Now()
		go c.Run(t.Context())
		<-c.Done()
		require.Equal(t, 10*time.Second, time.Since(start))
		require.ErrorIs(t, c.Err(), ErrLost)
		c.Stop()
	})
}

func TestBlockedCallWatchdogAndLateSuccessIgnored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			if calls.Add(1) == 1 {
				return d, nil
			}
			time.Sleep(time.Minute) // ignores ctx
			return d, nil
		}, 30*time.Second, WithJitter(noJitter))
		start := time.Now()
		go c.Run(t.Context())
		<-c.Done()
		require.Equal(t, 27*time.Second, time.Since(start))
		require.ErrorIs(t, c.Err(), ErrBudgetExhausted)
		c.Stop() // joins after the blocked call returns
		require.ErrorIs(t, c.Err(), ErrBudgetExhausted)
		require.Zero(t, c.Remaining())
	})
}

func TestNoInitialRenewalAborts(t *testing.T) {
	for _, acc := range []time.Duration{30 * time.Second, time.Hour} {
		synctest.Test(t, func(t *testing.T) {
			c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
				return 0, errTransient
			}, acc)
			start := time.Now()
			go c.Run(t.Context())
			<-c.Done()
			require.Equal(t, acc-margin(acc), time.Since(start))
			require.ErrorIs(t, c.Err(), ErrBudgetExhausted)
			c.Stop()
		})
	}
}

func TestDeadlineUsesMargin(t *testing.T) {
	for _, acc := range []time.Duration{30 * time.Second, time.Hour} {
		synctest.Test(t, func(t *testing.T) {
			c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
				return acc, nil
			}, acc)
			go c.Run(t.Context())
			synctest.Wait()
			require.Equal(t, acc-margin(acc), c.Remaining())
			c.Stop()
		})
	}
}

func TestRPCTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var got []time.Duration
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			dl, ok := ctx.Deadline()
			require.True(t, ok)
			got = append(got, time.Until(dl))
			if len(got) == 1 {
				return d, nil
			}
			return 0, errTransient
		}, 30*time.Second, WithJitter(noJitter))
		go c.Run(t.Context())
		<-c.Done()
		c.Stop()
		require.Equal(t, 5*time.Second, got[0])
		for _, g := range got {
			require.LessOrEqual(t, g, 5*time.Second)
		}
		// Last attempt is bounded by the remaining budget (< 5s).
		require.Less(t, got[len(got)-1], 5*time.Second)
	})
}

func TestStopBeforeRun(t *testing.T) {
	c := New(func(context.Context, time.Duration) (time.Duration, error) { return 0, nil }, 30*time.Second)
	c.Stop()
	c.Run(context.Background())
	require.NoError(t, c.Err())
}

func leaseAborts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, mm := range sm.Metrics {
			if mm.Name != "worker.lease.aborts" {
				continue
			}
			for _, dp := range mm.Data.(metricdata.Sum[int64]).DataPoints {
				v, _ := dp.Attributes.Value("reason")
				out[v.AsString()] += dp.Value
			}
		}
	}
	return out
}

func newTestMetrics(t *testing.T) (*telemetry.WorkerMetrics, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	m, err := telemetry.NewWorkerMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	require.NoError(t, err)
	return m, reader
}

func TestMetricsErrLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, reader := newTestMetrics(t)
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			return 0, errors.Join(errors.New("rpc"), ErrLost)
		}, 30*time.Second, WithJitter(noJitter), WithMetrics(m))
		go c.Run(t.Context())
		<-c.Done()
		c.Stop()
		require.Equal(t, map[string]int64{"lost": 1}, leaseAborts(t, reader))
	})
}

func TestMetricsBudgetExhausted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, reader := newTestMetrics(t)
		c := New(func(ctx context.Context, d time.Duration) (time.Duration, error) {
			return 0, errTransient
		}, 30*time.Second, WithJitter(noJitter), WithMetrics(m))
		go c.Run(t.Context())
		<-c.Done()
		c.Stop()
		require.ErrorIs(t, c.Err(), ErrBudgetExhausted)
		require.Equal(t, map[string]int64{"budget": 1}, leaseAborts(t, reader))
	})
}
