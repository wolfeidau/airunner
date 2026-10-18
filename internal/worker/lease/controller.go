// Package lease renews a job's visibility lease and enforces a conservative
// local execution budget derived from monotonic send times.
package lease

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

var (
	// ErrLost reports that the server no longer recognises the lease.
	ErrLost = errors.New("lease lost")
	// ErrBudgetExhausted reports that the local deadline passed without a confirmed renewal.
	ErrBudgetExhausted = errors.New("lease budget exhausted")
)

const (
	maxRPCTimeout = 5 * time.Second
	minMargin     = 2 * time.Second
	initialRetry  = 500 * time.Millisecond
	maxRetry      = 5 * time.Second
	jitterRatio   = 0.25
)

// RenewFunc extends the lease and returns the server-accepted duration.
// Implementations wrap FailedPrecondition with ErrLost.
type RenewFunc func(ctx context.Context, requested time.Duration) (accepted time.Duration, err error)

// Option configures a Controller.
type Option func(*Controller)

// WithJitter overrides the jitter source. f returns a value in [0,1).
func WithJitter(f func() float64) Option { return func(c *Controller) { c.jitter = f } }

// Controller renews a lease and aborts when the local budget is exhausted.
type Controller struct {
	renew  RenewFunc
	jitter func() float64

	mu       sync.Mutex
	accepted time.Duration
	deadline time.Time
	watchdog *time.Timer
	aborted  bool
	err      error
	started  bool
	stopped  bool

	done     chan struct{} // closed on abort or stop
	doneOnce sync.Once
	stopCh   chan struct{} // closed by Stop or abort to wake Run
	stopOnce sync.Once
	finished chan struct{} // closed when Run returns
}

// New returns a Controller. accepted is the effective duration from the dequeue response.
func New(renew RenewFunc, accepted time.Duration, opts ...Option) *Controller {
	c := &Controller{
		renew:    renew,
		jitter:   rand.Float64,
		accepted: accepted,
		done:     make(chan struct{}),
		stopCh:   make(chan struct{}),
		finished: make(chan struct{}),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func margin(d time.Duration) time.Duration { return max(minMargin, d/10) }

// Done is closed when the controller aborts or stops.
func (c *Controller) Done() <-chan struct{} { return c.done }

// Err returns nil after a normal stop, or ErrLost / ErrBudgetExhausted after an abort.
func (c *Controller) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Remaining returns the time until the last confirmed local deadline, or 0 if aborted or expired.
func (c *Controller) Remaining() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.aborted || c.deadline.IsZero() {
		return 0
	}
	return max(0, time.Until(c.deadline))
}

// Stop ends renewal and waits for Run to return. It is idempotent.
func (c *Controller) Stop() {
	c.mu.Lock()
	c.stopped = true
	started := c.started
	if c.watchdog != nil {
		c.watchdog.Stop()
	}
	c.mu.Unlock()
	c.stopOnce.Do(func() { close(c.stopCh) })
	c.doneOnce.Do(func() { close(c.done) })
	if started {
		<-c.finished
	}
}

// abort records the first abort reason; nothing un-aborts the controller.
func (c *Controller) abort(err error) {
	c.mu.Lock()
	if c.aborted || c.stopped {
		c.mu.Unlock()
		return
	}
	c.aborted, c.err = true, err
	if c.watchdog != nil {
		c.watchdog.Stop()
	}
	c.mu.Unlock()
	log.Warn().Err(err).Msg("lease aborted")
	c.doneOnce.Do(func() { close(c.done) })
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// Run renews the lease until ctx is cancelled, Stop is called, or the lease aborts.
func (c *Controller) Run(ctx context.Context) {
	c.mu.Lock()
	if c.started || c.stopped {
		c.mu.Unlock()
		return
	}
	c.started = true
	start := time.Now()
	c.deadline = start.Add(c.accepted - margin(c.accepted))
	c.watchdog = time.AfterFunc(time.Until(c.deadline), c.onWatchdog)
	c.mu.Unlock()
	defer close(c.finished)

	backoff := initialRetry
	for {
		wait, ok := c.attempt(ctx)
		if ok {
			backoff = initialRetry
		} else {
			wait, backoff = backoff, min(backoff*2, maxRetry)
		}
		if !c.sleep(ctx, wait) {
			return
		}
	}
}

func (c *Controller) onWatchdog() {
	c.mu.Lock()
	expired := !time.Now().Before(c.deadline)
	c.mu.Unlock()
	if expired {
		c.abort(ErrBudgetExhausted)
	}
}

// attempt performs one renewal. It returns the wait before the next one and whether it succeeded.
func (c *Controller) attempt(ctx context.Context) (time.Duration, bool) {
	c.mu.Lock()
	sent := time.Now()
	prev, requested := c.deadline, c.accepted
	c.mu.Unlock()

	remaining := prev.Sub(sent)
	if remaining <= 0 {
		c.abort(ErrBudgetExhausted)
		return 0, false
	}
	rctx, cancel := context.WithTimeout(ctx, min(maxRPCTimeout, remaining))
	acc, err := c.renew(rctx, requested)
	cancel()

	if err != nil {
		if errors.Is(err, ErrLost) {
			c.abort(ErrLost)
		} else if ctx.Err() == nil {
			log.Warn().Err(err).Dur("remaining", c.Remaining()).Msg("lease renewal failed, retrying")
		}
		return 0, false
	}
	if acc <= 0 {
		acc = requested
	}

	c.mu.Lock()
	// A response after the previous confirmed deadline cannot revive the budget.
	late := sent.After(c.deadline) || !time.Now().Before(c.deadline)
	if c.aborted || c.stopped || late {
		c.mu.Unlock()
		if late {
			c.abort(ErrBudgetExhausted)
		}
		return 0, false
	}
	c.accepted = acc
	c.deadline = sent.Add(acc - margin(acc))
	c.watchdog.Reset(time.Until(c.deadline))
	c.mu.Unlock()
	log.Debug().Dur("accepted", acc).Msg("lease renewed")

	j := 1 + jitterRatio*(2*c.jitter()-1)
	return time.Duration(float64(acc/3) * j), true
}

// sleep waits for d; it returns false if Run should exit.
func (c *Controller) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-c.stopCh:
		return false
	}
}
