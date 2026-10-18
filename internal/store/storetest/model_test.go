package storetest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	userA   = Caller{"org-a", "user-a"}
	workerA = Caller{"org-a", "worker-a"}
	otherA  = Caller{"org-a", "worker-a2"}
	workerB = Caller{"org-b", "worker-b"}
)

type harness struct {
	t     *testing.T
	m     *Model
	jobs  int
	rcpts int
}

func newHarness(t *testing.T) *harness { return &harness{t: t, m: New()} }

func (h *harness) apply(c Command) Outcome {
	h.t.Helper()
	before := h.m.Snapshot()
	out := h.m.Apply(c)
	require.NoError(h.t, h.m.CheckInvariants())
	if out.Kind != OK {
		require.Equal(h.t, before, h.m.Snapshot(), "rejected %s changed state", c.Kind())
	}
	return out
}

func (h *harness) enqueue(maxAttempts int) JobHandle {
	h.t.Helper()
	h.jobs++
	out := h.apply(Enqueue{
		Caller: userA, RequestID: fmt.Sprintf("r%d", h.jobs), Queue: "q", Fingerprint: "fp",
		MaxAttempts: &maxAttempts, Handle: JobHandle(fmt.Sprintf("j%d", h.jobs)),
	})
	require.Equal(h.t, OK, out.Kind)
	return out.Handle
}

func (h *harness) acquire(c Caller, now, lease int64) Acquired {
	h.t.Helper()
	h.rcpts++
	out := h.apply(Acquire{Caller: c, Queue: "q", Max: 1, Receipts: []Receipt{Receipt(fmt.Sprintf("rc%d", h.rcpts))}, Now: now, Lease: lease})
	require.Equal(h.t, OK, out.Kind)
	require.Len(h.t, out.Acquired, 1)
	return out.Acquired[0]
}

func (h *harness) state(j JobHandle) State {
	v, ok := h.m.Job(j)
	require.True(h.t, ok)
	return v.State
}

func publish(c Caller, a Acquired, now int64, recs ...Record) Publish {
	return Publish{Caller: c, Handle: a.Handle, Receipt: a.Receipt, Now: now, Events: recs}
}

func rec(seq, end int64, hash string) Record { return Record{seq, end, hash} }

func TestExactExpiryEquality(t *testing.T) {
	h := newHarness(t)
	h.enqueue(3)
	a := h.acquire(workerA, 10, 5) // deadline 15

	require.Equal(t, OK, h.apply(Renew{workerA, a.Handle, a.Receipt, 14, 5}).Kind) // deadline 19
	require.Equal(t, LeaseLost, h.apply(Renew{workerA, a.Handle, a.Receipt, 19, 5}).Kind)
	require.Equal(t, LeaseLost, h.apply(publish(workerA, a, 19, rec(1, 1, "h"))).Kind)
	require.Equal(t, LeaseLost, h.apply(Complete{workerA, a.Handle, a.Receipt, 19, true, 0}).Kind)
	require.Equal(t, LeaseLost, h.apply(Release{workerA, a.Handle, a.Receipt, 19}).Kind)

	h.apply(Expire{Now: 18})
	require.Equal(t, Running, h.state(a.Handle))
	h.apply(Expire{Now: 19})
	require.Equal(t, Scheduled, h.state(a.Handle))
}

func TestRepeatedRelease(t *testing.T) {
	h := newHarness(t)
	h.enqueue(3)
	a := h.acquire(workerA, 0, 10)
	require.Equal(t, OK, h.apply(Release{workerA, a.Handle, a.Receipt, 1}).Kind)
	require.Equal(t, Scheduled, h.state(a.Handle))
	require.Equal(t, LeaseLost, h.apply(Release{workerA, a.Handle, a.Receipt, 2}).Kind)
	require.Equal(t, LeaseLost, h.apply(Renew{workerA, a.Handle, a.Receipt, 2, 5}).Kind)
}

func TestExhaustionViaReleaseAndExpire(t *testing.T) {
	h := newHarness(t)
	rel := h.enqueue(2)
	exp := h.enqueue(2)

	a1 := h.acquire(workerA, 0, 10)
	require.Equal(t, rel, a1.Handle)
	a2 := h.acquire(workerA, 0, 10)
	require.Equal(t, exp, a2.Handle)

	h.apply(Release{workerA, a1.Handle, a1.Receipt, 1})
	h.apply(Expire{Now: 10})
	require.Equal(t, Scheduled, h.state(rel))
	require.Equal(t, Scheduled, h.state(exp))

	b1 := h.acquire(workerA, 20, 10)
	b2 := h.acquire(workerA, 20, 10)
	require.Equal(t, 2, b1.Attempt)
	require.Equal(t, 2, b2.Attempt)

	h.apply(Release{workerA, b1.Handle, b1.Receipt, 21})
	h.apply(Expire{Now: 30})
	require.Equal(t, Failed, h.state(rel))
	require.Equal(t, Failed, h.state(exp))
	require.Equal(t, "exhausted", h.m.Reason(rel))
	require.Equal(t, "exhausted", h.m.Reason(exp))

	// Exhausted jobs are never acquired again.
	out := h.apply(Acquire{Caller: workerA, Queue: "q", Max: 5, Receipts: []Receipt{"zz1", "zz2"}, Now: 40, Lease: 5})
	require.Empty(t, out.Acquired)
}

func TestTerminalNoReopen(t *testing.T) {
	h := newHarness(t)
	j := h.enqueue(3)
	a := h.acquire(workerA, 0, 10)
	require.Equal(t, OK, h.apply(Complete{workerA, j, a.Receipt, 1, true, 0}).Kind)
	require.Equal(t, Completed, h.state(j))

	require.Equal(t, LeaseLost, h.apply(Release{workerA, j, a.Receipt, 2}).Kind)
	require.Equal(t, Precondition, h.apply(Cancel{userA, j, 2}).Kind)
	h.apply(Expire{Now: 100})
	require.Empty(t, h.apply(Acquire{Caller: workerA, Queue: "q", Max: 1, Receipts: []Receipt{"new"}, Now: 3, Lease: 5}).Acquired)
	require.Equal(t, Completed, h.state(j))
}

func TestCrossOrgAndCrossWorker(t *testing.T) {
	h := newHarness(t)
	j := h.enqueue(3)

	// Another org cannot acquire or see the job.
	h.rcpts++
	require.Empty(t, h.apply(Acquire{Caller: workerB, Queue: "q", Max: 1, Receipts: []Receipt{"b1"}, Now: 0, Lease: 5}).Acquired)
	require.Empty(t, h.m.List("org-b", "q"))
	require.Equal(t, []JobHandle{j}, h.m.List("org-a", "q"))
	require.Equal(t, NotFound, h.apply(Cancel{workerB, j, 0}).Kind)
	require.Equal(t, NotFound, h.apply(Cancel{userA, "missing", 0}).Kind)

	a := h.acquire(workerA, 0, 10)
	require.Equal(t, LeaseLost, h.apply(Renew{workerB, j, a.Receipt, 1, 5}).Kind)
	require.Equal(t, LeaseLost, h.apply(Renew{otherA, j, a.Receipt, 1, 5}).Kind)
	require.Equal(t, LeaseLost, h.apply(Complete{otherA, j, a.Receipt, 1, true, 0}).Kind)
	require.Equal(t, LeaseLost, h.apply(Release{workerB, "missing", a.Receipt, 1}).Kind)
	require.Equal(t, OK, h.apply(Renew{workerA, j, a.Receipt, 1, 5}).Kind)
}

func TestStaleReceiptAfterRedelivery(t *testing.T) {
	h := newHarness(t)
	j := h.enqueue(3)
	old := h.acquire(workerA, 0, 5)
	h.apply(Expire{Now: 5})
	cur := h.acquire(otherA, 6, 5)
	require.Equal(t, 2, cur.Attempt)

	require.Equal(t, LeaseLost, h.apply(Renew{workerA, j, old.Receipt, 7, 5}).Kind)
	require.Equal(t, LeaseLost, h.apply(Renew{otherA, j, old.Receipt, 7, 5}).Kind)
	require.Equal(t, LeaseLost, h.apply(publish(workerA, old, 7, rec(1, 1, "h"))).Kind)
	require.Equal(t, LeaseLost, h.apply(Complete{workerA, j, old.Receipt, 7, true, 0}).Kind)
	require.Equal(t, OK, h.apply(Complete{otherA, j, cur.Receipt, 7, true, 0}).Kind)
}

func TestPublishConflictRetryAndRanges(t *testing.T) {
	h := newHarness(t)
	h.enqueue(3)
	a := h.acquire(workerA, 0, 100)

	out := h.apply(publish(workerA, a, 1, rec(1, 5, "h1")))
	require.Equal(t, OK, out.Kind)
	require.EqualValues(t, 5, out.AckThrough)
	require.Equal(t, 1, out.Attempt)

	// Identical retry is a no-op with the same ack.
	snap := h.m.Snapshot()
	again := h.apply(publish(workerA, a, 2, rec(1, 5, "h1")))
	require.Equal(t, OK, again.Kind)
	require.EqualValues(t, 5, again.AckThrough)
	require.Equal(t, snap, h.m.Snapshot())

	// Changed content or range at the same start conflicts.
	require.Equal(t, Conflict, h.apply(publish(workerA, a, 3, rec(1, 5, "other"))).Kind)
	require.Equal(t, Conflict, h.apply(publish(workerA, a, 3, rec(1, 4, "h1"))).Kind)

	// Overlap, gap, and malformed ranges are invalid.
	require.Equal(t, Invalid, h.apply(publish(workerA, a, 3, rec(3, 8, "x"))).Kind)
	require.Equal(t, Invalid, h.apply(publish(workerA, a, 3, rec(7, 7, "x"))).Kind)
	require.Equal(t, Invalid, h.apply(publish(workerA, a, 3, rec(0, 1, "x"))).Kind)
	require.Equal(t, Invalid, h.apply(publish(workerA, a, 3, rec(6, 5, "x"))).Kind)
	require.Equal(t, Invalid, h.apply(publish(workerA, a, 3)).Kind)

	// All-or-nothing: a bad record rejects the whole batch.
	require.Equal(t, Invalid, h.apply(publish(workerA, a, 3, rec(6, 6, "ok"), rec(9, 9, "gap"))).Kind)
	// A batch mixing a retry and new records succeeds and acks the last one.
	mixed := h.apply(publish(workerA, a, 4, rec(1, 5, "h1"), rec(6, 6, "h2"), rec(7, 9, "h3")))
	require.Equal(t, OK, mixed.Kind)
	require.EqualValues(t, 9, mixed.AckThrough)

	require.Equal(t, Invalid, h.apply(Complete{workerA, a.Handle, a.Receipt, 5, true, 6}).Kind)
	require.Equal(t, OK, h.apply(Complete{workerA, a.Handle, a.Receipt, 5, true, 9}).Kind)
}

func TestCancel(t *testing.T) {
	h := newHarness(t)
	sched := h.enqueue(3)
	run := h.enqueue(3)
	a := h.acquire(workerA, 0, 10)
	require.Equal(t, sched, a.Handle)
	b := h.acquire(workerA, 0, 10)
	require.Equal(t, run, b.Handle)

	require.Equal(t, OK, h.apply(Cancel{userA, run, 1}).Kind)
	require.Equal(t, Cancelled, h.state(run))
	require.Equal(t, LeaseLost, h.apply(publish(workerA, b, 2, rec(1, 1, "h"))).Kind)
	require.Equal(t, LeaseLost, h.apply(Complete{workerA, run, b.Receipt, 2, true, 0}).Kind)
	require.Equal(t, OK, h.apply(Cancel{userA, run, 3}).Kind) // idempotent

	// Cancelling a scheduled job works and it is never acquired.
	h.apply(Release{workerA, sched, a.Receipt, 1})
	require.Equal(t, OK, h.apply(Cancel{userA, sched, 2}).Kind)
	require.Empty(t, h.apply(Acquire{Caller: workerA, Queue: "q", Max: 1, Receipts: []Receipt{"n"}, Now: 3, Lease: 5}).Acquired)

	// Failed is also not cancellable.
	f := h.enqueue(3)
	c := h.acquire(workerA, 4, 10)
	require.Equal(t, f, c.Handle)
	h.apply(Complete{workerA, f, c.Receipt, 5, false, 0})
	require.Equal(t, Failed, h.state(f))
	require.Equal(t, Precondition, h.apply(Cancel{userA, f, 6}).Kind)
}

func TestNewAttemptRestartsSequences(t *testing.T) {
	h := newHarness(t)
	j := h.enqueue(3)
	a1 := h.acquire(workerA, 0, 5)
	h.apply(publish(workerA, a1, 1, rec(1, 3, "a1")))
	h.apply(Release{workerA, j, a1.Receipt, 2})

	a2 := h.acquire(workerA, 3, 5)
	require.Equal(t, 2, a2.Attempt)
	// Attempt 2 starts at 1 even though attempt 1 committed [1..3] with other content.
	out := h.apply(publish(workerA, a2, 4, rec(1, 2, "a2")))
	require.Equal(t, OK, out.Kind)
	require.Equal(t, 2, out.Attempt)
	require.EqualValues(t, 2, out.AckThrough)
	require.Equal(t, []Record{rec(1, 3, "a1")}, h.m.jobs[j].events[1])
	require.Equal(t, []Record{rec(1, 2, "a2")}, h.m.jobs[j].events[2])
	require.Equal(t, Invalid, h.apply(Complete{workerA, j, a2.Receipt, 5, true, 3}).Kind)
}

func TestEnqueueIdempotencyAndValidation(t *testing.T) {
	h := newHarness(t)
	enq := func(c Caller, req, fp string, handle JobHandle, maxAttempts *int) Outcome {
		return h.apply(Enqueue{Caller: c, RequestID: req, Queue: "q", Fingerprint: fp, MaxAttempts: maxAttempts, DefaultMaxAttempts: 3, Handle: handle})
	}
	first := enq(userA, "r", "fp1", "j1", nil)
	require.Equal(t, OK, first.Kind)
	retry := enq(userA, "r", "fp1", "j2", nil)
	require.Equal(t, OK, retry.Kind)
	require.Equal(t, JobHandle("j1"), retry.Handle)
	require.Equal(t, Conflict, enq(userA, "r", "fp2", "j3", nil).Kind)
	require.Len(t, h.m.List("org-a", "q"), 1)

	// Idempotency keys are scoped per org.
	cross := enq(workerB, "r", "fp1", "j4", nil)
	require.Equal(t, OK, cross.Kind)
	require.Equal(t, JobHandle("j4"), cross.Handle)

	for i, v := range []int{0, -1, 101} {
		v := v
		require.Equal(t, Invalid, enq(userA, fmt.Sprintf("bad%d", i), "fp", JobHandle(fmt.Sprintf("b%d", i)), &v).Kind)
	}
	for _, v := range []int{1, 100} {
		v := v
		require.Equal(t, OK, enq(userA, fmt.Sprintf("ok%d", v), "fp", JobHandle(fmt.Sprintf("o%d", v)), &v).Kind)
	}
	view, ok := h.m.Job("j1")
	require.True(t, ok)
	require.Equal(t, JobView{State: Scheduled, MaxAttempts: 3, Org: "org-a"}, view)
}

func TestAcquireFIFOAndBound(t *testing.T) {
	h := newHarness(t)
	j1, j2, j3 := h.enqueue(1), h.enqueue(1), h.enqueue(1)
	out := h.apply(Acquire{Caller: workerA, Queue: "q", Max: 2, Receipts: []Receipt{"x1", "x2", "x3"}, Now: 0, Lease: 5})
	require.Equal(t, []Acquired{{j1, 1, "x1"}, {j2, 1, "x2"}}, out.Acquired)

	// Reusing a receipt is rejected.
	require.Equal(t, Invalid, h.apply(Acquire{Caller: workerA, Queue: "q", Max: 1, Receipts: []Receipt{"x1"}, Now: 0, Lease: 5}).Kind)

	h.apply(Release{workerA, j1, "x1", 1}) // max 1 => exhausted
	require.Equal(t, Failed, h.state(j1))
	next := h.apply(Acquire{Caller: otherA, Queue: "q", Max: 5, Receipts: []Receipt{"y1", "y2"}, Now: 2, Lease: 5})
	require.Equal(t, []Acquired{{j3, 1, "y1"}}, next.Acquired)
}

func TestGeneratorDeterministic(t *testing.T) {
	first := Generate(7, 100, GenOptions{})
	require.Equal(t, first, Generate(7, 100, GenOptions{}))
	require.NotEqual(t, Generate(7, 100, GenOptions{}), Generate(8, 100, GenOptions{}))
}

func TestGenerateOnlyValidTokens(t *testing.T) {
	opts := GenOptions{
		Enabled:         map[CommandKind]bool{KindEnqueue: true, KindAcquire: true, KindComplete: true, KindList: true},
		OnlyValidTokens: true,
	}
	for seed := int64(1); seed <= 50; seed++ {
		m := New()
		for _, c := range Generate(seed, 150, opts) {
			out := m.Apply(c)
			require.NoError(t, m.CheckInvariants())
			if c.Kind() == KindComplete {
				require.Equal(t, OK, out.Kind, "seed %d", seed)
			}
		}
	}
}
