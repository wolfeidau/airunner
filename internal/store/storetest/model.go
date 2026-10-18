// Package storetest is a pure-Go reference model of the job lifecycle contract.
//
// It is the test oracle for differential testing of the production job stores.
// It is deliberately independent of production code: it imports nothing from
// internal/store/postgres, reuses no production transition helpers, and uses
// no database, network, filesystem, goroutines, or wall clock. Identities
// (organizations, principals, job handles, receipts) and time are supplied
// explicitly by the caller, which makes every history deterministic.
package storetest

import (
	"fmt"
	"slices"
	"strings"
)

// Identity types are opaque handles supplied by the caller.
type (
	OrgID       string
	PrincipalID string
	JobHandle   string
	Receipt     string
)

// Contract bounds on max attempts.
const (
	MinMaxAttempts = 1
	MaxMaxAttempts = 100
)

// State is the job lifecycle state.
type State int

// Lifecycle states.
const (
	Scheduled State = iota + 1
	Running
	Completed
	Failed
	Cancelled
)

func (s State) String() string {
	switch s {
	case Scheduled:
		return "SCHEDULED"
	case Running:
		return "RUNNING"
	case Completed:
		return "COMPLETED"
	case Failed:
		return "FAILED"
	case Cancelled:
		return "CANCELLED"
	}
	return fmt.Sprintf("State(%d)", int(s))
}

// Terminal reports whether the state is final.
func (s State) Terminal() bool { return s == Completed || s == Failed || s == Cancelled }

// OutcomeKind classifies the result of a command.
type OutcomeKind int

// Outcome kinds.
const (
	OK OutcomeKind = iota
	LeaseLost
	Conflict
	NotFound
	Invalid
	Precondition
)

func (k OutcomeKind) String() string {
	names := [...]string{"OK", "LeaseLost", "Conflict", "NotFound", "Invalid", "Precondition"}
	if int(k) < len(names) {
		return names[k]
	}
	return fmt.Sprintf("OutcomeKind(%d)", int(k))
}

// Caller identifies who issues a command.
type Caller struct {
	Org       OrgID
	Principal PrincipalID
}

// Record is a committed event covering [Sequence, EndSequence].
type Record struct {
	Sequence    int64
	EndSequence int64
	ContentHash string
}

// Acquired describes one job handed to a worker.
type Acquired struct {
	Handle  JobHandle
	Attempt int
	Receipt Receipt
}

// Outcome is the result of Apply. Only the fields relevant to the command are set.
type Outcome struct {
	Kind       OutcomeKind
	Acquired   []Acquired
	Handles    []JobHandle // List results, creation order
	Handle     JobHandle
	Attempt    int
	AckThrough int64
	State      State
}

// JobView is a comparable projection of a job for differential tests.
type JobView struct {
	State          State
	Attempt        int
	MaxAttempts    int
	LeasePrincipal PrincipalID
	Org            OrgID
}

type job struct {
	handle      JobHandle
	org         OrgID
	creator     PrincipalID
	queue       string
	requestID   string
	fingerprint string // includes the requested max attempts, see enqueueIntent
	state       State
	attempt     int
	maxAttempts int
	leasePrin   PrincipalID
	receipt     Receipt
	deadline    int64
	reason      string
	events      map[int][]Record
	lastSeq     int64
}

type seen struct {
	state   State
	attempt int
}

type requestKey struct {
	org OrgID
	id  string
}

// Model is the reference implementation. It is not safe for concurrent use.
type Model struct {
	jobs         map[JobHandle]*job
	order        []JobHandle
	requests     map[requestKey]JobHandle
	usedReceipts map[Receipt]bool
	acquisitions map[JobHandle]int
	prev         map[JobHandle]seen
	violation    error
}

// New returns an empty model.
func New() *Model {
	return &Model{
		jobs:         map[JobHandle]*job{},
		requests:     map[requestKey]JobHandle{},
		usedReceipts: map[Receipt]bool{},
		acquisitions: map[JobHandle]int{},
		prev:         map[JobHandle]seen{},
	}
}

// Apply executes a command and returns its outcome. A rejected command must
// leave the model unchanged; a violation is reported by CheckInvariants.
func (m *Model) Apply(cmd Command) Outcome {
	before := m.Snapshot()
	out := m.apply(cmd)
	if out.Kind != OK && m.violation == nil {
		if after := m.Snapshot(); after != before {
			m.violation = fmt.Errorf("rejected %s (%s) changed state", cmd.Kind(), out.Kind)
		}
	}
	return out
}

func (m *Model) apply(cmd Command) Outcome {
	switch c := cmd.(type) {
	case Enqueue:
		return m.enqueue(c)
	case Acquire:
		return m.acquire(c)
	case Renew:
		return m.renew(c)
	case Release:
		return m.release(c)
	case Complete:
		return m.complete(c)
	case Publish:
		return m.publish(c)
	case Expire:
		return m.expire(c)
	case Cancel:
		return m.cancel(c)
	case List:
		return m.list(c)
	}
	return Outcome{Kind: Invalid}
}

// Job returns a comparable view of a job.
func (m *Model) Job(h JobHandle) (JobView, bool) {
	j, ok := m.jobs[h]
	if !ok {
		return JobView{}, false
	}
	return JobView{State: j.state, Attempt: j.attempt, MaxAttempts: j.maxAttempts, LeasePrincipal: j.leasePrin, Org: j.org}, true
}

// Reason returns the terminal reason ("", "failed", "exhausted", "cancelled").
func (m *Model) Reason(h JobHandle) string {
	if j, ok := m.jobs[h]; ok {
		return j.reason
	}
	return ""
}

// Deadline returns the lease deadline of a running job.
func (m *Model) Deadline(h JobHandle) (int64, bool) {
	if j, ok := m.jobs[h]; ok && j.state == Running {
		return j.deadline, true
	}
	return 0, false
}

// LastSequence returns the highest committed event sequence of the job's current attempt.
func (m *Model) LastSequence(h JobHandle) int64 {
	if j, ok := m.jobs[h]; ok {
		return j.lastSeq
	}
	return 0
}

// List returns handles in (org, queue) in creation order.
func (m *Model) List(org OrgID, queue string) []JobHandle {
	var out []JobHandle
	for _, h := range m.order {
		if j := m.jobs[h]; j.org == org && j.queue == queue {
			out = append(out, h)
		}
	}
	return out
}

// Snapshot renders the full model state as a comparable value.
func (m *Model) Snapshot() string {
	var b strings.Builder
	for _, h := range m.order {
		j := m.jobs[h]
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s|%s|%s|%d/%d|%s|%s|%d|%s|%d|", j.handle, j.org, j.creator, j.queue, j.requestID,
			j.fingerprint, j.state, j.attempt, j.maxAttempts, j.leasePrin, j.receipt, j.deadline, j.reason, j.lastSeq)
		for a := 1; a <= j.attempt; a++ {
			fmt.Fprintf(&b, "a%d:%v;", a, j.events[a])
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "receipts=%d", len(m.usedReceipts))
	return b.String()
}

// fence returns the job if the caller holds a live lease on it.
func (m *Model) fence(c Caller, h JobHandle, r Receipt, now int64) (*job, bool) {
	j, ok := m.jobs[h]
	if !ok || j.org != c.Org || j.state != Running || j.receipt != r || r == "" ||
		j.leasePrin != c.Principal || now >= j.deadline {
		return nil, false
	}
	return j, true
}

func clearLease(j *job) {
	j.leasePrin, j.receipt, j.deadline = "", "", 0
}

// reclaim returns a leased job to the queue, or fails it when attempts are exhausted.
func reclaim(j *job) {
	clearLease(j)
	if j.attempt < j.maxAttempts {
		j.state = Scheduled
		return
	}
	j.state, j.reason = Failed, "exhausted"
}

func (m *Model) enqueue(c Enqueue) Outcome {
	maxAttempts := c.DefaultMaxAttempts
	if c.MaxAttempts != nil {
		maxAttempts = *c.MaxAttempts
	}
	if maxAttempts < MinMaxAttempts || maxAttempts > MaxMaxAttempts || c.RequestID == "" || c.Handle == "" {
		return Outcome{Kind: Invalid}
	}
	intent := enqueueIntent(c)
	if h, ok := m.requests[requestKey{c.Caller.Org, c.RequestID}]; ok {
		j := m.jobs[h]
		if j.fingerprint != intent {
			return Outcome{Kind: Conflict}
		}
		return Outcome{Handle: h, State: j.state, Attempt: j.attempt}
	}
	if _, dup := m.jobs[c.Handle]; dup {
		return Outcome{Kind: Invalid}
	}
	j := &job{
		handle: c.Handle, org: c.Caller.Org, creator: c.Caller.Principal, queue: c.Queue,
		requestID: c.RequestID, fingerprint: intent, state: Scheduled,
		maxAttempts: maxAttempts, events: map[int][]Record{},
	}
	m.jobs[j.handle] = j
	m.order = append(m.order, j.handle)
	m.requests[requestKey{j.org, j.requestID}] = j.handle
	return Outcome{Handle: j.handle, State: Scheduled}
}

// enqueueIntent is the idempotency fingerprint: the caller's intent string plus
// the requested max attempts (or "omitted"). An omitted value and an explicit
// value equal to the default are different intents, per the contract.
func enqueueIntent(c Enqueue) string {
	if c.MaxAttempts == nil {
		return c.Fingerprint + "|max=omitted"
	}
	return fmt.Sprintf("%s|max=%d", c.Fingerprint, *c.MaxAttempts)
}

func (m *Model) acquire(c Acquire) Outcome {
	if c.Max <= 0 || c.Lease <= 0 {
		return Outcome{Kind: Invalid}
	}
	for _, r := range c.Receipts {
		if r == "" || m.usedReceipts[r] {
			return Outcome{Kind: Invalid}
		}
	}
	var got []Acquired
	for _, h := range m.order {
		if len(got) >= c.Max || len(got) >= len(c.Receipts) {
			break
		}
		j := m.jobs[h]
		if j.org != c.Caller.Org || j.queue != c.Queue || j.state != Scheduled || j.attempt >= j.maxAttempts {
			continue
		}
		r := c.Receipts[len(got)]
		j.attempt++
		j.state = Running
		j.receipt, j.leasePrin, j.deadline = r, c.Caller.Principal, c.Now+c.Lease
		j.lastSeq = 0
		m.usedReceipts[r] = true
		m.acquisitions[h]++
		got = append(got, Acquired{Handle: h, Attempt: j.attempt, Receipt: r})
	}
	return Outcome{Acquired: got}
}

func (m *Model) renew(c Renew) Outcome {
	j, ok := m.fence(c.Caller, c.Handle, c.Receipt, c.Now)
	if !ok {
		return Outcome{Kind: LeaseLost}
	}
	if c.Lease <= 0 {
		return Outcome{Kind: Invalid}
	}
	j.deadline = c.Now + c.Lease
	return Outcome{Handle: j.handle, Attempt: j.attempt, State: j.state}
}

func (m *Model) release(c Release) Outcome {
	j, ok := m.fence(c.Caller, c.Handle, c.Receipt, c.Now)
	if !ok {
		return Outcome{Kind: LeaseLost}
	}
	reclaim(j)
	return Outcome{Handle: j.handle, Attempt: j.attempt, State: j.state}
}

func (m *Model) complete(c Complete) Outcome {
	j, ok := m.fence(c.Caller, c.Handle, c.Receipt, c.Now)
	if !ok {
		return Outcome{Kind: LeaseLost}
	}
	if c.FinalSequence != j.lastSeq {
		return Outcome{Kind: Invalid}
	}
	clearLease(j)
	if c.Success {
		j.state = Completed
	} else {
		j.state, j.reason = Failed, "failed"
	}
	return Outcome{Handle: j.handle, Attempt: j.attempt, State: j.state}
}

func (m *Model) publish(c Publish) Outcome {
	j, ok := m.fence(c.Caller, c.Handle, c.Receipt, c.Now)
	if !ok {
		return Outcome{Kind: LeaseLost}
	}
	if len(c.Events) == 0 {
		return Outcome{Kind: Invalid}
	}
	last := j.lastSeq
	existing := j.events[j.attempt]
	var added []Record
	var ack int64
	for _, r := range c.Events {
		if r.Sequence <= 0 || r.EndSequence < r.Sequence {
			return Outcome{Kind: Invalid}
		}
		switch {
		case r.Sequence <= last:
			// Must match a committed record with the same start exactly.
			i := slices.IndexFunc(existing, func(e Record) bool { return e.Sequence == r.Sequence })
			if i < 0 {
				return Outcome{Kind: Invalid} // overlaps a committed range
			}
			if existing[i] != r {
				return Outcome{Kind: Conflict}
			}
		case r.Sequence == last+1:
			added = append(added, r)
			existing = append(slices.Clone(existing), r)
			last = r.EndSequence
		default:
			return Outcome{Kind: Invalid} // gap
		}
		ack = r.EndSequence
	}
	j.events[j.attempt] = append(j.events[j.attempt], added...)
	j.lastSeq = last
	return Outcome{Handle: j.handle, Attempt: j.attempt, AckThrough: ack, State: j.state}
}

func (m *Model) expire(c Expire) Outcome {
	for _, h := range m.order {
		if j := m.jobs[h]; j.state == Running && j.deadline <= c.Now {
			reclaim(j)
		}
	}
	return Outcome{}
}

func (m *Model) cancel(c Cancel) Outcome {
	j, ok := m.jobs[c.Handle]
	if !ok || j.org != c.Caller.Org {
		return Outcome{Kind: NotFound}
	}
	switch j.state {
	case Scheduled, Running:
		clearLease(j)
		j.state, j.reason = Cancelled, "cancelled"
	case Cancelled:
	default:
		return Outcome{Kind: Precondition}
	}
	return Outcome{Handle: j.handle, Attempt: j.attempt, State: j.state}
}

func (m *Model) list(c List) Outcome {
	return Outcome{Handles: m.List(c.Caller.Org, c.Queue)}
}

// CheckInvariants verifies structural properties of the current state and its
// transition from the previously checked state. Call it after every Apply.
func (m *Model) CheckInvariants() error {
	if m.violation != nil {
		return m.violation
	}
	for _, h := range m.order {
		j := m.jobs[h]
		if p, ok := m.prev[h]; ok {
			if p.state.Terminal() && j.state != p.state {
				return fmt.Errorf("%s: terminal %s reopened as %s", h, p.state, j.state)
			}
			if j.attempt < p.attempt {
				return fmt.Errorf("%s: attempt decreased %d -> %d", h, p.attempt, j.attempt)
			}
		}
		m.prev[h] = seen{j.state, j.attempt}
		if j.attempt > j.maxAttempts {
			return fmt.Errorf("%s: attempt %d exceeds max %d", h, j.attempt, j.maxAttempts)
		}
		if j.attempt != m.acquisitions[h] {
			return fmt.Errorf("%s: attempt %d != acquisitions %d", h, j.attempt, m.acquisitions[h])
		}
		leased := j.leasePrin != "" || j.receipt != "" || j.deadline != 0
		if (j.state == Running) != leased {
			return fmt.Errorf("%s: state %s with lease=%v", h, j.state, leased)
		}
		if j.state == Running && (j.leasePrin == "" || j.receipt == "" || j.attempt == 0) {
			return fmt.Errorf("%s: running with incomplete lease or attempt 0", h)
		}
		for a, recs := range j.events {
			if a < 1 || a > j.attempt {
				return fmt.Errorf("%s: events for invalid attempt %d", h, a)
			}
			next := int64(1)
			for _, r := range recs {
				if r.Sequence != next || r.EndSequence < r.Sequence {
					return fmt.Errorf("%s: attempt %d records not contiguous at %+v (want start %d)", h, a, r, next)
				}
				next = r.EndSequence + 1
			}
		}
		var covered int64
		if recs := j.events[j.attempt]; len(recs) > 0 {
			covered = recs[len(recs)-1].EndSequence
		}
		if j.lastSeq != covered {
			return fmt.Errorf("%s: lastSeq %d != covered %d", h, j.lastSeq, covered)
		}
	}
	return nil
}
