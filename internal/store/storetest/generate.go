package storetest

import (
	"fmt"
	"math/rand/v2"
	"slices"
)

// GenOptions restricts the generated histories.
type GenOptions struct {
	// Enabled limits the command kinds; nil enables all.
	Enabled map[CommandKind]bool
	// OnlyValidTokens makes every token operation (renew, release, complete,
	// publish) carry the live lease holder's identity and an unexpired time.
	OnlyValidTokens bool
	// Lease is the lease duration; zero picks a random duration per acquire.
	Lease int64
}

type reqRecord struct {
	org   OrgID
	id    string
	fp    string
	queue string
}

type generator struct {
	r        *rand.Rand
	m        *Model
	opts     GenOptions
	kinds    []CommandKind
	now      int64
	jobN     int
	rcptN    int
	reqN     int
	reqs     []reqRecord
	receipts map[JobHandle][]Receipt
}

var (
	genOrgs   = []OrgID{"org-1", "org-2"}
	genQueues = []string{"q-1", "q-2"}
)

func genWorker(org, n int) Caller {
	return Caller{Org: genOrgs[org], Principal: PrincipalID(fmt.Sprintf("w%d-%d", org+1, n+1))}
}

func genUser(org int) Caller {
	return Caller{Org: genOrgs[org], Principal: PrincipalID(fmt.Sprintf("u%d", org+1))}
}

// Generate returns a deterministic, plausible command history of up to n
// commands. It steps a private Model so token-bearing commands can reference
// real leases. The result can be replayed against any implementation.
func Generate(seed int64, n int, opts GenOptions) []Command {
	src := rand.NewPCG(uint64(seed), 0x9e3779b97f4a7c15) //nolint:gosec // wraparound is fine for seeding
	g := &generator{
		r:        rand.New(src), //nolint:gosec // deterministic test histories, not security
		m:        New(),
		opts:     opts,
		receipts: map[JobHandle][]Receipt{},
	}
	for _, k := range AllKinds {
		if opts.Enabled == nil || opts.Enabled[k] {
			g.kinds = append(g.kinds, k)
		}
	}
	if len(g.kinds) == 0 {
		return nil
	}
	var cmds []Command
	for tries := 0; len(cmds) < n && tries < n*20; tries++ {
		g.advance()
		cmd := g.next(g.kinds[g.r.IntN(len(g.kinds))])
		if cmd == nil {
			continue
		}
		g.observe(cmd, g.m.Apply(cmd))
		cmds = append(cmds, cmd)
	}
	return cmds
}

func (g *generator) observe(cmd Command, out Outcome) {
	if _, ok := cmd.(Acquire); ok {
		for _, got := range out.Acquired {
			g.receipts[got.Handle] = append(g.receipts[got.Handle], got.Receipt)
		}
	}
}

// advance moves time forward, sometimes landing exactly on a lease deadline.
func (g *generator) advance() {
	switch x := g.r.IntN(10); {
	case x < 5:
		g.now += int64(g.r.IntN(5))
	case x == 5:
		for _, j := range g.running() {
			if j.deadline >= g.now {
				g.now = j.deadline
				return
			}
		}
	}
}

func (g *generator) running() []*job {
	var out []*job
	for _, h := range g.m.order {
		if j := g.m.jobs[h]; j.state == Running {
			out = append(out, j)
		}
	}
	return out
}

func (g *generator) pick(n int) int { return g.r.IntN(n) }

func (g *generator) chance(pct int) bool { return g.r.IntN(100) < pct }

func (g *generator) caller() Caller {
	o := g.pick(2)
	if g.chance(20) {
		return genUser(o)
	}
	return genWorker(o, g.pick(2))
}

func (g *generator) next(k CommandKind) Command {
	switch k {
	case KindEnqueue:
		return g.enqueue()
	case KindAcquire:
		return g.acquire()
	case KindExpire:
		return Expire{Now: g.now}
	case KindList:
		return List{Caller: g.caller(), Queue: genQueues[g.pick(2)]}
	case KindCancel:
		return g.cancel()
	default:
		return g.tokenOp(k)
	}
}

func (g *generator) enqueue() Command {
	c := Enqueue{Caller: g.caller(), Queue: genQueues[g.pick(2)], DefaultMaxAttempts: 3}
	g.jobN++
	c.Handle = JobHandle(fmt.Sprintf("job-%d", g.jobN))
	if len(g.reqs) > 0 && g.chance(35) {
		prev := g.reqs[g.pick(len(g.reqs))]
		c.RequestID, c.Fingerprint, c.Queue = prev.id, prev.fp, prev.queue
		if g.chance(50) {
			c.Fingerprint += "-changed"
		}
		if g.chance(50) {
			// Retry from the original org; principals only exist within their own org
			c.Caller = genUser(slices.Index(genOrgs, prev.org))
		}
	} else {
		g.reqN++
		c.RequestID = fmt.Sprintf("req-%d", g.reqN)
		c.Fingerprint = fmt.Sprintf("fp-%d", g.reqN)
		g.reqs = append(g.reqs, reqRecord{c.Caller.Org, c.RequestID, c.Fingerprint, c.Queue})
	}
	if g.chance(40) {
		v := 1 + g.pick(4)
		if g.chance(5) {
			v = []int{0, -1, 101}[g.pick(3)]
		}
		c.MaxAttempts = &v
	}
	return c
}

func (g *generator) acquire() Command {
	o := g.pick(2)
	maxN := 1 + g.pick(3)
	c := Acquire{Caller: genWorker(o, g.pick(2)), Queue: genQueues[g.pick(2)], Max: maxN, Now: g.now, Lease: g.opts.Lease}
	if c.Lease == 0 {
		c.Lease = int64(3 + g.pick(8))
	}
	for range maxN {
		g.rcptN++
		c.Receipts = append(c.Receipts, Receipt(fmt.Sprintf("rcpt-%d", g.rcptN)))
	}
	return c
}

func (g *generator) cancel() Command {
	if len(g.m.order) == 0 {
		return nil
	}
	j := g.m.jobs[g.m.order[g.pick(len(g.m.order))]]
	c := Cancel{Caller: g.caller(), Handle: j.handle, Now: g.now}
	if !g.chance(15) {
		c.Caller.Org = j.org
	}
	if g.chance(5) {
		c.Handle = "job-unknown"
	}
	return c
}

// tokenOp builds renew, release, complete, or publish for a chosen job,
// optionally corrupting the token.
func (g *generator) tokenOp(k CommandKind) Command {
	var j *job
	if run := g.running(); len(run) > 0 {
		if g.opts.OnlyValidTokens {
			var live []*job
			for _, r := range run {
				if g.now < r.deadline {
					live = append(live, r)
				}
			}
			run = live
		}
		if len(run) > 0 {
			j = run[g.pick(len(run))]
		}
	}
	if j == nil {
		if g.opts.OnlyValidTokens || len(g.m.order) == 0 {
			return nil
		}
		j = g.m.jobs[g.m.order[g.pick(len(g.m.order))]]
	}
	caller := Caller{Org: j.org, Principal: j.leasePrin}
	if caller.Principal == "" {
		caller.Principal = genWorker(0, 0).Principal
	}
	handle, receipt, now := j.handle, j.receipt, g.now
	if rs := g.receipts[handle]; receipt == "" && len(rs) > 0 {
		receipt = rs[len(rs)-1] // stale: lease was already given up
	}
	if !g.opts.OnlyValidTokens && g.chance(25) {
		switch g.pick(5) {
		case 0: // stale receipt
			if rs := g.receipts[handle]; len(rs) > 1 {
				receipt = rs[0]
			} else {
				receipt = "rcpt-bogus"
			}
		case 1: // wrong worker, same org
			caller.Principal = PrincipalID(string(caller.Principal) + "-other")
		case 2: // wrong org
			caller.Org = genOrgs[(indexOfOrg(j.org)+1)%2]
		case 3: // unknown job
			handle = "job-unknown"
		case 4: // exactly at the deadline
			if j.state == Running {
				now = j.deadline
			}
		}
	}
	switch k {
	case KindRenew:
		return Renew{Caller: caller, Handle: handle, Receipt: receipt, Now: now, Lease: int64(3 + g.pick(8))}
	case KindRelease:
		return Release{Caller: caller, Handle: handle, Receipt: receipt, Now: now}
	case KindComplete:
		final := j.lastSeq
		if !g.opts.OnlyValidTokens && g.chance(15) {
			final++
		}
		return Complete{Caller: caller, Handle: handle, Receipt: receipt, Now: now, Success: g.chance(70), FinalSequence: final}
	default:
		return Publish{Caller: caller, Handle: handle, Receipt: receipt, Now: now, Events: g.events(j)}
	}
}

func indexOfOrg(o OrgID) int {
	if o == genOrgs[1] {
		return 1
	}
	return 0
}

// events builds a publish batch, mostly extending the committed prefix and
// sometimes retrying, rewriting, gapping, or overlapping it.
func (g *generator) events(j *job) []Record {
	recs := j.events[j.attempt]
	next := j.lastSeq + 1
	fresh := func(start int64, n int) []Record {
		var out []Record
		for range n {
			end := start + int64(g.pick(5))
			out = append(out, Record{Sequence: start, EndSequence: end, ContentHash: fmt.Sprintf("h-%d-%d-%d", j.attempt, start, end)})
			start = end + 1
		}
		return out
	}
	switch x := g.pick(10); {
	case x == 0 && len(recs) > 0: // identical retry
		return []Record{recs[g.pick(len(recs))]}
	case x == 1 && len(recs) > 0 && !g.opts.OnlyValidTokens: // changed content
		r := recs[g.pick(len(recs))]
		r.ContentHash += "-x"
		return []Record{r}
	case x == 2 && !g.opts.OnlyValidTokens: // gap
		return fresh(next+1, 1)
	case x == 3 && next > 1 && !g.opts.OnlyValidTokens: // overlap
		return []Record{{Sequence: next - 1, EndSequence: next, ContentHash: "overlap"}}
	case x == 4 && !g.opts.OnlyValidTokens: // malformed
		return []Record{{Sequence: next + 2, EndSequence: next, ContentHash: "bad"}}
	}
	return fresh(next, 1+g.pick(3))
}
