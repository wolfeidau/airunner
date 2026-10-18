//go:build integration

package postgres

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/models"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/storetest"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	replayHistories = flag.Int("replay.histories", 200, "number of generated histories to replay (seeds 1..N)")
	replayLength    = flag.Int("replay.length", 60, "commands per generated history")
)

// regressionSeeds are replayed on every run in addition to seeds 1..N.
// To reproduce and pin a failure, add the seed printed in the failure message,
// then run: go test -tags integration -run TestDifferentialReplay -replay.histories=0 ./internal/store/postgres/
var regressionSeeds []int64

// replayTimeScale maps one model time unit to real seconds. The generator uses
// integer offsets, so any live lease is at least one unit (3s) from expiry, which
// keeps it valid for the duration of one store call even under -race. An offset of
// zero (Now == deadline) is the exact expiry boundary and is expired in both worlds.
const replayTimeScale = 3

// replayEnabled is the full command set.
//
// Stale-receipt, wrong-holder, wrong-org, unknown-job and at-deadline token
// operations are enabled (OnlyValidTokens is false).
var replayEnabled = map[storetest.CommandKind]bool{
	storetest.KindEnqueue:  true,
	storetest.KindAcquire:  true,
	storetest.KindRenew:    true,
	storetest.KindRelease:  true,
	storetest.KindComplete: true,
	storetest.KindPublish:  true,
	storetest.KindExpire:   true,
	storetest.KindCancel:   true,
	storetest.KindList:     true,
}

// replayEnv binds model identities to real rows for one history.
type replayEnv struct {
	js      *JobStore
	orgs    map[storetest.OrgID]uuid.UUID
	orgByID map[uuid.UUID]storetest.OrgID
	callers map[storetest.Caller]jobstore.Caller
	byPrin  map[storetest.PrincipalID]uuid.UUID
	prinMod map[uuid.UUID]storetest.PrincipalID
	handles map[storetest.JobHandle]string // model handle -> real job ID
	byReal  map[string]storetest.JobHandle
	tokens  map[storetest.Receipt]string // model receipt -> real task token
	attempt map[storetest.Receipt]int32  // model receipt -> leased attempt
}

func newReplayEnv(t *testing.T, js *JobStore) *replayEnv {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	env := &replayEnv{
		js:      js,
		orgs:    map[storetest.OrgID]uuid.UUID{},
		orgByID: map[uuid.UUID]storetest.OrgID{},
		callers: map[storetest.Caller]jobstore.Caller{},
		byPrin:  map[storetest.PrincipalID]uuid.UUID{},
		prinMod: map[uuid.UUID]storetest.PrincipalID{},
		handles: map[storetest.JobHandle]string{},
		byReal:  map[string]storetest.JobHandle{},
		tokens:  map[storetest.Receipt]string{},
		attempt: map[storetest.Receipt]int32{},
	}
	principals := NewPrincipalStore(js.pool)
	// Mirrors the generator: 2 orgs x (workers n=1,2 + one user).
	for i := 1; i <= 2; i++ {
		orgModel := storetest.OrgID(fmt.Sprintf("org-%d", i))
		orgID := uuid.Must(uuid.NewV7())
		ownerID := uuid.Must(uuid.NewV7())
		require.NoError(t, NewOrganizationStore(js.pool).Create(ctx, &models.Organization{
			OrgID: orgID, Name: "org-" + orgID.String(), OwnerPrincipalID: ownerID, CreatedAt: now, UpdatedAt: now,
		}))
		env.orgs[orgModel] = orgID
		env.orgByID[orgID] = orgModel

		add := func(pid uuid.UUID, model storetest.PrincipalID, user bool) {
			p := &models.Principal{PrincipalID: pid, OrgID: orgID, Name: string(model), CreatedAt: now, UpdatedAt: now}
			if user {
				gh := "gh-" + pid.String()
				p.Type, p.GitHubID, p.Roles = "user", &gh, []string{"user"}
			} else {
				p.Type, p.Fingerprint, p.Roles = "worker", "fp-"+pid.String(), []string{"worker"}
			}
			require.NoError(t, principals.Create(ctx, p))
			env.callers[storetest.Caller{Org: orgModel, Principal: model}] = jobstore.Caller{OrgID: orgID, PrincipalID: pid}
			env.prinMod[pid] = model
			env.byPrin[model] = pid
		}
		add(ownerID, storetest.PrincipalID(fmt.Sprintf("u%d", i)), true)
		for n := 1; n <= 2; n++ {
			add(uuid.Must(uuid.NewV7()), storetest.PrincipalID(fmt.Sprintf("w%d-%d", i, n)), false)
		}
	}
	return env
}

func (e *replayEnv) caller(t *testing.T, c storetest.Caller) jobstore.Caller {
	t.Helper()
	if rc, ok := e.callers[c]; ok {
		return rc
	}
	// The generator's idempotent-retry path can pair a principal with the other
	// org (an unrealizable identity). Authentication derives the org, so use the
	// org's real ID with the named principal's real ID. A principal that exists
	// nowhere (the generator's "wrong worker") gets a random real ID.
	org, ok := e.orgs[c.Org]
	require.True(t, ok, "no real org for model caller %+v", c)
	pid, ok := e.byPrin[c.Principal]
	if !ok {
		pid = uuid.New()
	}
	return jobstore.Caller{OrgID: org, PrincipalID: pid}
}

// outcome is the store-side result translated into model terms. The adapter
// only classifies; the model alone decides what the expected result is.
type outcome struct {
	Kind     storetest.OutcomeKind
	Acquired []storetest.Acquired // Receipt left empty: real tokens are opaque
	Handles  []storetest.JobHandle
	Handle   storetest.JobHandle
	Attempt  int   // Publish
	Ack      int64 // Publish
	Err      error
}

func (o outcome) String() string {
	return fmt.Sprintf("{kind=%s acquired=%v handles=%v handle=%q attempt=%d ack=%d err=%v}", o.Kind, o.Acquired, o.Handles, o.Handle, o.Attempt, o.Ack, o.Err)
}

// classify maps a store error to an outcome kind.
//   - ErrConflict -> Conflict.
//   - ErrInvalidArgument -> Invalid.
//   - ErrLeaseLost -> LeaseLost.
//   - ErrJobNotFound -> NotFound.
//   - ErrFailedPrecondition -> Precondition.
func classify(err error) storetest.OutcomeKind {
	switch {
	case err == nil:
		return storetest.OK
	case errors.Is(err, jobstore.ErrJobNotFound):
		return storetest.NotFound
	case errors.Is(err, jobstore.ErrFailedPrecondition):
		return storetest.Precondition
	case errors.Is(err, jobstore.ErrConflict):
		return storetest.Conflict
	case errors.Is(err, jobstore.ErrInvalidArgument):
		return storetest.Invalid
	case errors.Is(err, jobstore.ErrLeaseLost):
		return storetest.LeaseLost
	}
	return storetest.OutcomeKind(-1)
}

// cmdNow returns the model time a command executes at.
func cmdNow(cmd storetest.Command) (int64, bool) {
	switch c := cmd.(type) {
	case storetest.Acquire:
		return c.Now, true
	case storetest.Renew:
		return c.Now, true
	case storetest.Release:
		return c.Now, true
	case storetest.Complete:
		return c.Now, true
	case storetest.Publish:
		return c.Now, true
	case storetest.Expire:
		return c.Now, true
	case storetest.Cancel:
		return c.Now, true
	}
	return 0, false
}

// alignDeadlines maps the model clock onto the database: every job the model
// reports Running gets visibility_until = clock_timestamp() + (deadline - now).
func (e *replayEnv) alignDeadlines(t *testing.T, model *storetest.Model, now int64) {
	t.Helper()
	var ids []string
	var secs []float64
	for h, id := range e.handles {
		if dl, ok := model.Deadline(h); ok {
			ids = append(ids, id)
			secs = append(secs, float64((dl-now)*replayTimeScale))
		}
	}
	if len(ids) == 0 {
		return
	}
	_, err := e.js.pool.Exec(context.Background(), `
		UPDATE jobs SET visibility_until = clock_timestamp() + make_interval(secs => d.secs)
		FROM unnest($1::text[], $2::float8[]) AS d(id, secs)
		WHERE jobs.job_id = d.id::uuid AND jobs.state = 2`, ids, secs)
	require.NoError(t, err)
}

// tokenFor returns the task token and job ID for a model handle and receipt.
// Receipts the store issued map to their real token. Anything else (unknown job,
// never-issued receipt) becomes a validly signed token for a nonexistent job or
// a random receipt, which the store must reject as a lost lease.
func (e *replayEnv) tokenFor(h storetest.JobHandle, r storetest.Receipt) (token, jobID string) {
	realID, known := e.handles[h]
	if !known {
		jobID = uuid.NewString()
		return e.js.encodeTaskToken(jobID, "q-1", uuid.NewString()), jobID
	}
	if tok, ok := e.tokens[r]; ok {
		return tok, realID
	}
	return e.js.encodeTaskToken(realID, "q-1", uuid.NewString()), realID
}

// eventFor builds the output batch for a model record. Timestamp and payload
// derive only from the record and handle, so identical retries are byte-identical.
func eventFor(h storetest.JobHandle, r storetest.Record, attempt int32) *jobv1.JobEvent {
	hash := fnv.New32a()
	_, _ = fmt.Fprintf(hash, "%s|%d|%d|%s", h, r.Sequence, r.EndSequence, r.ContentHash)
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(hash.Sum32()) * time.Millisecond)

	var outputs []*jobv1.OutputItem
	for i := r.Sequence; i <= r.EndSequence; i++ {
		outputs = append(outputs, &jobv1.OutputItem{Output: []byte(fmt.Sprintf("%s#%d", r.ContentHash, i))})
	}
	return &jobv1.JobEvent{
		Attempt:   attempt,
		Sequence:  r.Sequence,
		Timestamp: timestamppb.New(ts),
		EventType: jobv1.EventType_EVENT_TYPE_OUTPUT_BATCH,
		EventData: &jobv1.JobEvent_OutputBatch{OutputBatch: &jobv1.OutputBatchEvent{
			StartSequence: r.Sequence,
			EndSequence:   r.EndSequence,
			Outputs:       outputs,
		}},
	}
}

func (e *replayEnv) step(t *testing.T, cmd storetest.Command, expect storetest.Outcome) outcome {
	t.Helper()
	ctx := context.Background()
	switch c := cmd.(type) {
	case storetest.Enqueue:
		req := &jobv1.EnqueueJobRequest{
			RequestId: c.RequestID,
			Queue:     c.Queue,
			JobParams: &jobv1.JobParams{Repository: "https://github.com/test/differential", Command: c.Fingerprint},
		}
		if c.MaxAttempts != nil {
			n := int32(*c.MaxAttempts) //nolint:gosec // generator range is small
			req.MaxAttempts = &n
		}
		resp, err := e.js.EnqueueJob(ctx, e.caller(t, c.Caller), req)
		out := outcome{Kind: classify(err), Err: err}
		if err != nil {
			return out
		}
		// Bind the real ID to the model's handle (its own on creation, the
		// original on an idempotent retry).
		h := expect.Handle
		if prev, ok := e.handles[h]; ok {
			out.Handle = h
			if prev != resp.JobId {
				out.Handle = "different-real-job:" + storetest.JobHandle(resp.JobId)
			}
			return out
		}
		e.handles[h], e.byReal[resp.JobId] = resp.JobId, h
		out.Handle = h
		return out

	case storetest.Acquire:
		jobs, err := e.js.DequeueJobs(ctx, e.caller(t, c.Caller), c.Queue, c.Max, int(c.Lease))
		out := outcome{Kind: classify(err), Err: err}
		for i, jt := range jobs {
			h, ok := e.byReal[jt.Job.JobId]
			if !ok {
				h = storetest.JobHandle("unknown-real-job:" + jt.Job.JobId)
			}
			out.Acquired = append(out.Acquired, storetest.Acquired{Handle: h, Attempt: int(jt.Job.Attempt)})
			// Receipts are fresh per command and handed out in claim order, so
			// the i-th claimed job takes the i-th receipt the model issued.
			if i < len(expect.Acquired) {
				e.tokens[expect.Acquired[i].Receipt] = jt.TaskToken
				e.attempt[expect.Acquired[i].Receipt] = jt.Job.Attempt
			}
		}
		return out

	case storetest.Renew:
		token, _ := e.tokenFor(c.Handle, c.Receipt)
		_, err := e.js.UpdateJobVisibility(ctx, e.caller(t, c.Caller), token, int(c.Lease)*replayTimeScale)
		return outcome{Kind: classify(err), Err: err}

	case storetest.Release:
		token, _ := e.tokenFor(c.Handle, c.Receipt)
		err := e.js.ReleaseJob(ctx, e.caller(t, c.Caller), token)
		return outcome{Kind: classify(err), Err: err}

	case storetest.Complete:
		token, jobID := e.tokenFor(c.Handle, c.Receipt)
		err := e.js.CompleteJob(ctx, e.caller(t, c.Caller), token, &jobv1.JobResult{JobId: jobID, Success: c.Success}, c.FinalSequence)
		return outcome{Kind: classify(err), Err: err}

	case storetest.Publish:
		token, _ := e.tokenFor(c.Handle, c.Receipt)
		// The worker stamps the leased attempt; receipts the store never issued fall back to 1.
		attempt := max(e.attempt[c.Receipt], 1)
		events := make([]*jobv1.JobEvent, 0, len(c.Events))
		for _, r := range c.Events {
			events = append(events, eventFor(c.Handle, r, attempt))
		}
		res, err := e.js.PublishEvents(ctx, e.caller(t, c.Caller), token, events)
		out := outcome{Kind: classify(err), Err: err}
		if err == nil {
			out.Attempt, out.Ack = int(res.Attempt), res.AcknowledgedThroughSequence
		}
		return out

	case storetest.Cancel:
		realID, known := e.handles[c.Handle]
		if !known {
			realID = uuid.NewString()
		}
		_, err := e.js.CancelJob(ctx, e.caller(t, c.Caller), realID)
		return outcome{Kind: classify(err), Err: err}

	case storetest.Expire:
		_, err := e.js.ReapExpired(ctx, 1_000_000)
		return outcome{Kind: classify(err), Err: err}

	case storetest.List:
		resp, err := e.js.ListJobs(ctx, e.caller(t, c.Caller), &jobv1.ListJobsRequest{Queue: c.Queue, PageSize: 100})
		out := outcome{Kind: classify(err), Err: err}
		if err != nil {
			return out
		}
		for _, j := range resp.Jobs {
			out.Handles = append(out.Handles, e.byReal[j.JobId])
		}
		slices.Reverse(out.Handles) // ListJobs is newest first; the model is creation order
		return out
	}
	t.Fatalf("command kind %T is not enabled in the replay", cmd)
	return outcome{}
}

// storeView is the store-side projection compared against the model.
type storeView struct {
	storetest.JobView
	LastSeq   int64
	Exhausted bool
}

// views reads the normalized view of every known job directly from Postgres.
func (e *replayEnv) views(t *testing.T) map[storetest.JobHandle]storeView {
	t.Helper()
	ids := make([]string, 0, len(e.handles))
	for _, id := range e.handles {
		ids = append(ids, id)
	}
	rows, err := e.js.pool.Query(context.Background(),
		`SELECT job_id, org_id, state, attempt, max_attempts, leased_by, last_event_sequence,
		        COALESCE(result->>'reason', '') = 'delivery attempts exhausted'
		 FROM jobs WHERE job_id = ANY($1)`, ids)
	require.NoError(t, err)
	defer rows.Close()
	out := map[storetest.JobHandle]storeView{}
	for rows.Next() {
		var (
			id            string
			org           uuid.UUID
			state         int
			attempt, maxA int
			leasedBy      *uuid.UUID
			lastSeq       int64
			exhausted     bool
		)
		require.NoError(t, rows.Scan(&id, &org, &state, &attempt, &maxA, &leasedBy, &lastSeq, &exhausted))
		v := storetest.JobView{State: storetest.State(state), Attempt: attempt, MaxAttempts: maxA, Org: e.orgByID[org]}
		if leasedBy != nil {
			v.LeasePrincipal = e.prinMod[*leasedBy]
		}
		out[e.byReal[id]] = storeView{JobView: v, LastSeq: lastSeq, Exhausted: exhausted}
	}
	require.NoError(t, rows.Err())
	return out
}

func replayHistory(t *testing.T, js *JobStore, seed int64) {
	cmds := storetest.Generate(seed, *replayLength, storetest.GenOptions{
		Enabled:         replayEnabled,
		OnlyValidTokens: false,
	})
	env := newReplayEnv(t, js)
	model := storetest.New()

	for i, cmd := range cmds {
		if now, ok := cmdNow(cmd); ok {
			env.alignDeadlines(t, model, now)
		}
		want := model.Apply(cmd)
		got := env.step(t, cmd, want)

		fail := func(why string, mv, sv any) {
			t.Fatalf("differential mismatch (%s)\n  reproduce: add seed %d to regressionSeeds, run -run TestDifferentialReplay -replay.histories=0\n  seed=%d step=%d\n  command=%#v\n  model outcome=%+v\n  store outcome=%s\n  model=%+v\n  store=%+v",
				why, seed, seed, i, cmd, want, got, mv, sv)
		}

		if got.Kind != want.Kind {
			fail("outcome kind", want.Kind, got.Kind)
		}
		if want.Kind == storetest.OK {
			switch cmd.(type) {
			case storetest.Enqueue:
				if got.Handle != want.Handle {
					fail("enqueue handle", want.Handle, got.Handle)
				}
			case storetest.Acquire:
				type ha struct {
					H storetest.JobHandle
					A int
				}
				var mw, sw []ha
				for _, a := range want.Acquired {
					mw = append(mw, ha{a.Handle, a.Attempt})
				}
				for _, a := range got.Acquired {
					sw = append(sw, ha{a.Handle, a.Attempt})
				}
				if !slices.Equal(mw, sw) {
					fail("acquired handles/attempts", mw, sw)
				}
			case storetest.Publish:
				if got.Attempt != want.Attempt || got.Ack != want.AckThrough {
					fail("publish attempt/ack", [2]int64{int64(want.Attempt), want.AckThrough}, [2]int64{int64(got.Attempt), got.Ack})
				}
			case storetest.List:
				if !slices.Equal(want.Handles, got.Handles) {
					fail("list handles", want.Handles, got.Handles)
				}
			}
		}

		sv := env.views(t)
		for h := range env.handles {
			mv, ok := model.Job(h)
			if !ok {
				fail("model lost job "+string(h), nil, nil)
			}
			if sv[h].JobView != mv {
				fail("job view "+string(h), mv, sv[h].JobView)
			}
			if want := model.LastSequence(h); sv[h].LastSeq != want {
				fail("last_event_sequence "+string(h), want, sv[h].LastSeq)
			}
			if want := model.Reason(h) == "exhausted"; sv[h].Exhausted != want {
				fail("exhausted reason "+string(h), want, sv[h].Exhausted)
			}
		}
		if len(sv) != len(env.handles) {
			fail("job count", len(env.handles), len(sv))
		}
		if err := model.CheckInvariants(); err != nil {
			fail("model invariant: "+err.Error(), nil, nil)
		}
	}
}

func TestDifferentialReplay(t *testing.T) {
	// One database for the whole test; each history creates its own orgs and
	// principals, and every store call is org-scoped, so histories are isolated.
	js, _ := setupStore(t)
	// Stop the background reaper: expiry must happen only at the model's Expire
	// commands. The pool stays open, so ReapExpired and all fenced calls still work.
	require.NoError(t, js.Stop())

	seeds := make([]int64, 0, *replayHistories+len(regressionSeeds))
	for s := int64(1); s <= int64(*replayHistories); s++ {
		seeds = append(seeds, s)
	}
	seeds = append(seeds, regressionSeeds...)

	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			replayHistory(t, js, seed)
		})
	}
}
