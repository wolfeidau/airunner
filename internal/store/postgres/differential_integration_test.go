//go:build integration

package postgres

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/models"
	jobstore "github.com/wolfeidau/airunner/internal/store"
	"github.com/wolfeidau/airunner/internal/store/storetest"
)

var (
	replayHistories = flag.Int("replay.histories", 200, "number of generated histories to replay (seeds 1..N)")
	replayLength    = flag.Int("replay.length", 60, "commands per generated history")
)

// regressionSeeds are replayed on every run in addition to seeds 1..N.
// To reproduce and pin a failure, add the seed printed in the failure message,
// then run: go test -tags integration -run TestDifferentialReplay -replay.histories=0 ./internal/store/postgres/
var regressionSeeds []int64

// replayLeaseSeconds keeps wall-clock lease expiry out of phase 2 histories.
const replayLeaseSeconds = 3600

// replayEnabled is the phase 2 command set.
//
// Disabled kinds and the phase that enables each:
//
//	Renew                    phase 4 (lease fencing and renewal)
//	Release                  phase 4
//	Expire                   phase 4 (reaper)
//	Publish                  phase 4 (contiguous, idempotent event publish)
//	stale-token operations   phase 4 (OnlyValidTokens is dropped, enabling stale/wrong-holder tokens)
//	Cancel                   phase 6
var replayEnabled = map[storetest.CommandKind]bool{
	storetest.KindEnqueue:  true,
	storetest.KindAcquire:  true,
	storetest.KindComplete: true,
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
	// org's real ID with the named principal's real ID.
	org, ok1 := e.orgs[c.Org]
	pid, ok2 := e.byPrin[c.Principal]
	require.True(t, ok1 && ok2, "no real identity for model caller %+v", c)
	return jobstore.Caller{OrgID: org, PrincipalID: pid}
}

// outcome is the store-side result translated into model terms. The adapter
// only classifies; the model alone decides what the expected result is.
type outcome struct {
	Kind     storetest.OutcomeKind
	Acquired []storetest.Acquired // Receipt left empty: real tokens are opaque
	Handles  []storetest.JobHandle
	Handle   storetest.JobHandle
	Err      error
}

func (o outcome) String() string {
	return fmt.Sprintf("{kind=%s acquired=%v handles=%v handle=%q err=%v}", o.Kind, o.Acquired, o.Handles, o.Handle, o.Err)
}

// classify maps a store error to an outcome kind.
//   - ErrConflict -> Conflict.
//   - ErrInvalidArgument -> Invalid.
//   - ErrLeaseLost -> LeaseLost.
func classify(err error) storetest.OutcomeKind {
	switch {
	case err == nil:
		return storetest.OK
	case errors.Is(err, jobstore.ErrConflict):
		return storetest.Conflict
	case errors.Is(err, jobstore.ErrInvalidArgument):
		return storetest.Invalid
	case errors.Is(err, jobstore.ErrLeaseLost):
		return storetest.LeaseLost
	}
	return storetest.OutcomeKind(-1)
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
			}
		}
		return out

	case storetest.Complete:
		token, ok := e.tokens[c.Receipt]
		require.True(t, ok, "no real token for receipt %q", c.Receipt)
		err := e.js.CompleteJob(ctx, e.caller(t, c.Caller), token, &jobv1.JobResult{JobId: e.handles[c.Handle], Success: c.Success})
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
	t.Fatalf("command kind %T is not enabled in phase 2", cmd)
	return outcome{}
}

// views reads the normalized view of every known job directly from Postgres.
func (e *replayEnv) views(t *testing.T) map[storetest.JobHandle]storetest.JobView {
	t.Helper()
	ids := make([]string, 0, len(e.handles))
	for _, id := range e.handles {
		ids = append(ids, id)
	}
	rows, err := e.js.pool.Query(context.Background(),
		`SELECT job_id, org_id, state, attempt, max_attempts, leased_by FROM jobs WHERE job_id = ANY($1)`, ids)
	require.NoError(t, err)
	defer rows.Close()
	out := map[storetest.JobHandle]storetest.JobView{}
	for rows.Next() {
		var (
			id            string
			org           uuid.UUID
			state         int
			attempt, maxA int
			leasedBy      *uuid.UUID
		)
		require.NoError(t, rows.Scan(&id, &org, &state, &attempt, &maxA, &leasedBy))
		v := storetest.JobView{State: storetest.State(state), Attempt: attempt, MaxAttempts: maxA, Org: e.orgByID[org]}
		if leasedBy != nil {
			v.LeasePrincipal = e.prinMod[*leasedBy]
		}
		out[e.byReal[id]] = v
	}
	require.NoError(t, rows.Err())
	return out
}

func replayHistory(t *testing.T, js *JobStore, seed int64) {
	cmds := storetest.Generate(seed, *replayLength, storetest.GenOptions{
		Enabled:         replayEnabled,
		OnlyValidTokens: true,
		Lease:           replayLeaseSeconds,
	})
	env := newReplayEnv(t, js)
	model := storetest.New()

	for i, cmd := range cmds {
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
			if sv[h] != mv {
				fail("job view "+string(h), mv, sv[h])
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
