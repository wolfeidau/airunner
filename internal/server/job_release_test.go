package server

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/internal/store"
)

// releaseRecorder records ReleaseJob calls; other JobStore methods are unimplemented.
type releaseRecorder struct {
	store.JobStore
	tokens  []string
	callers []store.Caller
	ctxErrs []error
	failFor string
}

func (r *releaseRecorder) ReleaseJob(ctx context.Context, caller store.Caller, token string) error {
	r.tokens = append(r.tokens, token)
	r.callers = append(r.callers, caller)
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	if token == r.failFor {
		return errors.New("release failed")
	}
	return nil
}

// TestReleaseUnsent covers the delivery-failure cleanup. A connect.ServerStream cannot be
// faked, so the stream-failure branch of DequeueJob is exercised through releaseUnsent,
// which it calls with jobs[i:] (the failed job plus all unsent jobs).
func TestReleaseUnsent(t *testing.T) {
	rec := &releaseRecorder{failFor: "t2"}
	srv := NewJobServer(rec)
	caller := store.Caller{OrgID: uuid.New(), PrincipalID: uuid.New()}

	jobs := []*store.JobWithToken{
		{Job: &jobv1.Job{JobId: "j1"}, TaskToken: "t1"},
		{Job: &jobv1.Job{JobId: "j2"}, TaskToken: "t2"},
		{Job: &jobv1.Job{JobId: "j3"}, TaskToken: "t3"},
	}

	// The request context is already cancelled, as after a client disconnect.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv.releaseUnsent(ctx, caller, jobs)

	// A failed release does not stop later releases; releases ignore request cancellation.
	require.Equal(t, []string{"t1", "t2", "t3"}, rec.tokens)
	for i := range rec.tokens {
		require.Equal(t, caller, rec.callers[i])
		require.NoError(t, rec.ctxErrs[i])
	}
}

func TestValidateVisibilityTimeout(t *testing.T) {
	for in, want := range map[int32]int{0: 300, 30: 30, 3600: 3600, 300: 300} {
		got, err := validateVisibilityTimeout(in)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	for _, in := range []int32{-1, 1, 29, 3601, 4000} {
		_, err := validateVisibilityTimeout(in)
		require.Error(t, err, in)
	}
}
