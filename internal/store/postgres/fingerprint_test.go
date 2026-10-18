package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

func TestEnqueueFingerprint(t *testing.T) {
	base := func() *jobv1.JobParams {
		return &jobv1.JobParams{
			Repository:  "https://github.com/test/repo",
			Command:     "echo",
			Args:        []string{"a", "b"},
			Environment: map[string]string{"A": "1", "B": "2", "C": "3"},
		}
	}
	three := int32(3)
	four := int32(4)

	fp := func(queue string, p *jobv1.JobParams, m *int32) string {
		t.Helper()
		b, err := enqueueFingerprint(queue, p, m)
		require.NoError(t, err)
		return string(b)
	}

	want := fp("q", base(), &three)

	t.Run("equal intents hash equal", func(t *testing.T) {
		for range 20 { // map iteration order must not matter
			require.Equal(t, want, fp("q", base(), &three))
		}
	})

	t.Run("queue change", func(t *testing.T) {
		require.NotEqual(t, want, fp("q2", base(), &three))
	})

	t.Run("params change", func(t *testing.T) {
		p := base()
		p.Command = "ls"
		require.NotEqual(t, want, fp("q", p, &three))
	})

	t.Run("max attempts value change", func(t *testing.T) {
		require.NotEqual(t, want, fp("q", base(), &four))
	})

	t.Run("omitted differs from explicit", func(t *testing.T) {
		require.NotEqual(t, want, fp("q", base(), nil))
		require.NotEqual(t, fp("q", base(), nil), fp("q", base(), new(int32)))
	})

	t.Run("field boundaries are unambiguous", func(t *testing.T) {
		require.NotEqual(t, fp("ab", &jobv1.JobParams{Repository: "c"}, nil), fp("a", &jobv1.JobParams{Repository: "bc"}, nil))
	})
}
