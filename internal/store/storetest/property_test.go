package storetest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func runHistory(t *testing.T, seed int64, n int) map[OutcomeKind]int {
	t.Helper()
	m := New()
	kinds := map[OutcomeKind]int{}
	for i, c := range Generate(seed, n, GenOptions{}) {
		before := m.Snapshot()
		out := m.Apply(c)
		kinds[out.Kind]++
		require.NoError(t, m.CheckInvariants(), "seed %d step %d %#v", seed, i, c)
		if out.Kind != OK {
			require.Equal(t, before, m.Snapshot(), "seed %d step %d: rejected %#v changed state", seed, i, c)
		}
	}
	return kinds
}

func TestPropertyGeneratedHistories(t *testing.T) {
	total := map[OutcomeKind]int{}
	for seed := int64(1); seed <= 500; seed++ {
		for k, v := range runHistory(t, seed, 200) {
			total[k] += v
		}
	}
	// The generator must exercise both accepted and rejected paths.
	for _, k := range []OutcomeKind{OK, LeaseLost, Conflict, NotFound, Invalid, Precondition} {
		require.Positive(t, total[k], "no %s outcomes generated", k)
	}
}

func FuzzJobContract(f *testing.F) {
	f.Add(int64(1), uint16(50))
	f.Add(int64(42), uint16(200))
	f.Add(int64(-7), uint16(0))
	f.Fuzz(func(t *testing.T, seed int64, n uint16) {
		runHistory(t, seed, int(n%400))
	})
}
