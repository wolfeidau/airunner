package commands

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wolfeidau/osc7501"
)

func runTestStatus(t *testing.T, scenario string) (string, []osc7501.Report, error) {
	t.Helper()
	var buf bytes.Buffer
	cmd := &TestStatusCmd{Scenario: scenario, Steps: 3, out: &buf}
	err := cmd.Run(context.Background(), &Globals{})

	var reports []osc7501.Report
	s := &osc7501.Scanner{W: io.Discard, OnReport: func(r osc7501.Report) { reports = append(reports, r) }}
	_, werr := s.Write(buf.Bytes())
	require.NoError(t, werr)
	return buf.String(), reports, err
}

func seq(reports []osc7501.Report) []string {
	var out []string
	for _, r := range reports {
		out = append(out, r.State+" "+r.ID)
	}
	return out
}

func TestTestStatusHappy(t *testing.T) {
	text, reports, err := runTestStatus(t, "happy")
	require.NoError(t, err)
	got := seq(reports)
	require.Contains(t, got, "done build/compile")
	require.Contains(t, got, "done build/test")
	require.Equal(t, "done build", got[len(got)-1])
	require.Contains(t, text, "compiling package 3/3...")
}

func TestTestStatusBlocked(t *testing.T) {
	text, reports, err := runTestStatus(t, "blocked")
	require.NoError(t, err)
	got := seq(reports)
	require.Contains(t, got, "blocked build/deploy")
	require.Contains(t, got, "done build/deploy")
	require.Equal(t, "done build", got[len(got)-1])
	for _, r := range reports {
		if r.State == osc7501.StateBlocked {
			require.Equal(t, osc7501.KindQuestion, r.Kind)
		}
	}
	require.Contains(t, text, "auto-approved for demo")
}

func TestTestStatusFail(t *testing.T) {
	text, reports, err := runTestStatus(t, "fail")
	require.Error(t, err)
	got := seq(reports)
	require.Contains(t, got, "done build/compile")
	require.Equal(t, "error build/test", got[len(got)-1])
	require.Contains(t, text, "FAIL: 2 tests failed")
}

func TestTestStatusCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &TestStatusCmd{Scenario: "happy", Steps: 3, StepDelay: 1e9, out: io.Discard}
	require.ErrorIs(t, cmd.Run(ctx, &Globals{}), context.Canceled)
}
