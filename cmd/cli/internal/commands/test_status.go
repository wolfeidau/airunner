package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wolfeidau/osc7501"
)

// TestStatusCmd emits OSC 7501 program status reports for demos and testing.
type TestStatusCmd struct {
	Scenario  string        `help:"Scenario to emit (happy|blocked|fail)" enum:"happy,blocked,fail" default:"happy"`
	Steps     int           `help:"Progress updates per id" default:"5"`
	StepDelay time.Duration `help:"Delay between steps" default:"500ms"`

	out io.Writer `kong:"-"`
}

func (t *TestStatusCmd) Run(ctx context.Context, globals *Globals) error {
	out := t.out
	if out == nil {
		out = os.Stdout
	}
	r := osc7501.NewReporter(out, "airunner-demo")

	if err := t.phase(ctx, out, r, "build/compile", "compiling package"); err != nil {
		return err
	}

	if t.Scenario == "blocked" {
		if err := r.Blocked("build/deploy", osc7501.KindQuestion, "Approve deploy?"); err != nil {
			return err
		}
		fmt.Fprintln(out, "waiting for deploy approval...")
		if err := t.sleep(ctx); err != nil {
			return err
		}
		fmt.Fprintln(out, "auto-approved for demo")
		if err := t.phase(ctx, out, r, "build/deploy", "deploying stage"); err != nil {
			return err
		}
	}

	if t.Scenario == "fail" {
		for i := 1; i <= 2; i++ {
			fmt.Fprintf(out, "running test batch %d/2...\n", i)
			if err := r.Working("build/test", i*40, fmt.Sprintf("batch %d/2", i)); err != nil {
				return err
			}
			if err := t.sleep(ctx); err != nil {
				return err
			}
		}
		if err := r.Failed("build/test", "2 tests failed"); err != nil {
			return err
		}
		fmt.Fprintln(out, "FAIL: 2 tests failed")
		return fmt.Errorf("test-status: simulated failure")
	}

	if err := t.phase(ctx, out, r, "build/test", "running test"); err != nil {
		return err
	}
	if err := r.Done("build", "all steps complete"); err != nil {
		return err
	}
	fmt.Fprintln(out, "build complete")
	return nil
}

// phase reports id working from 0 to 100 over Steps steps, then done.
func (t *TestStatusCmd) phase(ctx context.Context, out io.Writer, r *osc7501.Reporter, id, text string) error {
	steps := max(t.Steps, 1)
	for i := 1; i <= steps; i++ {
		progress := 100 * (i - 1) / max(steps-1, 1)
		if steps == 1 {
			progress = 100
		}
		fmt.Fprintf(out, "%s %d/%d...\n", text, i, steps)
		if err := r.Working(id, progress, fmt.Sprintf("%s %d/%d", text, i, steps)); err != nil {
			return err
		}
		if err := t.sleep(ctx); err != nil {
			return err
		}
	}
	if err := r.Done(id, "done"); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s finished\n", id)
	return nil
}

func (t *TestStatusCmd) sleep(ctx context.Context) error {
	if t.StepDelay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(t.StepDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
