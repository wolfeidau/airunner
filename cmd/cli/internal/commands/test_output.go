package commands

import (
	"context"
	"fmt"
	"time"
)

type TestOutputCmd struct {
	Pattern  string        `help:"Output pattern (burst|steady|gaps|mixed)" default:"mixed"`
	Lines    int           `help:"Number of lines to output" default:"20"`
	Interval time.Duration `help:"Base interval between lines" default:"100ms"`
}

func (t *TestOutputCmd) Run(ctx context.Context, globals *Globals) error {
	fmt.Printf("=== Test Output Generator ===\n")
	fmt.Printf("Pattern: %s, Lines: %d, Interval: %v\n", t.Pattern, t.Lines, t.Interval)
	fmt.Printf("Started at: %s\n", time.Now().Format("15:04:05.000"))
	fmt.Printf("=============================\n\n")

	switch t.Pattern {
	case "burst":
		return t.runBurst(ctx)
	case "steady":
		return t.runSteady(ctx)
	case "gaps":
		return t.runGaps(ctx)
	case "mixed":
		return t.runMixed(ctx)
	default:
		return fmt.Errorf("unknown pattern: %s", t.Pattern)
	}
}

// runBurst outputs all lines immediately
func (t *TestOutputCmd) runBurst(ctx context.Context) error {
	start := time.Now()
	for i := 0; i < t.Lines; i++ {
		elapsed := time.Since(start)
		fmt.Printf("[%s +%8s] Line %3d: Burst output (no delay)\n",
			time.Now().Format("15:04:05.000"), elapsed.Round(time.Millisecond), i+1)
	}
	fmt.Printf("\n=== Burst Complete (Total: %v) ===\n", time.Since(start).Round(time.Millisecond))
	return nil
}

// runSteady outputs lines at regular intervals
func (t *TestOutputCmd) runSteady(ctx context.Context) error {
	start := time.Now()
	for i := 0; i < t.Lines; i++ {
		elapsed := time.Since(start)
		fmt.Printf("[%s +%8s] Line %3d: Steady output (interval: %v)\n",
			time.Now().Format("15:04:05.000"), elapsed.Round(time.Millisecond), i+1, t.Interval)

		if i < t.Lines-1 { // Don't sleep after last line
			time.Sleep(t.Interval)
		}
	}
	fmt.Printf("\n=== Steady Complete (Total: %v) ===\n", time.Since(start).Round(time.Millisecond))
	return nil
}

// runGaps outputs lines with increasing gaps
func (t *TestOutputCmd) runGaps(ctx context.Context) error {
	start := time.Now()
	for i := 0; i < t.Lines; i++ {
		elapsed := time.Since(start)
		gap := time.Duration(i) * t.Interval // Increasing gap
		fmt.Printf("[%s +%8s] Line %3d: Gap output (next gap: %v)\n",
			time.Now().Format("15:04:05.000"), elapsed.Round(time.Millisecond), i+1, gap)

		if i < t.Lines-1 {
			time.Sleep(gap)
		}
	}
	fmt.Printf("\n=== Gaps Complete (Total: %v) ===\n", time.Since(start).Round(time.Millisecond))
	return nil
}

// runMixed outputs with a realistic mixed pattern
func (t *TestOutputCmd) runMixed(ctx context.Context) error {
	start := time.Now()

	// Phase 1: Initial burst (5 lines, no delay)
	fmt.Printf("Phase 1: Initial burst...\n")
	for i := 0; i < 5; i++ {
		elapsed := time.Since(start)
		fmt.Printf("[%s +%8s] Line %3d: Initial burst\n",
			time.Now().Format("15:04:05.000"), elapsed.Round(time.Millisecond), i+1)
	}

	// Small gap
	time.Sleep(t.Interval * 2)

	// Phase 2: Steady output (5 lines, regular interval)
	fmt.Printf("\nPhase 2: Steady output...\n")
	for i := 5; i < 10; i++ {
		elapsed := time.Since(start)
		fmt.Printf("[%s +%8s] Line %3d: Steady phase\n",
			time.Now().Format("15:04:05.000"), elapsed.Round(time.Millisecond), i+1)
		time.Sleep(t.Interval)
	}

	// Long gap (simulating a quiet period)
	fmt.Printf("\nPhase 3: Long gap (simulating processing)...\n")
	time.Sleep(t.Interval * 10)

	// Phase 3: Final burst (remaining lines)
	fmt.Printf("\nPhase 4: Final burst...\n")
	remaining := t.Lines - 10
	for i := 0; i < remaining; i++ {
		elapsed := time.Since(start)
		fmt.Printf("[%s +%8s] Line %3d: Final burst\n",
			time.Now().Format("15:04:05.000"), elapsed.Round(time.Millisecond), i+11)
	}

	fmt.Printf("\n=== Mixed Complete (Total: %v) ===\n", time.Since(start).Round(time.Millisecond))
	return nil
}
