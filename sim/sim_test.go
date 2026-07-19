package sim

import (
	"errors"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// The scripted guest: two compensatable effects around reads and one
// non-compensatable effect.
var program = Program{
	{Name: "clock.now"},
	{Name: "transfer.out", Args: `{"amount":100}`},
	{Name: "internet.read", Args: `{"url":"https://example.com"}`},
	{Name: "mail.send", Args: `{"to":"ops"}`},
	{Name: "transfer.out", Args: `{"amount":250}`},
}

var wantApplied = map[string]int{
	"clock.now":     1,
	"transfer.out":  2,
	"internet.read": 1,
	"mail.send":     1,
}

// totalAppends measures a clean run: two records per step.
func totalAppends(t *testing.T) int {
	t.Helper()
	world := NewWorld()
	if err := Run(world, "run-clean", program); err != nil {
		t.Fatalf("clean run: %v", err)
	}
	return world.Journal.Length()
}

func requireApplied(t *testing.T, world *World, want map[string]int) {
	t.Helper()
	for name, count := range want {
		if world.Effects.Applied[name] != count {
			t.Fatalf("effect %q applied %d times, want %d (exactly-once violated)",
				name, world.Effects.Applied[name], count)
		}
	}
}

// completedTransfers counts transfer.out effects whose completion reached the
// journal's execution section — the set saga unwinding is answerable for.
func completedTransfers(t *testing.T, journal *Journal) int {
	t.Helper()
	count := 0
	for i := 0; i < journal.Length()-1; i++ {
		record, err := journal.Load(i)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if record.Kind != journaled.KindIntent || record.Syscall == nil || record.Syscall.Name != "transfer.out" {
			continue
		}
		next, err := journal.Load(i + 1)
		if err != nil {
			t.Fatalf("load %d: %v", i+1, err)
		}
		if next.Kind == journaled.KindCompletion && next.Result != nil && next.Result.Status() == sys.StatusResult {
			count++
		}
	}
	return count
}

// TestCrashMatrixConverges kills the process at every journal append and
// requires that a restart converges: same effects exactly once, an intact
// chain, and a byte-complete journal.
func TestCrashMatrixConverges(t *testing.T) {
	total := totalAppends(t)
	if total != 2*len(program) {
		t.Fatalf("clean run wrote %d records, want %d", total, 2*len(program))
	}

	for crashAt := 0; crashAt < total; crashAt++ {
		world := NewWorld()
		world.Journal.CrashAt = crashAt

		if err := Run(world, "run-1", program); !errors.Is(err, ErrCrash) {
			t.Fatalf("crashAt=%d: err = %v, want the injected crash", crashAt, err)
		}

		world.Journal.CrashAt = -1
		if err := Run(world, "run-1", program); err != nil {
			t.Fatalf("crashAt=%d: resume did not converge: %v", crashAt, err)
		}

		if err := journaled.Verify(world.Journal); err != nil {
			t.Fatalf("crashAt=%d: chain verify: %v", crashAt, err)
		}
		if world.Journal.Length() != total {
			t.Fatalf("crashAt=%d: journal length %d, want %d", crashAt, world.Journal.Length(), total)
		}
		requireApplied(t, world, wantApplied)

		// A third run must be pure replay: no new records, no driver calls.
		records, dispatches := world.Journal.Length(), world.Effects.Dispatches
		if err := Run(world, "run-1", program); err != nil {
			t.Fatalf("crashAt=%d: replay run: %v", crashAt, err)
		}
		if world.Journal.Length() != records {
			t.Fatalf("crashAt=%d: replay appended records", crashAt)
		}
		if world.Effects.Dispatches != dispatches {
			t.Fatalf("crashAt=%d: replay reached the driver", crashAt)
		}
	}
}

// TestOrderBugCaught resumes a crashed run with a reordered program — the
// class of bug versioned replay exists to catch — and requires divergence,
// not silent corruption.
func TestOrderBugCaught(t *testing.T) {
	world := NewWorld()
	world.Journal.CrashAt = 6 // mid-run
	if err := Run(world, "run-1", program); !errors.Is(err, ErrCrash) {
		t.Fatalf("err = %v, want the injected crash", err)
	}
	world.Journal.CrashAt = -1

	reordered := Program{program[1], program[0], program[2], program[3], program[4]}
	err := Run(world, "run-1", reordered)
	var diverged journaled.ReplayDivergedError
	if !errors.As(err, &diverged) {
		t.Fatalf("err = %v, want ReplayDivergedError", err)
	}
}
