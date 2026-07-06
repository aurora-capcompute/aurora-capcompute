package agent

import (
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"

	"github.com/aurora-capcompute/capcompute/sys"
)

// buildJournal stores a sequence of completed syscalls (intent/completion
// pairs) and returns the journal. Each step is "begin"/"commit" (savepoint
// markers) or "name:fail"/"name" (a failing or successful capability call).
func buildJournal(t *testing.T, steps ...step) *logJournal {
	t.Helper()
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now, nil)
	for _, s := range steps {
		appendPair(t, j, sys.Syscall{Abi: sys.ABIVersion, Name: s.name}, s.result)
	}
	return j
}

type step struct {
	name   string
	result sys.SyscallResult
}

func begin() step  { return step{sys.SyscallBegin, sys.Result([]byte("{}"))} }
func commit() step { return step{sys.SyscallCommit, sys.Result([]byte("{}"))} }
func ok(name string) step {
	return step{name, sys.Result([]byte("{}"))}
}
func failed(name string) step { return step{name, sys.Fail(name + " failed")} }

func TestOutermostOpenBegin(t *testing.T) {
	// Record offsets: each step is one intent/completion pair, so step i's
	// intent is record 2i and its completion 2i+1. The expected fork offset is
	// one past the open begin's completion record.
	cases := []struct {
		name     string
		steps    []step
		wantOff  int
		wantOpen bool
	}{
		{
			name:     "no begin at all",
			steps:    []step{ok("a"), failed("b")},
			wantOpen: false,
		},
		{
			name:     "single open begin",
			steps:    []step{begin(), failed("x")},
			wantOff:  2, // fork right after the begin pair at records 0-1
			wantOpen: true,
		},
		{
			name:     "committed begin then bare soft fail",
			steps:    []step{begin(), ok("a"), commit(), failed("y")},
			wantOpen: false, // the bare fail synthesizes no fork point
		},
		{
			name:     "sequential committed then open",
			steps:    []step{begin(), ok("a"), commit(), begin(), failed("b")},
			wantOff:  8, // fork after the second begin's pair at records 6-7
			wantOpen: true,
		},
		{
			name:     "nested both open forks at outermost",
			steps:    []step{begin(), ok("a"), begin(), failed("b")},
			wantOff:  2, // outermost begin at records 0-1
			wantOpen: true,
		},
		{
			name:     "nested inner committed outer open",
			steps:    []step{begin(), ok("a"), begin(), ok("b"), commit(), failed("c")},
			wantOff:  2, // outer begin still open
			wantOpen: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := buildJournal(t, tc.steps...)
			off, open := j.outermostOpenBegin()
			if open != tc.wantOpen {
				t.Fatalf("open = %v, want %v", open, tc.wantOpen)
			}
			if open && off != tc.wantOff {
				t.Fatalf("forkOffset = %d, want %d", off, tc.wantOff)
			}
		})
	}
}

// An uncompleted begin intent at the tail (crashed mid-marker) must not count
// as an open bracket: nothing after it executed, so the default fork applies.
func TestOutermostOpenBeginIgnoresUncompletedIntent(t *testing.T) {
	j := buildJournal(t, ok("a"))
	appendIntent(t, j, sys.Syscall{Abi: sys.ABIVersion, Name: sys.SyscallBegin})
	if off, open := j.outermostOpenBegin(); open {
		t.Fatalf("open = true at %d, want false for an uncompleted begin intent", off)
	}
}
