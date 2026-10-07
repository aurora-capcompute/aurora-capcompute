package agent

// The quantum deadline is a bound on execution, not a verdict on the work. A
// guest that runs out of wall-clock — very often because something it called
// hung, not because it misbehaved — must come back interrupted, with its journal
// standing, and must be resumable.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// deadlineRuntime starts a process whose guest parks inside a host call — a
// third party that never answers — under the given per-quantum deadline.
func deadlineRuntime(t *testing.T, deadline time.Duration) (*Runtime, *blockingDispatchers, string) {
	t.Helper()
	dispatchers := newBlockingDispatchers(true)
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: dispatchers,
		Log:         store.log,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "think", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants(),
	}, deadline)
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	select {
	case <-dispatchers.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("process never reached the blocking dispatch")
	}
	return runtime, dispatchers, proc.ID
}

// A quantum that runs out of time is interrupted, never stopped: stopping is a
// deliberate abort and rolls the open section back, while a deadline says
// nothing about whether the work was good.
func TestDeadlineInterruptsRatherThanStops(t *testing.T) {
	runtime, dispatchers, processID := deadlineRuntime(t, 200*time.Millisecond)

	snapshot := waitForStatus(t, runtime, processID, durable.ProcessInterrupted)
	if !strings.Contains(snapshot.Error, context.DeadlineExceeded.Error()) {
		t.Fatalf("interrupted with %q, want the deadline named in the record", snapshot.Error)
	}
	// The journal survives: an interruption is external, so nothing about the
	// process's recorded history is abandoned.
	if len(processLog(t, runtime, processID).Entries) == 0 {
		t.Fatal("no journal after a deadline abort")
	}

	// And it is resumable. Let the third party answer this time.
	close(dispatchers.release)
	if _, err := runtime.Retry(processID, RetryResume); err != nil {
		t.Fatalf("retry after a deadline abort: %v", err)
	}
	if done := waitForStatus(t, runtime, processID, durable.ProcessCompleted); done.Answer == "" {
		t.Fatal("resumed process completed with no answer")
	}
}

// The deadline a caller asks for is clamped by the host ceiling: a caller may
// ask for less than the host allows and never for more, and asking for nothing
// takes the host's own bound. The ceiling is a bound, never a grant.
func TestClampDeadlineHonoursTheHostCeiling(t *testing.T) {
	runtime := &Runtime{quantumCeiling: time.Minute}
	cases := []struct {
		name      string
		requested time.Duration
		want      time.Duration
	}{
		{name: "zero takes the host default", requested: 0, want: time.Minute},
		{name: "negative takes the host default", requested: -1, want: time.Minute},
		{name: "below the ceiling is honoured", requested: time.Second, want: time.Second},
		{name: "above the ceiling is clamped down", requested: time.Hour, want: time.Minute},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := runtime.clampDeadline(test.requested); got != test.want {
				t.Fatalf("clampDeadline(%v) = %v, want %v", test.requested, got, test.want)
			}
		})
	}

	// A host that disabled its own bound has nothing to clamp to, so a caller's
	// request stands verbatim — and an unbounded host stays unbounded.
	unbounded := &Runtime{quantumCeiling: 0}
	if got := unbounded.clampDeadline(time.Hour); got != time.Hour {
		t.Fatalf("clampDeadline under an unbounded host = %v, want it honoured verbatim", got)
	}
	if got := unbounded.clampDeadline(0); got != 0 {
		t.Fatalf("clampDeadline(0) under an unbounded host = %v, want unbounded", got)
	}
}
