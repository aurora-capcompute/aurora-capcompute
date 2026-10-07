package agent

// The quantum deadline is a bound on execution, not a verdict on the work. A
// guest that runs out of wall-clock — very often because something it called
// hung, not because it misbehaved — must come back interrupted, with its journal
// standing, and must be resumable.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/capcompute/sys"
)

// blockingDispatchers hands every process a dispatcher that parks inside the
// cognition call — a third party that does not answer — until the test
// releases it or the quantum's context ends.
type blockingDispatchers struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockingDispatchers() *blockingDispatchers {
	return &blockingDispatchers{entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (*blockingDispatchers) ValidateConfig(string, json.RawMessage) error { return nil }

func (d *blockingDispatchers) NewDispatcher(_ context.Context, _ durable.ProcessContext, _ manifest.Manifest) (*capability.Table, error) {
	return tableOf(d, llmCapability()), nil
}

func (d *blockingDispatchers) Dispatch(ctx context.Context, _ durable.ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != "core.openaiApi" {
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
	select {
	case d.entered <- struct{}{}:
	default:
	}
	select {
	case <-d.release:
	case <-ctx.Done():
	case <-time.After(30 * time.Second): // safety valve, never reached in a passing run
	}
	return chatActions(`{"actions":[{"action":"final","content":{"answer":"done"}}]}`), nil
}

// A quantum that runs out of time is interrupted, never stopped: stopping is a
// deliberate abort, while a deadline says nothing about whether the work was
// good.
func TestDeadlineInterruptsRatherThanStops(t *testing.T) {
	dispatchers := newBlockingDispatchers()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers:     dispatchers,
		Log:             newMemLog(),
		TaskSecret:      []byte("stable-secret"),
		QuantumDeadline: 200 * time.Millisecond,
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
	})
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	select {
	case <-dispatchers.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("process never reached the blocking dispatch")
	}

	snapshot := waitForStatus(t, runtime, proc.ID, durable.ProcessInterrupted)
	if !strings.Contains(snapshot.Error, context.DeadlineExceeded.Error()) {
		t.Fatalf("interrupted with %q, want the deadline named in the record", snapshot.Error)
	}
	// The journal survives: an interruption is external, so nothing about the
	// process's recorded history is abandoned.
	if len(processLog(t, runtime, proc.ID).Entries) == 0 {
		t.Fatal("no journal after a deadline abort")
	}

	// And it is resumable. Let the third party answer this time.
	close(dispatchers.release)
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry after a deadline abort: %v", err)
	}
	if done := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted); done.Answer == "" {
		t.Fatal("resumed process completed with no answer")
	}
}
