package agent

// Removing a program while one of its processes is mid-quantum: the guest is
// suspended inside a host call, so its wasm module is live on the processor when
// the runtime withdraws — and closes — the compiled image underneath it.

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
// cognition call until the test releases it. A process waiting in there is
// durable.ProcessRunning with a live wasm module on the processor — mid-quantum — which
// is the exact window RemoveProgram has to survive.
type blockingDispatchers struct {
	entered chan struct{}
	release chan struct{}
	// stoppable dispatchers abandon the call when their context is cancelled,
	// the way a real driver does. An unstoppable one ignores the cancellation,
	// standing in for a driver that will not come back until it is good and
	// ready.
	stoppable bool
}

func newBlockingDispatchers(stoppable bool) *blockingDispatchers {
	return &blockingDispatchers{entered: make(chan struct{}, 1), release: make(chan struct{}), stoppable: stoppable}
}

func (*blockingDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (d *blockingDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ manifest.Manifest) (*capability.Table, error) {
	return tableOf(d, llmCapability()), nil
}

func (d *blockingDispatchers) Dispatch(ctx context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != "core.openaiApi" {
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
	select {
	case d.entered <- struct{}{}:
	default:
	}
	done := ctx.Done()
	if !d.stoppable {
		// Ignoring the cancellation forces control back into the wasm module
		// *after* its image has been closed — the sharp edge of removal.
		done = nil
	}
	select {
	case <-d.release:
	case <-done:
	case <-time.After(30 * time.Second): // safety valve, never reached in a passing run
	}
	return chatActions(`{"actions":[{"action":"final","content":{"answer":"done"}}]}`), nil
}

// midQuantumRuntime starts a process and blocks it inside its cognition call, so
// the guest is provably mid-quantum — a live wasm module on the processor —
// when the test withdraws its program.
func midQuantumRuntime(t *testing.T, stoppable bool) (*Runtime, *blockingDispatchers, string) {
	t.Helper()
	dispatchers := newBlockingDispatchers(stoppable)
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: dispatchers,
		Log:         store.log,
		Leases:      store,
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
	}, 0)
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	select {
	case <-dispatchers.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("process never reached the blocking dispatch")
	}
	if snapshot, err := runtime.GetProcess(proc.ID); err != nil || snapshot.Status != durable.ProcessRunning {
		t.Fatalf("process before removal = %+v (err %v), want running", snapshot, err)
	}
	return runtime, dispatchers, proc.ID
}

// TestRemoveProgramDrainsEvictedProcesses: RemoveProgram must not return while
// the processes it evicted are still unwinding. Returning early leaves their
// terminal state to a race between the stop and the image close — the same
// eviction recorded as `stopped` one run and as a wasm-level failure the next —
// and an audit target's final state must not depend on that.
func TestRemoveProgramDrainsEvictedProcesses(t *testing.T) {
	runtime, _, processID := midQuantumRuntime(t, true)

	if err := runtime.RemoveProgram(context.Background(), "program@1"); err != nil {
		t.Fatalf("remove program: %v", err)
	}
	// No waiting here on purpose: removal is done, so the eviction is done.
	snapshot, err := runtime.GetProcess(processID)
	if err != nil {
		t.Fatalf("get process: %v", err)
	}
	if !isTerminal(snapshot.Status) {
		t.Fatalf("process is %s after RemoveProgram returned, want a terminal state", snapshot.Status)
	}
	if snapshot.Status != durable.ProcessStopped {
		t.Fatalf("evicted process settled as %s (%q), want stopped", snapshot.Status, snapshot.Error)
	}
	if strings.Contains(snapshot.Error, "wazero") || strings.Contains(snapshot.Error, "module closed") {
		t.Fatalf("eviction leaked a processor-level error into the audit record: %q", snapshot.Error)
	}
	if _, err := runtime.Journal(processID); err != nil {
		t.Fatalf("journal of an evicted process: %v", err)
	}
}

// TestRemoveProgramWithUnstoppableProcess: a driver that ignores its
// cancellation cannot hold the withdrawal hostage. The eviction drain is bounded
// — by the caller's context, and by the runtime's own backstop behind it — and
// the guest returning afterwards into a closed image settles the process instead
// of taking the host down: the processor recovers the closed module into a
// failed call.
func TestRemoveProgramWithUnstoppableProcess(t *testing.T) {
	runtime, dispatchers, processID := midQuantumRuntime(t, false)

	// The caller's context bounds the wait, below the runtime's own backstop.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := runtime.RemoveProgram(ctx, "program@1"); err != nil {
		t.Fatalf("remove program: %v", err)
	}
	if waited := time.Since(start); waited >= evictionDrainTimeout {
		t.Fatalf("removal waited %s on an unstoppable process; the caller's context must bound the drain", waited)
	}
	// Let the guest run on, back into a program image the runtime has withdrawn.
	close(dispatchers.release)

	settled := waitForTerminal(t, runtime, processID)
	if _, err := runtime.Journal(processID); err != nil {
		t.Fatalf("journal of a settled process: %v", err)
	}
	t.Logf("unstoppable process settled as %s (%q)", settled.Status, settled.Error)
}
