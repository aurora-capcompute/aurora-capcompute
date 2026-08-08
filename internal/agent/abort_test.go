package agent

// What a guest's sys.abort does now that nothing is compensated: it re-runs the
// savepoint section the guest abandoned, by forking the journal at that
// section's still-open sys.begin. With no section open there is nothing smaller
// to re-run and the process fails; the same once the abort budget is spent.
//
// These stop short of instantiating wasm — the journal is hand-built — so they
// run everywhere. TestResumeForksAtTheOpenBegin below is the guest-backed half.

import (
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// abortProcess installs a process with a hand-built journal on a guest-free
// runtime. Its program is never registered, so the relaunch a fork triggers
// settles as failed — which is what makes the post-fork revision observable.
func abortProcess(t *testing.T, runtime *Runtime, steps ...step) string {
	t.Helper()
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc := &processState{
		id:        "proc_abort",
		sessionID: session.ID,
		revision:  1,
		status:    durable.ProcessRunning,
		manifest:  manifest.Manifest{Version: manifest.Version, Program: "unloaded@1"},
		journal:   buildJournal(t, steps...),
	}
	runtime.mu.Lock()
	runtime.processes[proc.id] = proc
	runtime.sessions[session.ID].processIDs = append(runtime.sessions[session.ID].processIDs, proc.id)
	runtime.mu.Unlock()
	return proc.id
}

// An abort inside an open section forks at that section's sys.begin and
// re-drives: a new revision, starting from the fork offset, and one unit of the
// abort budget spent.
func TestAbortForksAtTheOpenBegin(t *testing.T) {
	runtime := seamRuntime(t)
	processID := abortProcess(t, runtime, begin(), ok("billing.charge"))

	runtime.retryAbortedSection(processID, "could not confirm the order")

	final := waitForTerminal(t, runtime, processID)
	if final.Revision != 2 {
		t.Fatalf("revision = %d, want 2: the abort must mint a fresh revision", final.Revision)
	}
	runtime.mu.Lock()
	proc := runtime.processes[processID]
	forkOffset, retries := proc.forkOffset, proc.abortRetries
	runtime.mu.Unlock()
	// The begin pair is records 0-1, so the section's body starts at 2.
	if forkOffset != 2 {
		t.Fatalf("forkOffset = %d, want 2 (one past the open begin's completion)", forkOffset)
	}
	if retries != 1 {
		t.Fatalf("abortRetries = %d, want 1", retries)
	}
}

// With nothing bracketed there is no smaller unit to re-run: the guest gave up
// on the whole process, and its declared reason is the failure.
func TestAbortWithoutAnOpenSectionFails(t *testing.T) {
	runtime := seamRuntime(t)
	processID := abortProcess(t, runtime, ok("billing.charge"))

	runtime.retryAbortedSection(processID, "nothing left to try")

	final, err := runtime.GetProcess(processID)
	if err != nil {
		t.Fatalf("get process: %v", err)
	}
	if final.Status != durable.ProcessFailed {
		t.Fatalf("status = %s, want failed", final.Status)
	}
	if !strings.Contains(final.Error, "nothing left to try") {
		t.Fatalf("error = %q, want the guest's own reason", final.Error)
	}
	if final.Revision != 1 {
		t.Fatalf("revision = %d, want 1: nothing was re-run", final.Revision)
	}
}

// The budget is the guard against a guest that aborts forever: once spent, the
// section is not re-run again and the process fails.
func TestAbortBudgetExhaustedFails(t *testing.T) {
	runtime := seamRuntime(t)
	processID := abortProcess(t, runtime, begin(), ok("billing.charge"))
	runtime.mu.Lock()
	runtime.processes[processID].abortRetries = runtime.maxAbortRetries
	runtime.mu.Unlock()

	runtime.retryAbortedSection(processID, "still stuck")

	final, err := runtime.GetProcess(processID)
	if err != nil {
		t.Fatalf("get process: %v", err)
	}
	if final.Status != durable.ProcessFailed {
		t.Fatalf("status = %s, want failed", final.Status)
	}
	if !strings.Contains(final.Error, "no attempts left") {
		t.Fatalf("error = %q, want the exhausted budget named", final.Error)
	}
	if final.Revision != 1 {
		t.Fatalf("revision = %d, want 1: a spent budget re-runs nothing", final.Revision)
	}
}

// The abort budget is durable state. An in-memory counter would hand every
// restart a fresh budget, which is no bound at all.
func TestAbortBudgetSurvivesRestore(t *testing.T) {
	runtime := seamRuntime(t)
	processID := abortProcess(t, runtime, begin(), ok("billing.charge"))
	runtime.mu.Lock()
	proc := runtime.processes[processID]
	proc.abortRetries = 3
	stored := runtime.storedProcessLocked(proc)
	runtime.mu.Unlock()

	if stored.AbortRetries != 3 {
		t.Fatalf("stored AbortRetries = %d, want 3", stored.AbortRetries)
	}
}

// The guest-backed half: a turn that breaks mid-way leaves its savepoint open,
// and a resume must fork there so the whole turn re-executes live. Without the
// fork, a deterministic failure replays its broken completion forever and the
// retry can never make progress — which is what the brackets exist to prevent.
func TestResumeForksAtTheOpenBegin(t *testing.T) {
	disp := &effectsDispatcher{}
	runtime := newEffectsRuntime(t, disp)
	processID := startEffectsProcess(t, runtime).ID

	failed := waitForStatus(t, runtime, processID, durable.ProcessFailed)
	if failed.Revision != 1 {
		t.Fatalf("revision = %d before the retry, want 1", failed.Revision)
	}

	if _, err := runtime.Retry(processID, RetryResume); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := waitForStatus(t, runtime, processID, durable.ProcessFailed)
	if final.Revision != 2 {
		t.Fatalf("revision = %d after resuming into an open section, want 2", final.Revision)
	}
	// The turn really re-executed rather than replaying its recorded failure:
	// the charge landed a second time, under the new revision's key space.
	disp.mu.Lock()
	charges := disp.charges
	disp.mu.Unlock()
	if charges != 2 {
		t.Fatalf("charges = %d, want 2: the forked section must re-run its body live", charges)
	}
}
