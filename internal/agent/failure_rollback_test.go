package agent

// Failure- and stop-triggered rollback: a process that dies (or is stopped)
// inside an open critical section closes it exactly as sys.abort would — the
// host authors the abort record, the registered compensations run — so a later
// retry re-executes the section over rolled-back state instead of orphaning a
// half-executed attempt and its registrations under an abandoned revision.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

// TestFailureInsideSectionRollsBackThenRetryRecovers: the guest fails
// mid-section after a charge and its registered refund. The failure is an
// implicit abort — the refund runs before the process reports failed, the
// original error survives the rollback, and a retry re-runs the section fresh
// (attempt 2 recovers without charging again).
func TestFailureInsideSectionRollsBackThenRetryRecovers(t *testing.T) {
	disp := &compensationDispatcher{failMidTurn: true}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	failed := waitForStatus(t, runtime, proc.ID, ProcessFailed)
	if !strings.Contains(failed.Error, "kaboom.unavailable") {
		t.Fatalf("failure = %q, want the guest's original error preserved", failed.Error)
	}
	if !strings.Contains(failed.Answer, "billing.refund") {
		t.Fatalf("rollback report = %q, want the executed undo named", failed.Answer)
	}
	disp.mu.Lock()
	charges, refunds := disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want the failed section rolled back before anything else", charges, refunds)
	}

	// The journal narrates the whole story: the host-authored abort carrying
	// the failure, then the executed compensation.
	entries, err := runtime.Journal(proc.ID)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	var sawAbort, sawCompensation bool
	for _, entry := range entries {
		if entry.Syscall.Name == callSysAbort {
			var args abortArgs
			if err := json.Unmarshal(entry.Syscall.Args, &args); err != nil ||
				args.Cause != abortCauseFailure || !strings.Contains(args.Reason, "kaboom.unavailable") {
				t.Fatalf("abort record args = %s (err %v), want cause=failure with the guest error", entry.Syscall.Args, err)
			}
			sawAbort = true
		}
		if entry.Syscall.Name == "billing.refund" && entry.Compensates != nil {
			sawCompensation = true
		}
	}
	if !sawAbort || !sawCompensation {
		t.Fatalf("journal lacks the rollback story: abort=%v compensation=%v", sawAbort, sawCompensation)
	}

	// Retry forks at the section's begin — over compensated state — and the
	// fresh attempt completes without a second charge.
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if final.Answer != "recovered-after-rollback" || final.Attempt != 2 {
		t.Fatalf("answer = %q attempt = %d, want recovery on attempt 2", final.Answer, final.Attempt)
	}
	disp.mu.Lock()
	charges, refunds = disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("after retry: charges = %d, refunds = %d, want no re-charge and no double refund", charges, refunds)
	}
}

// TestRetryAfterRollbackReExecutesIdenticalEffects: intent identity is scoped
// by the revision that wrote the record, so a rolled-back attempt's exactly-
// once memory is dead to its retry. Attempt 2 re-issues the byte-identical
// charge at the same journal position; against a deduping driver it must land
// as a NEW charge (the first one was compensated — adopting its recorded
// result would commit a refunded effect), while the crash-redrive path keeps
// the stability the matrix proves.
func TestRetryAfterRollbackReExecutesIdenticalEffects(t *testing.T) {
	disp := &compensationDispatcher{failMidTurn: true, rechargeAfterRollback: true, dedupe: true}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, ProcessFailed)
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if final.Answer != "recharged" {
		t.Fatalf("answer = %q", final.Answer)
	}
	disp.mu.Lock()
	charges, refunds := disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 2 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want 2 and 1: the fresh attempt's identical charge must re-execute, never adopt the compensated one", charges, refunds)
	}
}

// TestStopInsideSectionRollsBack: stopping a process parked mid-section (the
// yielding call's intent open at the journal tail) is an abort without a
// retry — the registered refund runs, then the process stops.
func TestStopInsideSectionRollsBack(t *testing.T) {
	disp := &compensationDispatcher{parkMidTurn: true}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, ProcessWaitingTask)
	if _, err := runtime.Stop(proc.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	stopped := waitForStatus(t, runtime, proc.ID, ProcessStopped)
	if !strings.Contains(stopped.Answer, "billing.refund") {
		t.Fatalf("rollback report = %q, want the executed undo named", stopped.Answer)
	}
	disp.mu.Lock()
	charges, refunds := disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want the stopped section rolled back", charges, refunds)
	}
}

// TestStopRefusedMidRollback: a rollback parked on its inverse's approval task
// cannot be stopped out from under — abandoning it would leave external state
// undefined. The task's denial is the way out.
func TestStopRefusedMidRollback(t *testing.T) {
	disp := &compensationDispatcher{
		abortContent: `{"reason":"could not confirm the order"}`,
		guardRefunds: true,
	}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, ProcessWaitingTask)
	if _, err := runtime.Stop(proc.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("stop mid-rollback = %v, want ErrConflict", err)
	}

	// Denying the pending inverse resolves the rollback the honest way: it
	// fails with the report naming the outstanding undo.
	tasks, err := runtime.Tasks(proc.ID)
	if err != nil || len(tasks) == 0 {
		t.Fatalf("tasks: %v (%d)", err, len(tasks))
	}
	if _, err := runtime.ResolveTask(tasks[0].ID, tasks[0].ResolutionToken, task.Resolution{
		Decision: task.StateDenied, Actor: "human",
	}); err != nil {
		t.Fatalf("deny: %v", err)
	}
	failed := waitForStatus(t, runtime, proc.ID, ProcessFailed)
	if !strings.Contains(failed.Answer, "outstanding: billing.refund") {
		t.Fatalf("report = %q, want the outstanding undo listed", failed.Answer)
	}
}

// appendAbortPair appends a sys.abort intent with the given args plus its
// completion — the shape both the guest's dispatch and journaled.Abort leave.
func appendAbortPair(t *testing.T, j *logJournal, args string, result sys.SyscallResult) {
	t.Helper()
	appendIntent(t, j, sys.Syscall{Abi: sys.ABIVersion, Name: callSysAbort, Args: json.RawMessage(args)})
	appendCompletion(t, j, result)
}

// TestAbortTailSemantics: only the journal's last word rolls back, and only
// when the abort actually completed — a rejected abort (a forged cause) or one
// followed by further calls is inert history.
func TestAbortTailSemantics(t *testing.T) {
	t.Run("host abort parses cause and reason", func(t *testing.T) {
		j := buildJournal(t, begin(), ok("billing.charge"))
		appendAbortPair(t, j, `{"reason":"guest died","cause":"failure"}`, sys.Result([]byte(`{"ok":true}`)))
		state, aborted := j.abortTail()
		if !aborted {
			t.Fatal("abort tail not found")
		}
		if state.Cause != abortCauseFailure || state.Reason != "guest died" {
			t.Fatalf("state = %+v, want cause=failure reason=guest died", state)
		}
		if state.ScopeStart != 2 {
			t.Fatalf("scope start = %d, want one past the begin pair", state.ScopeStart)
		}
		if !state.settled() {
			t.Fatal("no registrations: the rollback is trivially settled")
		}
	})
	t.Run("rejected abort is inert", func(t *testing.T) {
		j := buildJournal(t, begin(), ok("billing.charge"))
		appendAbortPair(t, j, `{"reason":"x","cause":"forged"}`, sys.FailCode(sys.ErrnoInvalidArgs, "cause is reserved"))
		if _, aborted := j.abortTail(); aborted {
			t.Fatal("a failed abort completion must not trigger a rollback")
		}
	})
	t.Run("abandoned abort is inert", func(t *testing.T) {
		j := buildJournal(t, begin(), ok("billing.charge"))
		appendAbortPair(t, j, `{"reason":"x"}`, sys.Result([]byte(`{"ok":true}`)))
		appendPair(t, j, sys.Syscall{Abi: sys.ABIVersion, Name: "billing.charge"}, sys.Result([]byte(`{}`)))
		if _, aborted := j.abortTail(); aborted {
			t.Fatal("an abort followed by further calls is not the journal's last word")
		}
	})
	t.Run("abort over an open intent still scans", func(t *testing.T) {
		j := buildJournal(t, begin(), ok("billing.charge"))
		appendIntent(t, j, sys.Syscall{Abi: sys.ABIVersion, Name: "flaky.call"})
		appendAbortPair(t, j, `{"reason":"driver error","cause":"failure"}`, sys.Result([]byte(`{"ok":true}`)))
		state, aborted := j.abortTail()
		if !aborted || state.Cause != abortCauseFailure {
			t.Fatalf("aborted=%v state=%+v, want the abort found past the open intent", aborted, state)
		}
	})
}

// TestLifecycleRejectsForgedAbortCause: the cause field is the host's alone.
func TestLifecycleRejectsForgedAbortCause(t *testing.T) {
	l := newLifecycleDispatcher(stubNext{}, "msg", nil, Manifest{}, 1)
	result, err := l.Dispatch(context.Background(), ProcessContext{},
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysAbort, Args: json.RawMessage(`{"reason":"r","cause":"failure"}`)},
		sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("forged cause = %v/%v, want failed/invalid_args", result.Status(), result.Errno())
	}

	honest, err := l.Dispatch(context.Background(), ProcessContext{},
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysAbort, Args: json.RawMessage(`{"reason":"r","retry_seconds":5}`)},
		sys.Authorization{})
	if err != nil || honest.Status() != sys.StatusResult {
		t.Fatalf("guest abort = %v/%v, want acknowledged", honest.Status(), err)
	}
}

type stubNext struct{}

func (stubNext) Dispatch(context.Context, ProcessContext, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Fail("unexpected"), nil
}

func (stubNext) Capabilities() []sys.Capability { return nil }
