package agent

// Failure- and stop-triggered rollback: a process that dies (or is stopped)
// inside an open critical section abandons its revision — the registered
// compensations run before the process reports its terminal state — so a later
// retry re-executes the section over rolled-back state instead of orphaning a
// half-executed attempt and its registrations. The abandonment is management
// state, never a journal record: the journal stays the guest's narrative,
// gaining only the compensations the rollback executes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

// TestFailureInsideSectionRollsBackThenRetryRecovers: the guest fails
// mid-section after a charge and its registered refund. The failure abandons
// the revision — the refund runs before the process reports failed, the
// original error survives the rollback, and a retry re-runs the section fresh
// (attempt 2 recovers without charging again).
func TestFailureInsideSectionRollsBackThenRetryRecovers(t *testing.T) {
	disp := &compensationDispatcher{failMidTurn: true}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	failed := waitForStatus(t, runtime, proc.ID, durable.ProcessFailed)
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

	// The journal stays the guest's narrative: the host's abandonment writes
	// no record of its own — no sys.abort the guest never made — and the only
	// trace of the rollback is the compensation it executed. The failure lives
	// where management state belongs, on the process.
	entries, err := runtime.Journal(proc.ID)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	var sawCompensation bool
	for _, entry := range entries {
		if entry.Syscall.Name == callSysAbort {
			t.Fatalf("journal carries a sys.abort the guest never made: %s", entry.Syscall.Args)
		}
		if entry.Syscall.Name == "billing.refund" && entry.Compensates != nil {
			sawCompensation = true
		}
	}
	if !sawCompensation {
		t.Fatal("journal lacks the executed compensation")
	}

	// Retry forks at the section's begin — over compensated state — and the
	// fresh attempt completes without a second charge. Attempt 3, exactly: the
	// deterministic failure earned one re-drive (which replayed to the same
	// wall with no journal progress) before the rollback ran.
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	if final.Answer != "recovered-after-rollback" || final.Attempt != 3 {
		t.Fatalf("answer = %q attempt = %d, want recovery on attempt 3 (one re-drive, one rollback retry)", final.Answer, final.Attempt)
	}
	disp.mu.Lock()
	charges, refunds = disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("after retry: charges = %d, refunds = %d, want no re-charge and no double refund", charges, refunds)
	}

	// Purity holds across the whole history: no revision — the rolled-back
	// attempt included — carries a sys.abort the guest did not make.
	revisions, err := runtime.JournalRevisions(proc.ID)
	if err != nil {
		t.Fatalf("journal revisions: %v", err)
	}
	for rev, entries := range revisions {
		for _, entry := range entries {
			if entry.Syscall.Name == callSysAbort {
				t.Fatalf("revision %d carries a sys.abort the guest never made", rev)
			}
		}
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

	waitForStatus(t, runtime, proc.ID, durable.ProcessFailed)
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
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

// TestInfraFailureInTheGapHealsByRedrive: the driver dies between an effect
// and its registration — the worst register-after-dispatch window. The
// failure re-drives by replay: the recorded charge is served (never
// re-executed), the open inventory intent re-drives under its original key,
// and the guest walks forward into the registration it never made. When the
// model later aborts, the refund is armed and runs — nothing leaked, no
// human involved.
func TestInfraFailureInTheGapHealsByRedrive(t *testing.T) {
	disp := &compensationDispatcher{gapInfraFailure: true, abortContent: `{"reason":"order abandoned"}`}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	final := waitForStatus(t, runtime, proc.ID, durable.ProcessCompensated)
	disp.mu.Lock()
	charges, refunds := disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want the gap-interrupted registration recovered and executed exactly once", charges, refunds)
	}
	if !strings.Contains(final.Answer, "billing.refund") {
		t.Fatalf("rollback report = %q, want the executed undo named", final.Answer)
	}
}

// TestStopInsideSectionRollsBack: stopping a process parked mid-section (the
// yielding call's intent open at the journal tail) is an abandonment without
// a retry — the registered refund runs, then the process stops.
func TestStopInsideSectionRollsBack(t *testing.T) {
	disp := &compensationDispatcher{parkMidTurn: true}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)
	if _, err := runtime.Stop(proc.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	stopped := waitForStatus(t, runtime, proc.ID, durable.ProcessStopped)
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

// TestRestartAbandonsOpenSection: an explicit restart abandons the current
// revision, so a process parked mid-section rolls back — the registered
// refund runs — before the fresh from-scratch run (which re-reads its input,
// sees attempt 2, and concludes). Without the abandonment the fork at 0 would
// orphan the charge and its registration in the shadowed revision.
func TestRestartAbandonsOpenSection(t *testing.T) {
	disp := &compensationDispatcher{parkMidTurn: true}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)
	if _, err := runtime.Retry(proc.ID, RetryRestart); err != nil {
		t.Fatalf("restart: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	if final.Answer != "recovered-after-rollback" {
		t.Fatalf("answer = %q, want the fresh run's attempt-2 conclusion", final.Answer)
	}
	disp.mu.Lock()
	charges, refunds := disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want the abandoned revision rolled back exactly once", charges, refunds)
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

	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)
	if _, err := runtime.Stop(proc.ID); !errors.Is(err, errs.Conflict) {
		t.Fatalf("stop mid-rollback = %v, want errs.Conflict", err)
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
	failed := waitForStatus(t, runtime, proc.ID, durable.ProcessFailed)
	if !strings.Contains(failed.Answer, "outstanding: billing.refund") {
		t.Fatalf("report = %q, want the outstanding undo listed", failed.Answer)
	}
}

// appendAbortPair appends a sys.abort intent with the given args plus its
// completion — the shape the guest's own dispatch leaves on the journal.
func appendAbortPair(t *testing.T, j *logJournal, args string, result sys.SyscallResult) {
	t.Helper()
	appendIntent(t, j, sys.Syscall{Abi: sys.ABIVersion, Name: callSysAbort, Args: json.RawMessage(args)})
	appendCompletion(t, j, result)
}

// TestLifecycleAbortArgs: sys.abort carries the guest's reason and retry
// policy; malformed args are rejected at dispatch and empty args are a bare
// "roll back now, no retry".
func TestLifecycleAbortArgs(t *testing.T) {
	l := newLifecycleDispatcher(stubNext{}, "msg", nil, nil, manifest.Manifest{}, 1, nil)
	dispatch := func(args string) sys.SyscallResult {
		t.Helper()
		result, err := l.Dispatch(context.Background(), ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: callSysAbort, Args: json.RawMessage(args)},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return result
	}
	if r := dispatch(`{"reason":"r","retry_seconds":5}`); r.Status() != sys.StatusResult {
		t.Fatalf("abort = %v, want acknowledged", r.Status())
	}
	if r := dispatch(``); r.Status() != sys.StatusResult {
		t.Fatalf("bare abort = %v, want acknowledged", r.Status())
	}
	if r := dispatch(`{"reason":`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("malformed abort = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
}

// TestLifecycleValidatesAnswer: sys.output runs the program's output-schema
// hook, so an answer that violates the interface comes back as a failed
// result the guest can react to — nothing is recorded as terminal until the
// answer satisfies the schema. A nil hook (unbound program) acknowledges.
func TestLifecycleValidatesAnswer(t *testing.T) {
	reject := func(answer string) error {
		if answer == "bad" {
			return fmt.Errorf("answer rejected by output schema")
		}
		return nil
	}
	l := newLifecycleDispatcher(stubNext{}, "msg", nil, nil, manifest.Manifest{}, 1, reject)
	output := func(args string) sys.SyscallResult {
		t.Helper()
		result, err := l.Dispatch(context.Background(), ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: callSysOutput, Args: json.RawMessage(args)},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return result
	}
	if r := output(`{"answer":"good"}`); r.Status() != sys.StatusResult {
		t.Fatalf("valid answer = %v, want acknowledged", r.Status())
	}
	if r := output(`{"answer":"bad"}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("invalid answer = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
}

type stubNext struct{}

func (stubNext) Dispatch(context.Context, ProcessContext, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Fail("unexpected"), nil
}

func (stubNext) Capabilities() []sys.Capability { return nil }
