package agent

// Compensation: rolling a process back. When a guest ends a critical zone with
// sys.abort instead of sys.commit, the runtime unwinds the zone's completed
// effects with the kernel's saga unwinder — dispatching each capability's
// declared inverse newest-first — and finishes the process as compensated. This
// is the deliberate, guest-chosen counterpart to the (automatic, forward)
// crash-resume path: a host failure re-drives a process; sys.abort undoes it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

// abortReason reports whether a completed process's terminal call was sys.abort
// — the guest asking to roll itself back — and the reason it recorded.
func (r *Runtime) abortReason(processID string) (string, bool) {
	r.mu.Lock()
	proc := r.processes[processID]
	var journal *logJournal
	if proc != nil {
		journal = proc.journal
	}
	r.mu.Unlock()
	if journal == nil {
		return "", false
	}
	length := journal.Length()
	if length < 2 {
		return "", false
	}
	intent, err := journal.Load(length - 2)
	if err != nil || intent.Syscall == nil || intent.Syscall.Name != callSysAbort {
		return "", false
	}
	var args abortArgs
	_ = json.Unmarshal(intent.Syscall.Args, &args)
	return args.Reason, true
}

// compensate rolls a process back with the kernel's saga unwinder: it walks all
// of the process's completed effects newest-first, dispatching each capability's
// declared inverse and journaling the compensations. sys.abort rolls back the
// whole task (each root process is one task), so a read-only effect is skipped
// and one with no mechanical inverse is escalated to the journal for a human —
// never silently dropped. A rollback is not gated on approval, so inverses run
// through the driver chain directly rather than the full guest chain.
func (r *Runtime) compensate(processID, reason string) {
	r.mu.Lock()
	proc := r.processes[processID]
	var cred ProcessContext
	var journal *logJournal
	if proc != nil {
		cred = r.processContextLocked(proc)
		journal = proc.journal
	}
	r.mu.Unlock()
	if proc == nil || journal == nil {
		r.finish(processID, ProcessFailed, "", errors.New("compensate: process journal is unavailable"))
		return
	}

	ctx := context.Background()
	drivers, err := r.processDrivers(ctx, cred)
	if err != nil {
		r.finish(processID, ProcessFailed, "", fmt.Errorf("compensate: %w", err))
		return
	}
	outcomes, unwindErr := capcompute.Unwind(ctx, cred, journal, 0, reservedNoCompensation{drivers})
	summary := compensationSummary(reason, outcomes)
	if unwindErr != nil {
		r.finish(processID, ProcessCompensated, summary, fmt.Errorf("compensation incomplete: %w", unwindErr))
		return
	}
	r.finish(processID, ProcessCompensated, summary, nil)
}

// reservedNoCompensation wraps the driver chain so the reserved runtime-protocol
// calls a guest records inside a zone — the savepoint markers, the lifecycle
// calls, and progress logs — are declared as having nothing to undo. Without
// this the unwinder would treat them as unknown capabilities and escalate them;
// they are protocol, not effects.
type reservedNoCompensation struct {
	sys.Dispatcher[ProcessContext]
}

func (d reservedNoCompensation) Capabilities() []sys.Capability {
	caps := d.Dispatcher.Capabilities()
	for _, name := range []string{
		sys.SyscallBegin, sys.SyscallCommit,
		callSysInput, callSysOutput, callSysAbort, "sys.log",
	} {
		caps = append(caps, sys.Capability{Name: name, Compensation: sys.Compensation{Kind: sys.CompensateNone}})
	}
	return caps
}

// compensationSummary renders the abort reason and a tally of what unwinding did;
// it is stored as the compensated process's answer.
func compensationSummary(reason string, outcomes []capcompute.CompensationOutcome) string {
	var dispatched, skipped, escalated int
	for _, outcome := range outcomes {
		switch outcome.Action {
		case capcompute.CompensationDispatched:
			dispatched++
		case capcompute.CompensationSkipped:
			skipped++
		case capcompute.CompensationEscalated:
			escalated++
		}
	}
	tally := fmt.Sprintf("compensated %d, skipped %d, escalated %d", dispatched, skipped, escalated)
	if strings.TrimSpace(reason) == "" {
		return tally
	}
	return fmt.Sprintf("aborted: %s — %s", reason, tally)
}
