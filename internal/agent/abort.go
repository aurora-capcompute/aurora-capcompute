package agent

// How a revision ends badly, and what follows.
//
// A guest's sys.abort gives up on the savepoint section it is inside: the
// journal forks at the section's still-open sys.begin and the whole declared
// unit re-executes as a fresh revision, over whatever state its first attempt
// left behind. Nothing is undone, so a section that must be re-runnable is the
// program's own contract, and the
// abandoned attempt stays in the log as an audited, closed revision.
//
// A host failure re-drives the same revision instead, at most once per journal
// length: replay serves everything recorded, and the guest proceeds mid-flight.
// A failure that cannot get past the same point is a deterministic wall, and the
// process fails.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute/sys"
)

// lastCall is the journal's last completed call: its syscall and its result.
// The journal is intent/completion pairs, so an odd length ends in an open
// intent and there is no last completed call.
func (r *Runtime) lastCall(processID string) (sys.Syscall, sys.SyscallResult, bool) {
	r.mu.Lock()
	journal := r.processes[processID].journal
	r.mu.Unlock()
	length := journal.Length()
	if length == 0 || length%2 != 0 {
		return sys.Syscall{}, sys.SyscallResult{}, false
	}
	// Both positions are below the length, so both loads succeed.
	intent, _ := journal.Load(length - 2)
	completion, _ := journal.Load(length - 1)
	return *intent.Syscall, *completion.Result, true
}

// guestAbort reports whether the guest ended with its own sys.abort, and the
// reason it gave.
func (r *Runtime) guestAbort(processID string) (string, bool) {
	call, _, ok := r.lastCall(processID)
	if !ok || call.Name != sys.SyscallAbort {
		return "", false
	}
	var args abortArgs
	_ = json.Unmarshal(call.Args, &args)
	return args.Reason, true
}

// retryAbortedSection re-runs the section a guest abandoned, as a fresh revision
// forked at its open sys.begin. With no section open there is no smaller unit to
// re-run — the guest gave up on the whole process — and the process fails, as it
// does once the abort budget is spent: the guard against a guest that aborts
// forever.
func (r *Runtime) retryAbortedSection(processID, reason string) {
	failure := errors.New("guest aborted")
	if reason != "" {
		failure = fmt.Errorf("guest aborted: %s", reason)
	}
	r.mu.Lock()
	proc := r.processes[processID]
	forkOffset, open := proc.journal.outermostOpenBegin()
	switch {
	case !open:
		r.mu.Unlock()
		r.finish(processID, durable.ProcessFailed, "", failure)
	case proc.abortRetries >= maxAbortRetries:
		r.mu.Unlock()
		r.finish(processID, durable.ProcessFailed, "",
			fmt.Errorf("%w (no attempts left after %d)", failure, maxAbortRetries))
	default:
		proc.abortRetries++
		r.forkJournalLocked(proc, forkOffset)
		if _, err := r.relaunchLocked(proc); err != nil {
			slog.Warn("abort retry relaunch", "process_id", processID, "error", err)
		}
	}
}

// failProcess finishes a failed process, after giving it the one re-drive a
// failure inside an open section has earned.
func (r *Runtime) failProcess(processID string, failure error) {
	if r.redriveAfterFailure(processID) {
		return
	}
	r.finish(processID, durable.ProcessFailed, "", failure)
}

// redriveAfterFailure relaunches a process that failed inside an open savepoint
// section, at most once per journal length: the progress guard. It reports false
// — fall through to the failure — when no section is open, a stop or shutdown is
// in flight, or the journal did not grow since the previous failure (the
// deterministic wall).
func (r *Runtime) redriveAfterFailure(processID string) bool {
	r.mu.Lock()
	proc := r.processes[processID]
	_, open := proc.journal.outermostOpenBegin()
	length := proc.journal.Length()
	if proc.stopRequested || r.closed || !open || proc.lastFailureLength == length {
		r.mu.Unlock()
		return false
	}
	proc.lastFailureLength = length
	if _, err := r.relaunchLocked(proc); err != nil {
		slog.Warn("re-drive after failure", "process_id", processID, "error", err)
		return false
	}
	return true
}

// isTerminal reports whether a process status is a final state (no further execution).
func isTerminal(status durable.ProcessStatus) bool {
	switch status {
	case durable.ProcessCompleted, durable.ProcessFailed, durable.ProcessStopped, durable.ProcessInterrupted:
		return true
	default:
		return false
	}
}
