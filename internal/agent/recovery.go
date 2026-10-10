package agent

// What follows when a run ends badly.
//
// A guest's sys.abort gives up on the section it is inside. The journal forks
// at the section's open sys.begin, and the whole section runs again as a new
// revision. Nothing is undone, so a section must be safe to run again: that is
// the program's contract. The abandoned attempt stays in the log as a closed
// revision.
//
// A failure inside an open section runs the same revision again instead, at
// most once per journal length: replay serves everything recorded, and the
// guest continues where it stopped. A failure at the same point again is
// deterministic, and the process fails.

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

// maxAbortRetries bounds how many times a process may abort and run its
// section again.
const maxAbortRetries = 10

// retryAbortedSection runs the section a guest abandoned again, as a new
// revision forked at its open sys.begin. With no section open, the guest gave up
// on the whole process, and the process fails. It fails too once the abort
// budget is spent, so a guest cannot abort forever.
func (r *Runtime) retryAbortedSection(processID, reason string) {
	failure := errors.New("guest aborted")
	if reason != "" {
		failure = fmt.Errorf("guest aborted: %s", reason)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	forkOffset, open := proc.journal.outermostOpenBegin()
	switch {
	case !open:
		r.finishLocked(proc, durable.ProcessFailed, "", failure)
	case proc.abortRetries >= maxAbortRetries:
		r.finishLocked(proc, durable.ProcessFailed, "",
			fmt.Errorf("%w (no attempts left after %d)", failure, maxAbortRetries))
	default:
		proc.abortRetries++
		r.forkJournalLocked(proc, forkOffset)
		if _, err := r.relaunchLocked(proc); err != nil {
			slog.Warn("abort retry relaunch", "process_id", processID, "error", err)
		}
	}
}

// failProcess records a failed run, unless the failure earns one more run
// (redriveAfterFailure).
func (r *Runtime) failProcess(processID string, failure error) {
	if r.redriveAfterFailure(processID) {
		return
	}
	r.finish(processID, durable.ProcessFailed, "", failure)
}

// redriveAfterFailure runs a process that failed inside an open section again,
// on the same revision. A process gets one such run per journal length: when it
// fails again without the journal growing, the failure is deterministic. It
// reports false, and the failure stands, when no section is open, a stop or a
// shutdown is under way, or the journal did not grow.
func (r *Runtime) redriveAfterFailure(processID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	_, open := proc.journal.outermostOpenBegin()
	length := proc.journal.Length()
	if proc.stopRequested || r.closed || !open || proc.lastFailureLength == length {
		return false
	}
	proc.lastFailureLength = length
	if _, err := r.relaunchLocked(proc); err != nil {
		slog.Warn("re-drive after failure", "process_id", processID, "error", err)
		return false
	}
	return true
}
