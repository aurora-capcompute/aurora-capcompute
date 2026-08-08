package agent

// How a revision ends badly, and what follows.
//
// A guest's sys.abort gives up on the savepoint section it is inside: the
// journal forks at the section's still-open sys.begin and the whole declared
// unit re-executes as a fresh revision, over whatever state its first attempt
// left behind. Nothing is undone — the runtime serves no compensations — so a
// section that must be re-runnable is the program's own contract, and the
// abandoned attempt stays in the log as an audited, closed revision.
//
// A host failure re-drives the same revision instead, at most once per journal
// length: replay serves everything recorded, and the guest proceeds mid-flight.
// A failure that cannot get past the same point is a deterministic wall, and the
// process fails.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// liveJournal fetches a process's live journal under the runtime lock.
func (r *Runtime) liveJournal(processID string) (*logJournal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil || proc.journal == nil {
		return nil, false
	}
	return proc.journal, true
}

// guestAbort reports whether a process's journal ends in the guest's own
// completed sys.abort, and the reason it declared — the completion path's cheap
// dispatch test.
func (r *Runtime) guestAbort(processID string) (string, bool) {
	journal, ok := r.liveJournal(processID)
	if !ok {
		return "", false
	}
	length := journal.Length()
	if length < 2 {
		return "", false
	}
	completion, err := journal.Load(length - 1)
	if err != nil || completion.Kind != journaled.KindCompletion {
		return "", false
	}
	intent, err := journal.Load(length - 2)
	if err != nil || intent.Syscall == nil || intent.Syscall.Name != sys.SyscallAbort {
		return "", false
	}
	var args abortArgs
	_ = json.Unmarshal(intent.Syscall.Args, &args)
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
	if proc == nil || proc.journal == nil {
		r.mu.Unlock()
		return
	}
	forkOffset, open := proc.journal.outermostOpenBegin()
	switch {
	case !open:
		r.mu.Unlock()
		r.finish(processID, durable.ProcessFailed, "", failure)
	case proc.abortRetries >= r.maxAbortRetries:
		r.mu.Unlock()
		r.finish(processID, durable.ProcessFailed, "",
			fmt.Errorf("%w (no attempts left after %d)", failure, r.maxAbortRetries))
	default:
		proc.abortRetries++
		r.forkJournalLocked(proc, forkOffset, RetryResume)
		if _, err := r.relaunchLocked(context.Background(), proc); err != nil {
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
	if failure == nil {
		failure = errors.New("process failed")
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
	if proc == nil || proc.journal == nil || proc.stopRequested || r.closed {
		r.mu.Unlock()
		return false
	}
	if _, open := proc.journal.outermostOpenBegin(); !open {
		r.mu.Unlock()
		return false
	}
	if length := proc.journal.Length(); proc.lastFailureLength == length {
		r.mu.Unlock()
		return false
	} else {
		proc.lastFailureLength = length
	}
	if _, err := r.relaunchLocked(context.Background(), proc); err != nil {
		slog.Warn("re-drive after failure", "process_id", processID, "error", err)
		return false
	}
	return true
}

// stopProcess finishes a stopped process. A stop walks away from the revision
// where it stands: its journal is the record of what ran, and a later retry
// resumes or restarts from there.
func (r *Runtime) stopProcess(processID string, cause error) {
	r.finish(processID, durable.ProcessStopped, "", cause)
}
