package agent

// The process API: create, read, stop and retry. A process runs in quanta: each
// one is an execute goroutine (executor.go).

import (
	"context"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// CreateProcess checks a process request and starts the process on a session.
// A session runs one process at a time.
func (r *Runtime) CreateProcess(sessionID string, input string, spec manifest.Manifest) (ProcessSnapshot, error) {
	if input == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: input is required", errs.Invalid)
	}
	spec, err := manifest.Validate(spec, r.dispatchers)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	program, ok := r.programs[ProgramID(spec.Program)]
	if !ok {
		return ProcessSnapshot{}, fmt.Errorf("%w: program %q is not registered", errs.Invalid, spec.Program)
	}
	if err := program.validateInput(input); err != nil {
		return ProcessSnapshot{}, err
	}
	processID, err := randomID("proc_")
	if err != nil {
		return ProcessSnapshot{}, err
	}
	now := r.now().UTC()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		return ProcessSnapshot{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	if session.activeProcessID != "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", errs.Conflict, session.activeProcessID)
	}
	proc := &processState{
		id:        processID,
		sessionID: sessionID,
		input:     input,
		status:    durable.ProcessQueued,
		attempt:   1,
		createdAt: now,
		updatedAt: now,
		manifest:  spec,
		revision:  1,
		digest:    program.Digest,
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	// Record the process before it exists in memory, so a failed append leaves
	// nothing to undo.
	if err := r.appendProcess(proc); err != nil {
		return ProcessSnapshot{}, err
	}
	r.processes[processID] = proc
	session.processIDs = append(session.processIDs, processID)
	session.activeProcessID = processID
	session.updatedAt = now
	r.launchLocked(proc)
	return r.processSnapshotLocked(proc), nil
}

func (r *Runtime) GetProcess(processID string) (ProcessSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil {
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	return r.processSnapshotLocked(proc), nil
}

// Stop stops a process. A running quantum is cancelled, and execute records the
// stop when the quantum ends. A process parked on a task stops at once. Nothing
// is undone: the journal records what ran, and a later retry resumes or
// restarts from there.
func (r *Runtime) Stop(processID string) (ProcessSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil {
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	switch proc.status {
	case durable.ProcessQueued, durable.ProcessRunning:
		proc.stopRequested = true
		proc.status = durable.ProcessStopping
		proc.updatedAt = r.now().UTC()
		if proc.stop != nil {
			proc.stop()
		}
		_ = r.appendProcess(proc)
	case durable.ProcessWaitingTask:
		r.finishLocked(proc, durable.ProcessStopped, "", context.Canceled)
	case durable.ProcessStopping, durable.ProcessStopped:
		// Already stopping or stopped.
	default:
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot be stopped from %s", errs.Conflict, processID, proc.status)
	}
	return r.processSnapshotLocked(proc), nil
}

// Retry runs a process again on a fresh quantum.
//
// A restart forks a new revision from the beginning. A resume continues the
// journal: replay serves everything recorded and the guest goes on from where
// it stopped. A resume forks only when the process stopped inside an open
// section: then the whole section runs again from its sys.begin, which is what
// sections are for. Without that fork, a deterministic failure would replay its
// broken result forever.
func (r *Runtime) Retry(processID string, mode RetryMode) (ProcessSnapshot, error) {
	if mode != RetryResume && mode != RetryRestart {
		return ProcessSnapshot{}, fmt.Errorf("%w: retry mode must be resume or restart", errs.Invalid)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil {
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	if err := r.checkRetryLocked(proc, mode); err != nil {
		return ProcessSnapshot{}, err
	}
	switch forkOffset, open := proc.journal.outermostOpenBegin(); {
	case mode == RetryRestart:
		r.forkJournalLocked(proc, 0)
	case proc.status == durable.ProcessWaitingTask:
		// A parked process continues the same revision: replay drives the open
		// intent at the tail again, and the task layer serves the resolved task.
	case open:
		r.forkJournalLocked(proc, forkOffset)
	}
	return r.relaunchLocked(proc)
}

// checkRetryLocked refuses a retry that the process's state does not allow.
func (r *Runtime) checkRetryLocked(proc *processState, mode RetryMode) error {
	// A process never runs under different program bytes. The quantum checks
	// this again: this is the early refusal.
	if _, err := r.programs.bound(ProgramID(proc.manifest.Program), proc.digest); err != nil {
		return err
	}
	switch proc.status {
	case durable.ProcessWaitingTask, durable.ProcessStopped, durable.ProcessFailed, durable.ProcessInterrupted:
	case durable.ProcessCompleted:
		// A completed process has nothing to resume, but it can restart.
		if mode != RetryRestart {
			return fmt.Errorf("%w: completed process %s can only be restarted, not resumed", errs.Conflict, proc.id)
		}
	default:
		return fmt.Errorf("%w: process %s cannot retry from %s", errs.Conflict, proc.id, proc.status)
	}
	// Only the latest process in a session may run again: the history the
	// later processes read already holds an earlier one's answer.
	session := r.sessions[proc.sessionID]
	if session.processIDs[len(session.processIDs)-1] != proc.id {
		return fmt.Errorf("%w: only the latest session process can be retried", errs.Conflict)
	}
	if session.activeProcessID != "" && session.activeProcessID != proc.id {
		return fmt.Errorf("%w: session already has active process %s", errs.Conflict, session.activeProcessID)
	}
	return nil
}

// forkJournalLocked starts a new revision of the process's journal at
// forkOffset: records before it are shared with the earlier revisions, and the
// new revision writes from there. The old revision never runs again, so its
// taint is released. The new one rebuilds its taint by replay. Call with r.mu
// held.
func (r *Runtime) forkJournalLocked(proc *processState, forkOffset int) {
	r.taints.ForgetProcess(proc.context())
	proc.revision++
	proc.forkOffset = forkOffset
	proc.lastFailureLength = 0
	proc.journal = r.newJournal(proc, proc.journal.history, forkOffset)
}

// relaunchLocked queues a process for a fresh quantum: the attempt is bumped,
// the last run's outcome cleared, and its session made active. Call with r.mu
// held.
func (r *Runtime) relaunchLocked(proc *processState) (ProcessSnapshot, error) {
	if r.closed {
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	proc.status = durable.ProcessQueued
	proc.attempt++
	proc.answer = ""
	proc.err = ""
	proc.stopRequested = false
	proc.startedAt = nil
	proc.completedAt = nil
	proc.updatedAt = r.now().UTC()
	session := r.sessions[proc.sessionID]
	session.activeProcessID = proc.id
	session.updatedAt = proc.updatedAt
	if err := r.appendProcess(proc); err != nil {
		return ProcessSnapshot{}, err
	}
	r.launchLocked(proc)
	return r.processSnapshotLocked(proc), nil
}

// launchLocked starts a quantum of the process in its own goroutine. Call it
// with r.mu held, in the same hold that checked r.closed: Close sets closed
// under r.mu and then waits on wg, so an Add after that point would race the
// Wait. execute takes r.mu itself, so it starts once the caller releases it.
func (r *Runtime) launchLocked(proc *processState) {
	r.wg.Add(1)
	go r.execute(proc.id)
}
