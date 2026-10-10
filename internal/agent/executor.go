package agent

// One quantum of one process: run the guest on the pool, then record how the
// run ended.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

// execute runs one quantum of a process and records how it ended. CreateProcess
// and Retry start it in its own goroutine, counted in wg.
func (r *Runtime) execute(processID string) {
	defer r.wg.Done()

	r.mu.Lock()
	proc := r.processes[processID]
	if proc.stopRequested {
		// Stopped before the quantum started.
		r.mu.Unlock()
		r.finish(processID, durable.ProcessStopped, "", context.Canceled)
		return
	}
	cred := proc.context()
	program := ProgramID(proc.manifest.Program)
	digest := proc.digest
	r.mu.Unlock()

	results, stop, err := r.pool.submit(r.quantumDeadline, func(ctx context.Context) quantumResult {
		return r.runQuantum(ctx, cred, program, digest)
	})
	if err != nil {
		r.finish(processID, durable.ProcessInterrupted, "", err)
		return
	}

	// The process runs. A Stop that arrived while the quantum queued stops it
	// now. Later Stops find proc.stop.
	r.mu.Lock()
	now := r.now().UTC()
	proc.stop = stop
	proc.status = durable.ProcessRunning
	proc.startedAt = &now
	proc.updatedAt = now
	stopRequested := proc.stopRequested
	_ = r.appendProcess(proc)
	r.mu.Unlock()
	if stopRequested {
		stop()
	}

	result := <-results
	r.mu.Lock()
	proc.stop = nil
	r.mu.Unlock()
	r.recordOutcome(processID, result)
}

// recordOutcome turns how a quantum ended into the process's next state.
func (r *Runtime) recordOutcome(processID string, result quantumResult) {
	switch result.status {
	case capcompute.ResumeCompleted:
		if reason, aborted := r.guestAbort(processID); aborted {
			r.retryAbortedSection(processID, reason)
			return
		}
		answer, err := r.answerFromJournal(processID)
		if err != nil {
			r.failProcess(processID, err)
			return
		}
		r.finish(processID, durable.ProcessCompleted, answer, nil)
	case capcompute.ResumeYielded:
		// Only the task layer yields, so the process waits on a task. A task
		// settled before this point is found by the next sweep, which wakes the
		// process.
		r.finish(processID, durable.ProcessWaitingTask, "", nil)
	case capcompute.ResumeStopped:
		r.mu.Lock()
		closing := r.closed
		r.mu.Unlock()
		switch {
		case closing:
			// A shutdown interrupts: the next boot resumes the process where it
			// stood.
			r.finish(processID, durable.ProcessInterrupted, "", result.err)
		case errors.Is(result.err, context.DeadlineExceeded):
			// The quantum ran out of time. That bounds execution and says
			// nothing about the work (the guest may have waited on a third party
			// that hung), so the process is interrupted and a retry resumes it.
			r.finish(processID, durable.ProcessInterrupted, "", result.err)
		default:
			// A Stop. The journal records what ran, and a later retry resumes or
			// restarts from there.
			r.finish(processID, durable.ProcessStopped, "", result.err)
		}
	default:
		r.failProcess(processID, result.err)
	}
}

// runQuantum gives one process the CPU for one quantum: it checks that the
// process still runs the program it was created from, builds its dispatcher
// chain, and runs the guest until it completes, yields, stops or fails.
func (r *Runtime) runQuantum(ctx context.Context, cred durable.ProcessContext, id ProgramID, digest string) quantumResult {
	// Setup that fails because the quantum was stopped (a kill, a deadline, a
	// shutdown) is a stop, not a failure of the process.
	failed := func(err error) quantumResult {
		if ctx.Err() != nil {
			return quantumResult{status: capcompute.ResumeStopped, err: ctx.Err()}
		}
		return quantumResult{status: capcompute.ResumeFailed, err: err}
	}
	program, err := r.programs.bound(id, digest)
	if err != nil {
		return failed(err)
	}
	dispatcher, err := r.newDispatcher(ctx, cred, program)
	if err != nil {
		return failed(err)
	}
	process, err := capcompute.NewProcess(ctx, program.image, capcompute.ProcessSpec[durable.ProcessContext]{
		Entrypoint: "run",
		Cred:       cred,
		Dispatcher: dispatcher,
	})
	if err != nil {
		return failed(err)
	}
	// An instance never outlives its quantum.
	defer process.Close(context.Background())
	results, err := capcompute.Resume(ctx, process)
	if err != nil {
		return failed(err)
	}
	result := <-results
	return quantumResult{status: result.Status, err: result.Err}
}

// A guest that completes says how it ended in its last journaled call:
// sys.output with its answer, or sys.abort.

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

// answerFromJournal reads a completed process's answer from its last call,
// which must be a sys.output the output schema accepted: a guest that reports
// completion without an accepted answer did not finish.
func (r *Runtime) answerFromJournal(processID string) (string, error) {
	call, result, ok := r.lastCall(processID)
	switch {
	case !ok || call.Name != sys.SyscallOutput:
		return "", errors.New("agent did not finish: its last call was not sys.output")
	case result.Status() != sys.StatusResult:
		return "", errors.New("agent did not finish: the output schema rejected its final answer")
	}
	var args finishArgs
	if err := json.Unmarshal(call.Args, &args); err != nil {
		return "", fmt.Errorf("decode the final answer: %w", err)
	}
	return args.Answer, nil
}

// finish records how a process's run ended.
func (r *Runtime) finish(processID string, status durable.ProcessStatus, answer string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finishLocked(r.processes[processID], status, answer, err)
}

// finishLocked records how a process's run ended, and frees its session for the
// next process unless the process only parked on a task. Call with r.mu held.
func (r *Runtime) finishLocked(proc *processState, status durable.ProcessStatus, answer string, err error) {
	now := r.now().UTC()
	proc.status = status
	proc.answer = answer
	proc.updatedAt = now
	proc.completedAt = &now
	proc.stop = nil
	proc.err = ""
	if err != nil {
		proc.err = err.Error()
	}
	if isTerminal(status) {
		// Keep the run's taint with the process before releasing it: its answer
		// joins the session history, and a later run that reads the answer
		// inherits the taint. A retry rebuilds the live taint by replay.
		proc.labels = r.taints.Snapshot(proc.context())
		r.taints.ForgetProcess(proc.context())
	}
	session := r.sessions[proc.sessionID]
	if status != durable.ProcessWaitingTask && session.activeProcessID == proc.id {
		session.activeProcessID = ""
	}
	session.updatedAt = now
	_ = r.appendProcess(proc)
}

// isTerminal reports whether a status ends the process's activity: only a
// retry runs it again. A process parked on a task is not terminal: the sweep
// wakes it.
func isTerminal(status durable.ProcessStatus) bool {
	switch status {
	case durable.ProcessCompleted, durable.ProcessFailed, durable.ProcessStopped, durable.ProcessInterrupted:
		return true
	default:
		return false
	}
}
