package agent

import (
	"context"
	"errors"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute"
)

func (r *Runtime) execute(processID string) {
	defer r.wg.Done()

	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return
	}
	if proc.stopRequested {
		r.mu.Unlock()
		r.stopProcess(processID, context.Canceled)
		return
	}
	cred := r.processContextLocked(proc)
	program := ProgramID(proc.manifest.Program)
	digest := proc.digest
	deadline := proc.deadline
	r.mu.Unlock()

	results, stop, err := r.pool.submit(deadline, func(ctx context.Context) quantumResult {
		return r.runQuantum(ctx, cred, program, digest)
	})
	if err != nil {
		r.finish(processID, durable.ProcessInterrupted, "", err)
		return
	}

	r.mu.Lock()
	proc = r.processes[processID]
	if proc == nil {
		// The process was removed while its quantum was starting (a withdrawn
		// program drains its processes). Abort the quantum rather than record a
		// running state for a process that is gone; the result is buffered, so
		// leaving it unread strands nothing.
		r.mu.Unlock()
		stop()
		return
	}
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
	if proc = r.processes[processID]; proc != nil {
		proc.stop = nil
	}
	r.mu.Unlock()
	switch result.status {
	case capcompute.ResumeCompleted:
		if reason, aborted := r.guestAbort(processID); aborted {
			// The guest ended with sys.abort: re-drive its open savepoint
			// section instead of reading an answer.
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
		tasks, taskErr := r.tasks.List(context.Background(), r.tenantID, processID)
		if taskErr == nil && hasPendingTask(tasks) {
			r.finish(processID, durable.ProcessWaitingTask, "", nil)
		} else {
			r.finish(processID, durable.ProcessYielded, "", taskErr)
		}
	case capcompute.ResumeStopped:
		r.mu.Lock()
		closing := r.closed
		r.mu.Unlock()
		switch {
		case closing:
			// A closing host interrupts, never aborts: the restart resumes the
			// open section mid-flight — a host restart must not touch effects.
			r.finish(processID, durable.ProcessInterrupted, "", result.err)
		case errors.Is(result.err, context.DeadlineExceeded):
			// The quantum ran out of wall-clock. That is a bound on execution,
			// not a verdict on the work: the guest may have been waiting on a
			// third party that hung. So the process is interrupted — its journal
			// stands, and a retry resumes from the last open savepoint.
			r.finish(processID, durable.ProcessInterrupted, "", result.err)
		default:
			r.stopProcess(processID, result.err)
		}
	default:
		r.failProcess(processID, result.err)
	}
}

// runQuantum gives one process the CPU for one quantum: it checks that the
// process still runs the program it was created from, builds its dispatcher
// chain, and runs the guest until it completes, yields, stops or fails.
func (r *Runtime) runQuantum(ctx context.Context, cred ProcessContext, id ProgramID, digest string) quantumResult {
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
	dispatcher, err := r.factory.NewDispatcher(ctx, cred)
	if err != nil {
		return failed(err)
	}
	process, err := capcompute.NewProcess(ctx, program.image, capcompute.ProcessSpec[ProcessContext]{
		Entrypoint: "run",
		Cred:       cred,
		Dispatcher: dispatcher,
	})
	if err != nil {
		return failed(err)
	}
	// An instance never outlives its quantum.
	defer process.Close(context.Background())
	handle, err := capcompute.Resume(ctx, process)
	if err != nil {
		return failed(err)
	}
	result := <-handle.Results
	return quantumResult{status: result.Status, err: result.Err}
}

func (r *Runtime) finish(processID string, status durable.ProcessStatus, answer string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil {
		return
	}
	r.finishLocked(proc, status, answer, err)
	_ = r.appendProcess(proc)
}

func (r *Runtime) finishLocked(proc *processState, status durable.ProcessStatus, answer string, err error) {
	now := r.now().UTC()
	proc.status = status
	proc.answer = answer
	proc.updatedAt = now
	proc.completedAt = &now
	proc.stop = nil
	if err != nil {
		proc.err = err.Error()
	} else {
		proc.err = ""
	}
	if isTerminal(status) {
		// Snapshot the run's taint before releasing it, so the answer this process
		// contributes to session history carries the run's provenance into any
		// later run that reads it (closing the run-to-run laundering loophole).
		proc.labels = r.taints.Snapshot(proc.key())
		// The process's taint state is scoped to its revision identity; release
		// it when no further quantum can observe it. A parked process keeps its
		// taint (resume must re-enforce flow policy over the same history).
		r.taints.ForgetProcess(proc.key())
	}
	session := r.sessions[proc.sessionID]
	if session != nil {
		if status != durable.ProcessYielded && status != durable.ProcessWaitingTask && session.activeProcessID == proc.id {
			session.activeProcessID = ""
		}
		session.updatedAt = now
		if status == durable.ProcessCompleted {
			session.history = append(session.history,
				HistoryMessage{Role: "user", Content: proc.input},
				HistoryMessage{Role: "assistant", Content: answer, Labels: proc.labels},
			)
		}
	}
}
