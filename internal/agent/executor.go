package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/process"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
)

// processActivator is the application half of the run queue's seam: it puts one
// process revision on the CPU. It assembles the revision's dispatcher chain
// (monitor stack, replay tape over the journal, task layer, delegation routes,
// drivers) and hands it to the direct package, which owns everything below —
// instantiating the guest from the program's compiled image and starting its
// quantum. Activation is exactly journal-replay wiring — the journal, not the
// instance, is the durable process — which is why the queue cannot do it and the
// runtime must.
type processActivator struct{ runtime *Runtime }

func (a processActivator) Execute(ctx context.Context, key processKey) (process.Handle, error) {
	r := a.runtime
	r.mu.Lock()
	proc := r.processes[key.processID]
	if proc != nil && proc.revision != key.revision {
		// The process has forked past the revision this quantum was submitted
		// for; the submission is stale and must not run.
		proc = nil
	}
	var cred ProcessContext
	var program ProgramID
	if proc != nil {
		cred = ProcessContext{
			TenantID:  r.tenantID,
			SessionID: proc.sessionID,
			ProcessID: proc.id,
			Revision:  proc.revision,
			Digest:    proc.digest,
		}
		program = ProgramID(proc.manifest.Program)
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: no process for pid %s", errs.NotFound, key)
	}
	if err := r.programBinding(proc); err != nil {
		return nil, err
	}
	return r.images.Spawn(ctx, program, cred, r.factory.NewDispatcher)
}

// processMachine is the hardware half of the seam: it waits out one quantum and
// releases the instance afterwards. It holds no runtime state, because it needs
// none — the direct package speaks for the processor, and this type only
// restates its handle in the queue's vocabulary.
type processMachine struct{}

func (processMachine) Resume(_ context.Context, handle process.Handle) (sched.Result, error) {
	return quantumResult(<-handle.Result()), nil
}

func (processMachine) Release(handle process.Handle) { handle.Release() }

// quantumResult restates a process outcome as a queue outcome.
func quantumResult(result process.Result) sched.Result {
	status := sched.Failed
	switch result.Status {
	case process.Completed:
		status = sched.Completed
	case process.Yielded:
		status = sched.Yielded
	case process.Stopped:
		status = sched.Stopped
	}
	return sched.Result{Status: status, Err: result.Error}
}

func (r *Runtime) execute(ctx context.Context, processID string) {
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
	leaseResource := fmt.Sprintf("%s/%d", proc.id, proc.revision)
	acquired, leaseErr := r.leases.Acquire(
		context.Background(), r.tenantID, "process", leaseResource,
		r.instanceID, r.now().UTC(), r.leaseTTL,
	)
	if leaseErr != nil || !acquired {
		err := leaseErr
		if err == nil {
			err = errors.New("process is leased by another Aurora instance")
		}
		r.mu.Unlock()
		r.finish(processID, durable.ProcessInterrupted, "", err)
		return
	}
	defer r.leases.Release(
		context.Background(), r.tenantID, "process", leaseResource, r.instanceID,
	)
	key := proc.key()
	isChild := proc.parentProcessID != ""
	deadline := proc.deadline
	r.mu.Unlock()

	results, stop, err := r.startQuantum(ctx, key, deadline, isChild)
	if err != nil {
		// Only admission can fail here; an activation that fails arrives as a
		// result, on both paths alike.
		if r.failureStatus(err) == durable.ProcessFailed {
			r.failProcess(processID, err)
		} else {
			r.finish(processID, durable.ProcessInterrupted, "", err)
		}
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
	snapshot := r.processSnapshotLocked(proc)
	sessionID := proc.sessionID
	_ = r.appendProcess(proc)
	r.mu.Unlock()
	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	if stopRequested {
		stop()
	}

	result := <-results
	r.mu.Lock()
	if proc = r.processes[processID]; proc != nil {
		proc.stop = nil
	}
	r.mu.Unlock()
	switch result.Status {
	case sched.Completed:
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
	case sched.Yielded:
		tasks, taskErr := r.tasks.List(context.Background(), r.tenantID, processID)
		if taskErr == nil && hasPendingTask(tasks) {
			r.finish(processID, durable.ProcessWaitingTask, "", nil)
		} else {
			r.finish(processID, durable.ProcessYielded, "", taskErr)
		}
	case sched.Stopped:
		r.mu.Lock()
		closing := r.closed
		r.mu.Unlock()
		switch {
		case closing:
			// A closing host interrupts, never aborts: the restart resumes the
			// open section mid-flight — a host restart must not touch effects.
			r.finish(processID, durable.ProcessInterrupted, "", result.Err)
		case errors.Is(result.Err, context.DeadlineExceeded):
			// The quantum ran out of wall-clock. That is a bound on execution,
			// not a verdict on the work: the guest may have been waiting on a
			// third party that hung. So the process is interrupted — its journal
			// stands, and a retry resumes from the last open savepoint.
			r.finish(processID, durable.ProcessInterrupted, "", result.Err)
		default:
			r.stopProcess(processID, result.Err)
		}
	default:
		r.failProcess(processID, result.Err)
	}
}

// startQuantum puts a process on the CPU and returns the channel its outcome
// will arrive on, with the means to abort it. A root queues for a slot; a
// delegated child runs off the queue inside its parent's quantum — ctx — rather
// than competing for a slot the parent is already holding, which is what keeps
// delegation from deadlocking against the concurrency cap. Only a root can fail
// here, and only on admission: an activation that fails is a result, not an
// error, on both paths alike.
func (r *Runtime) startQuantum(ctx context.Context, key processKey, deadline time.Duration, isChild bool) (<-chan sched.Result, func(), error) {
	if isChild {
		results, cancel := r.scheduler.Run(ctx, key, deadline)
		return results, cancel, nil
	}
	results, err := r.scheduler.Submit(key, deadline)
	if err != nil {
		return nil, nil, err
	}
	return results, func() { r.scheduler.Stop(key) }, nil
}

// failureStatus maps an admission error to the process status it should finish
// with: a scheduling conflict is an interruption (the process can be re-driven);
// anything else is a failure.
func (r *Runtime) failureStatus(err error) durable.ProcessStatus {
	if errors.Is(err, sched.ErrAlreadyScheduled) || errors.Is(err, sched.ErrClosed) {
		return durable.ProcessInterrupted
	}
	return durable.ProcessFailed
}

func (r *Runtime) finish(processID string, status durable.ProcessStatus, answer string, err error) {
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return
	}
	r.finishLocked(proc, status, answer, err)
	_ = r.appendProcess(proc)
	snapshot := r.processSnapshotLocked(proc)
	sessionID := proc.sessionID
	parentProcessID := proc.parentProcessID
	r.mu.Unlock()
	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})

	// When a delegated child reaches a terminal state, re-drive its parent if the
	// parent is suspended waiting on it (HITL approval flow). resumeParentIfWaiting
	// is a no-op for a parent still actively blocked in a synchronous delegation
	// call, so the existing fast path is unaffected.
	if parentProcessID != "" && isTerminal(status) {
		r.resumeParentIfWaiting(parentProcessID)
	}
}

func (r *Runtime) finishLocked(proc *processState, status durable.ProcessStatus, answer string, err error) {
	now := r.now().UTC()
	proc.status = status
	proc.answer = answer
	proc.updatedAt = now
	proc.completedAt = &now
	proc.stop = nil
	// Consumed by the reconnect re-drive during the play; clear it now the play has
	// ended so a later unrelated retry isn't treated as a reconnect.
	proc.reconnectChildren = false
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
			// When a child process finishes in the parent's session, return activeProcessID to
			// the parent so the parent goroutine can resume on the same session.
			if proc.parentProcessID != "" {
				if parent := r.processes[proc.parentProcessID]; parent != nil && parent.sessionID == proc.sessionID {
					session.activeProcessID = proc.parentProcessID
				} else {
					session.activeProcessID = ""
				}
			} else {
				session.activeProcessID = ""
			}
		}
		session.updatedAt = now
		if status == durable.ProcessCompleted && proc.parentProcessID == "" {
			session.history = append(session.history,
				HistoryMessage{Role: "user", Content: proc.input},
				HistoryMessage{Role: "assistant", Content: answer, Labels: proc.labels},
			)
		}
	}
}

// scope returns the event stream key for a session.
func (r *Runtime) scope(sessionID string) eventlog.Scope {
	return eventlog.Scope{TenantID: r.tenantID, SessionID: sessionID}
}

func (r *Runtime) journalNow() time.Time { return r.now().UTC() }

// journalAppendPublisher publishes a journal.appended event for a session when a
// record is appended to one of its processes' journals.
func (r *Runtime) journalAppendPublisher(sessionID string) func(string, uint64, journaled.Record, string) {
	return func(processID string, revision uint64, rec journaled.Record, syscallName string) {
		event := JournalEvent{
			ProcessID: processID,
			Position:  rec.Position,
			Revision:  revision,
			Kind:      rec.Kind,
			Syscall:   syscallName,
		}
		if rec.Result != nil {
			event.OutcomeStatus = rec.Result.Status()
			event.OutcomeSize = len(rec.Result.Result())
		}
		r.publish(sessionID, Event{Type: "journal.appended", Data: event})
	}
}

// appendProcess records a process's current state to its session's event stream.
//
// CONTRACT: this runs while r.mu (the single lock guarding all session/process
// maps) is held, and callers check its error to roll a partial mutation back —
// so the append stays synchronous and under the lock by design. The injected
// eventlog.Log.Append MUST therefore be non-blocking/local (an in-memory or fast
// local sink): a log that blocks on remote I/O would stall every concurrent
// reader and state transition for that duration. Moving the append off-lock is
// not a safe local change — it would either reorder same-entity events in the
// restore fold or force appends to become asynchronous (losing the
// synchronous-failure rollback callers depend on); an async ordered-append
// pipeline is the proper redesign if a blocking log is ever required. The
// context is non-cancellable on purpose: a metadata append must complete on
// shutdown to persist final state (unlike background work, which derives from
// the cancellable baseCtx).
func (r *Runtime) appendProcess(proc *processState) error {
	ev, err := durable.ProcessStateEvent(r.now().UTC(), r.storedProcessLocked(proc))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), r.scope(proc.sessionID), ev)
	return err
}

func (r *Runtime) appendSession(session *sessionState) error {
	ev, err := durable.SessionStateEvent(r.now().UTC(), r.storedSessionLocked(session))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), r.scope(session.id), ev)
	return err
}

func (r *Runtime) newJournal(proc *processState, history *processHistory, forkOffset int) *logJournal {
	return newLogJournal(r.log, r.scope(proc.sessionID), proc.id, proc.revision,
		history, forkOffset, r.journalNow, r.journalAppendPublisher(proc.sessionID))
}

func (r *Runtime) publish(sessionID string, event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.subscribers[sessionID] {
		select {
		case ch <- event:
		default:
		}
	}
}
