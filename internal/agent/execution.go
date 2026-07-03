package agent

// Run execution: the quantum that drives a brain to a terminal state, the
// finishing path, and the event appends plus subscriber publishing that surface
// each state change to the durable log and live watchers.
//
// Root runs are submitted to the kernel's fair-share scheduler (per-tenant
// round-robin, quotas, virtual-actor residency); a delegated child run
// executes directly inside its parent's quantum — the kernel's own sync-spawn
// posture — so delegation can never deadlock the scheduler's concurrency cap.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sched"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
)

// activateProcess reconstructs the process for one run revision: it assembles
// the run's dispatcher chain (monitor stack, replay tape over the journal,
// task layer, delegation routes, drivers), instantiates the guest from the
// brain's kernel, and saves it to the process table so the syscall host path
// can find its dispatcher. Activation is exactly journal-replay wiring — the
// journal, not the instance, is the durable process.
func (r *Runtime) activateProcess(ctx context.Context, pid string) (*capcompute.Process[RunContext], error) {
	r.mu.Lock()
	var run *runState
	for _, candidate := range r.runs {
		if runPID(candidate.id, candidate.revision) == pid {
			run = candidate
			break
		}
	}
	var cred RunContext
	var brainID string
	if run != nil {
		cred = r.runContextLocked(run)
		brainID = run.manifest.Brain
	}
	kernel := r.kernels[brainID]
	r.mu.Unlock()
	if run == nil {
		return nil, fmt.Errorf("%w: no run for process %s", ErrNotFound, pid)
	}
	if kernel == nil {
		return nil, fmt.Errorf("brain %q is unavailable", brainID)
	}

	chain, err := r.factory.NewDispatcher(ctx, cred)
	if err != nil {
		return nil, err
	}
	process, err := kernel.CreateProcess(ctx, capcompute.ProcessSpec[string, RunContext]{
		Entrypoint: "run",
		Cred:       cred,
		Dispatcher: chain,
		// The guest fetches its input via the agent.input syscall (served by
		// the lifecycle dispatcher), so no entrypoint input is supplied here.
	})
	if err != nil {
		return nil, err
	}
	if err := r.processTable.SaveProcess(ctx, pid, process); err != nil {
		_ = process.Close(context.Background())
		return nil, err
	}
	return process, nil
}

// resumeProcess is the scheduler's Resume seam: one quantum on the kernel
// owning the process's brain.
func (r *Runtime) resumeProcess(ctx context.Context, process *capcompute.Process[RunContext]) (<-chan capcompute.ResumeResult[RunContext], error) {
	r.mu.Lock()
	var brainID string
	if run := r.runs[process.Cred.RunID]; run != nil {
		brainID = run.manifest.Brain
	}
	kernel := r.kernels[brainID]
	r.mu.Unlock()
	if kernel == nil {
		return nil, fmt.Errorf("brain %q is unavailable", brainID)
	}
	handle, err := kernel.Resume(ctx, process)
	if err != nil {
		return nil, err
	}
	return handle.Results(), nil
}

// execute drives one run attempt to a terminal-or-parked state.
func (r *Runtime) execute(runID string) {
	defer r.wg.Done()

	r.mu.Lock()
	run := r.runs[runID]
	if run == nil {
		r.mu.Unlock()
		return
	}
	if run.stopRequested {
		r.finishLocked(run, RunStopped, "", context.Canceled)
		snapshot := r.runSnapshotLocked(run)
		threadID := run.threadID
		r.mu.Unlock()
		r.publish(threadID, Event{Type: "run.updated", Data: snapshot})
		return
	}
	leaseResource := fmt.Sprintf("%s/%d", run.id, run.revision)
	acquired, leaseErr := r.leases.Acquire(
		context.Background(), r.tenantID, "run", leaseResource,
		r.instanceID, r.now().UTC(), r.leaseTTL,
	)
	if leaseErr != nil || !acquired {
		err := leaseErr
		if err == nil {
			err = errors.New("run is leased by another Aurora instance")
		}
		r.finishLocked(run, RunInterrupted, "", err)
		_ = r.appendRun(run)
		snapshot := r.runSnapshotLocked(run)
		threadID := run.threadID
		r.mu.Unlock()
		r.publish(threadID, Event{Type: "run.updated", Data: snapshot})
		return
	}
	defer r.leases.Release(
		context.Background(), r.tenantID, "run", leaseResource, r.instanceID,
	)
	pid := runPID(run.id, run.revision)
	isChild := run.parentRunID != ""
	tenantID := r.tenantID
	r.mu.Unlock()

	var results <-chan capcompute.ResumeResult[RunContext]
	var stop func()
	var err error
	if isChild {
		// A delegated child executes inside its parent's quantum: activate and
		// resume directly rather than competing for a scheduler slot the
		// parent is already holding.
		results, stop, err = r.driveDirect(pid)
	} else {
		results, err = r.scheduler.Submit(context.Background(), pid, tenantID, sched.Normal)
		if err == nil {
			stop = func() { r.scheduler.Stop(pid) }
		}
	}
	if err != nil {
		r.finish(runID, r.failureStatus(err), "", err)
		return
	}

	r.mu.Lock()
	run = r.runs[runID]
	now := r.now().UTC()
	run.stop = stop
	run.status = RunRunning
	run.startedAt = &now
	run.updatedAt = now
	stopRequested := run.stopRequested
	snapshot := r.runSnapshotLocked(run)
	threadID := run.threadID
	_ = r.appendRun(run)
	r.mu.Unlock()
	r.publish(threadID, Event{Type: "run.updated", Data: snapshot})
	if stopRequested {
		stop()
	}

	result := <-results
	r.mu.Lock()
	run = r.runs[runID]
	run.stop = nil
	forced := run.failure
	r.mu.Unlock()
	if forced != nil {
		r.finish(runID, RunFailed, "", forced)
		return
	}
	switch result.Status {
	case capcompute.ResumeCompleted:
		answer, err := r.answerFromJournal(runID)
		if err != nil {
			r.finish(runID, RunFailed, "", err)
			return
		}
		r.finish(runID, RunCompleted, answer, nil)
	case capcompute.ResumeYielded:
		tasks, taskErr := r.tasks.List(context.Background(), r.tenantID, runID)
		if taskErr == nil && hasPendingTask(tasks) {
			r.finish(runID, RunWaitingTask, "", nil)
		} else {
			r.finish(runID, RunYielded, "", taskErr)
		}
	case capcompute.ResumeStopped:
		r.mu.Lock()
		closing := r.closed
		r.mu.Unlock()
		if closing {
			r.finish(runID, RunInterrupted, "", result.Err)
		} else {
			r.finish(runID, RunStopped, "", result.Err)
		}
	default:
		r.finish(runID, RunFailed, "", result.Err)
	}
}

// driveDirect activates and resumes a run outside the scheduler — the path for
// delegated children, which run inside their parent's quantum.
func (r *Runtime) driveDirect(pid string) (<-chan capcompute.ResumeResult[RunContext], func(), error) {
	ctx, cancel := context.WithCancel(context.Background())
	process, err := r.activateProcess(ctx, pid)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	results, err := r.resumeProcess(ctx, process)
	if err != nil {
		cancel()
		_ = process.Close(context.Background())
		return nil, nil, err
	}
	out := make(chan capcompute.ResumeResult[RunContext], 1)
	go func() {
		defer cancel()
		result := <-results
		// A direct-driven instance is per-quantum: reactivation is by replay.
		_ = process.Close(context.Background())
		out <- result
	}()
	return out, cancel, nil
}

// failureStatus maps a pre-quantum error to the run status it should finish
// with: an incompatible journal or an already-scheduled process is a lifecycle
// conflict (interrupted), everything else a failure.
func (r *Runtime) failureStatus(err error) RunStatus {
	var incompatible journaled.ReplayIncompatibleError
	if errors.As(err, &incompatible) {
		return RunFailed
	}
	if errors.Is(err, sched.ErrAlreadyScheduled) || errors.Is(err, sched.ErrClosed) {
		return RunInterrupted
	}
	return RunFailed
}

// requestRunFailure marks a run to finish as failed and stops its in-flight
// quantum. It is used to propagate a delegated child's failure up to its parent
// run when the child's failure-mode policy is OnFailurePropagate.
func (r *Runtime) requestRunFailure(runID string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return
	}
	if run.failure == nil {
		run.failure = err
	}
	if run.stop != nil {
		run.stop()
	}
}

func (r *Runtime) finish(runID string, status RunStatus, answer string, err error) {
	r.mu.Lock()
	run := r.runs[runID]
	if run == nil {
		r.mu.Unlock()
		return
	}
	r.finishLocked(run, status, answer, err)
	_ = r.appendRun(run)
	snapshot := r.runSnapshotLocked(run)
	threadID := run.threadID
	parentRunID := run.parentRunID
	r.mu.Unlock()
	r.publish(threadID, Event{Type: "run.updated", Data: snapshot})

	// When a delegated child reaches a terminal state, re-drive its parent if the
	// parent is suspended waiting on it (HITL approval flow). resumeParentIfWaiting
	// is a no-op for a parent still actively blocked in a synchronous delegation
	// call, so the existing fast path is unaffected.
	if parentRunID != "" && isTerminal(status) {
		r.resumeParentIfWaiting(parentRunID)
	}
}

func (r *Runtime) finishLocked(run *runState, status RunStatus, answer string, err error) {
	now := r.now().UTC()
	run.status = status
	run.answer = answer
	run.updatedAt = now
	run.completedAt = &now
	run.stop = nil
	// Consumed by the reconnect re-drive during the play; clear it now the play has
	// ended so a later unrelated retry isn't treated as a reconnect.
	run.reconnectChildren = false
	if err != nil {
		run.err = err.Error()
	} else {
		run.err = ""
	}
	if isTerminal(status) {
		// The run's taint state is scoped to its process identity; release it
		// when no further quantum can observe it. A parked run keeps its taint
		// (resume must re-enforce flow policy over the same history).
		r.taints.ForgetRun(runPID(run.id, run.revision))
	}
	thread := r.threads[run.threadID]
	if thread != nil {
		if status != RunYielded && status != RunWaitingTask && thread.activeRunID == run.id {
			// When a child run finishes in the parent's thread, return activeRunID to
			// the parent so the parent goroutine can resume on the same thread.
			if run.parentRunID != "" {
				if parent := r.runs[run.parentRunID]; parent != nil && parent.threadID == run.threadID {
					thread.activeRunID = run.parentRunID
				} else {
					thread.activeRunID = ""
				}
			} else {
				thread.activeRunID = ""
			}
		}
		thread.updatedAt = now
		if status == RunCompleted && run.parentRunID == "" {
			thread.history = append(thread.history,
				HistoryMessage{Role: "user", Content: run.message},
				HistoryMessage{Role: "assistant", Content: answer},
			)
		}
	}
}

// scope returns the event stream key for a thread.
func (r *Runtime) scope(threadID string) eventlog.Scope {
	return eventlog.Scope{TenantID: r.tenantID, ThreadID: threadID}
}

func (r *Runtime) journalNow() time.Time { return r.now().UTC() }

// journalAppendPublisher publishes a journal.appended event for a thread when a
// record is appended to one of its runs' journals.
func (r *Runtime) journalAppendPublisher(threadID string) func(string, uint64, journaled.Record, string) {
	return func(runID string, revision uint64, rec journaled.Record, syscallName string) {
		event := JournalEvent{
			RunID:    runID,
			Position: rec.Position,
			Revision: revision,
			Kind:     rec.Kind,
			Syscall:  syscallName,
		}
		if rec.Result != nil {
			event.OutcomeStatus = rec.Result.Status()
			event.OutcomeSize = len(rec.Result.Result())
		}
		r.publish(threadID, Event{Type: "journal.appended", Data: event})
	}
}

// appendRun records a run's current state to its thread's event stream.
func (r *Runtime) appendRun(run *runState) error {
	ev, err := runStateEvent(r.now().UTC(), r.storedRunLocked(run))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), r.scope(run.threadID), ev)
	return err
}

func (r *Runtime) newJournal(run *runState, history *runHistory, forkOffset int) *logJournal {
	return newLogJournal(r.log, r.scope(run.threadID), run.id, run.revision,
		history, forkOffset, r.journalNow, r.journalAppendPublisher(run.threadID))
}

func (r *Runtime) publish(threadID string, event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.subscribers[threadID] {
		select {
		case ch <- event:
		default:
		}
	}
}
