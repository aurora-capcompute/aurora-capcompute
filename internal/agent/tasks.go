package agent

// The task API. A process that yields parks on a durable task: an approval a
// human resolves, or a timer. The sweep settles tasks whose deadline passed,
// and wakes every process whose task is settled.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
)

// ResolveTask records a human's decision on a pending task, authenticated by
// the task's token, and wakes the process parked on it.
func (r *Runtime) ResolveTask(taskID, token string, resolution durable.TaskResolution) (TaskSnapshot, error) {
	switch resolution.Decision {
	case durable.TaskApproved, durable.TaskCompleted, durable.TaskFailed, durable.TaskDenied, durable.TaskCancelled:
	default:
		return TaskSnapshot{}, fmt.Errorf("%w: unsupported task decision %q", errs.Invalid, resolution.Decision)
	}
	if resolution.Decision == durable.TaskCompleted && !json.Valid(resolution.Data) {
		return TaskSnapshot{}, fmt.Errorf("%w: completed task data must be valid JSON", errs.Invalid)
	}
	tokenHash := sha256.Sum256([]byte(token))
	record, err := r.tasks.Resolve(context.Background(), taskID, tokenHash[:], resolution, r.now().UTC())
	if err != nil {
		return TaskSnapshot{}, err
	}

	// The resolution stands whether or not the wake works: a process that
	// cannot run now (its program is not loaded) is woken by a later sweep.
	if err := r.wake(record.Scope.ProcessID); err != nil {
		slog.Warn("wake process after task resolution", "process_id", record.Scope.ProcessID, "task_id", record.ID, "error", err)
	}
	return r.taskSnapshot(record), nil
}

// taskSweepInterval is how often the runtime settles due tasks and wakes the
// processes parked on settled ones. A timer fires within this of its time.
const taskSweepInterval = time.Second

// sweepLoop sweeps once at start — deadlines can pass while the host is down —
// and then on every interval, until the runtime closes.
func (r *Runtime) sweepLoop() {
	ticker := time.NewTicker(taskSweepInterval)
	defer ticker.Stop()
	for {
		r.sweepTasks()
		select {
		case <-r.baseCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepTasks settles every pending task whose deadline passed (a timer fires,
// an unanswered approval expires), then wakes every process parked on a task
// that is no longer pending. Wakes are read from state, so one that fails is
// tried again on the next sweep. The task store settles each task under its
// lock, so a human and the sweep cannot both resolve it.
func (r *Runtime) sweepTasks() {
	now := r.now().UTC()
	for _, taskID := range r.tasks.Due(now) {
		if err := r.tasks.Settle(context.Background(), taskID, now); err != nil {
			slog.Warn("settle task", "task_id", taskID, "error", err)
		}
	}
	for _, processID := range r.parkedOnSettledTasks() {
		if err := r.wake(processID); err != nil {
			slog.Debug("wake process", "process_id", processID, "error", err)
		}
	}
}

// parkedOnSettledTasks lists the processes waiting on a task that no longer
// waits on anyone.
func (r *Runtime) parkedOnSettledTasks() []string {
	r.mu.Lock()
	var waiting []string
	for id, proc := range r.processes {
		if proc.status == durable.ProcessWaitingTask {
			waiting = append(waiting, id)
		}
	}
	r.mu.Unlock()
	var settled []string
	for _, id := range waiting {
		pending := slices.ContainsFunc(r.tasks.List(id), func(task durable.TaskRecord) bool {
			return task.State == durable.TaskPending
		})
		if !pending {
			settled = append(settled, id)
		}
	}
	return settled
}

// wake resumes a process parked on a task. It leaves a process in any other
// state alone, so the resolver and the sweep may both call it.
func (r *Runtime) wake(processID string) error {
	r.mu.Lock()
	waiting := r.processes[processID].status == durable.ProcessWaitingTask
	r.mu.Unlock()
	if !waiting {
		return nil
	}
	_, err := r.Retry(processID, RetryResume)
	return err
}
