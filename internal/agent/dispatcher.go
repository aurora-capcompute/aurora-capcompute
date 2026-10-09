package agent

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// newDispatcher builds one process's dispatcher chain for one quantum,
// outermost first:
//
//	Validator → Flow.Guard → replay → Flow.Stamp  (monitor.Wrap)
//	  → savepoints → world → lifecycle → task → Declassifier → progress → timer → drivers
//
// Everything beneath the replay layer is journaled: the savepoint markers, the
// world sources (sys.now, sys.random), the lifecycle calls, and every effect.
// The task layer sits just beneath the protocol layers, so a yield from below
// it becomes a durable task and the journal tail is the call's intent.
func (r *Runtime) newDispatcher(ctx context.Context, cred durable.ProcessContext, program compiledProgram) (sys.Dispatcher[durable.ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	spec := proc.manifest.Clone()
	input := proc.input
	var history []HistoryMessage
	// A manifest declaring history:false serves no session history on its
	// sys.input — the process sees only its own input.
	if spec.SharesHistory() {
		history = r.historyBeforeLocked(proc)
	}
	attempt := proc.attempt
	journal := proc.journal
	r.mu.Unlock()

	table, err := r.dispatchers.NewDispatcher(ctx, cred, spec)
	if err != nil {
		return nil, err
	}
	if err := reconcileGrants(table.Descriptors(), spec); err != nil {
		return nil, err
	}
	// The routing dispatcher is built here, from the table the provider
	// returned, rather than by the provider: the chain that serves a call and
	// the index the monitor judges it against are then the same object by
	// construction. Each layer below declares the syscalls it serves into that
	// table as it is built, so the grant set names only what the chain answers.
	var chain sys.Dispatcher[durable.ProcessContext] = capability.NewDispatcher[durable.ProcessContext](table)
	if grant, ok := spec.FindSyscall(manifest.TimerSyscall); ok {
		if chain, err = newTimerDispatcher(chain, grant, table); err != nil {
			return nil, err
		}
	}
	if chain, err = newProgressDispatcher(chain, table); err != nil {
		return nil, err
	}
	// Beneath the task layer, so its approval yield becomes a durable task.
	chain = monitor.NewDeclassifier(chain)
	chain = &task.Dispatcher{
		Next:        chain,
		Store:       r.tasks,
		Journal:     journal,
		Now:         r.now,
		TokenSecret: r.taskSecret,
		TaskTTL:     r.taskTTL,
	}
	if chain, err = newLifecycleDispatcher(chain, input, history, spec, attempt, program.validateOutput, table); err != nil {
		return nil, err
	}
	if chain, err = newWorldDispatcher(chain, r.now, rand.Reader, table); err != nil {
		return nil, err
	}
	chain = &savepointDispatcher{next: chain}

	// A malformed journal is refused before any record is served to replay
	// rather than replayed as truth: positions out of order, or intents and
	// completions that do not alternate, mean the store handed back something
	// replay cannot reason about.
	if err := journaled.Verify(journal); err != nil {
		return nil, fmt.Errorf("journal integrity check failed: %w", err)
	}
	return monitor.Wrap(r.taints, journaled.NewTape(journal), table, chain), nil
}
