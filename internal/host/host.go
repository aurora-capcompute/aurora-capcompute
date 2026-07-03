// Package host owns the per-process dispatcher stack. It takes the caller-supplied
// driver chain and completes it, for one process, with durable task approval and
// savepoint markers, then hands the whole thing to capcompute.Stack.ForProcess so
// the kernel's canonical monitor chain (Validator → FlowMonitor → replay →
// Labeler → Declassifier → drivers) is assembled in the one correct order —
// never by hand. The per-process piece is the tape: a journaled.Tape over the
// process's journal, stamped with the process's header (ABI, program digest, PID).
//
// It owns only the wiring of that stack; the task store, journal, grant
// source, taint state, and driver chain are injected.
package host

import (
	"context"
	"errors"
	"time"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

// Factory builds one process's complete dispatcher chain.
//
// Drivers supplies everything below the task layer (progress reporting and
// the application's capability drivers). Wrap stacks the runtime's protocol
// layers above the task layer, below the savepoint markers — delegation
// routing (which must see a syscall before the task layer so a delegated
// child's park never becomes a human task) and the agent lifecycle (whose
// input payload advertises the whole capability surface beneath it). The
// resulting chain, innermost first:
//
//	Drivers ← task ← Wrap ← savepoints ← [Stack: Labeler/Declassifier ← replay ← FlowMonitor ← Validator]
type Factory[ID comparable, K capcompute.PID[ID]] struct {
	Drivers    func(context.Context, K) (sys.Dispatcher[K], error)
	Wrap       func(K, sys.Dispatcher[K]) (sys.Dispatcher[K], error)
	NewJournal func(context.Context, K) (journaled.Journal, error)
	Header     func(K) journaled.Header
	Taints     *capcompute.Taints[ID]

	Tasks         task.Store
	TaskScope     func(K) task.Scope
	TaskSecret    []byte
	TaskTTL       time.Duration
	OnTaskCreated func(task.Record)
}

func (f Factory[ID, K]) NewDispatcher(ctx context.Context, cred K) (sys.Dispatcher[K], error) {
	if f.Drivers == nil || f.NewJournal == nil || f.Header == nil || f.Taints == nil ||
		f.Tasks == nil || f.TaskScope == nil || len(f.TaskSecret) == 0 {
		return nil, errors.New("dispatcher factory is not configured")
	}
	drivers, err := f.Drivers(ctx, cred)
	if err != nil {
		return nil, err
	}
	if drivers == nil {
		return nil, errors.New("dispatcher provider returned nil dispatcher")
	}
	journal, err := f.NewJournal(ctx, cred)
	if err != nil {
		return nil, err
	}
	tape, err := journaled.NewTape(journal, f.Header(cred))
	if err != nil {
		return nil, err
	}
	var below sys.Dispatcher[K] = &task.Dispatcher[K]{
		Next:          drivers,
		Store:         f.Tasks,
		Journal:       journal,
		Scope:         f.TaskScope,
		TokenSecret:   append([]byte(nil), f.TaskSecret...),
		TaskTTL:       f.TaskTTL,
		OnTaskCreated: f.OnTaskCreated,
	}
	if f.Wrap != nil {
		below, err = f.Wrap(cred, below)
		if err != nil {
			return nil, err
		}
	}
	// Savepoint markers sit below replay (so they are journaled) and above the
	// task and routing layers (so they never become durable tasks or dispatch
	// a child).
	withSavepoints := &savepointDispatcher[K]{next: below}

	// The grant set is the complete mediation surface: everything this process's
	// chain can serve — drivers, delegation routes, and the runtime's own
	// protocol capabilities — is granted explicitly; anything else is denied
	// by the Validator before it reaches a driver.
	stack := capcompute.Stack[ID, K]{
		Grants: func(K) []sys.Capability { return withSavepoints.Capabilities() },
		Taints: f.Taints,
	}
	return stack.ForProcess(tape, withSavepoints)
}
