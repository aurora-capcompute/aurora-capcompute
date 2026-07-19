// Package host owns the per-process dispatcher stack. It takes the caller-supplied
// driver chain and completes it, for one process, with durable task approval and
// savepoint markers, then hands the whole thing to monitor.Stack.ForProcess so
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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
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
	Taints     *monitor.Taints[ID]
	// OpenIntents overrides the replay open-intent policy — what to do with an
	// effect journaled without a recorded completion, met on crash-resume. Nil
	// retries every open intent under its original idempotency key.
	OpenIntents replay.OpenIntentPolicy
	// Now and Rand feed the journaled world sources (sys.now / sys.random);
	// nil defaults to the real clock and crypto/rand.
	Now  func() time.Time
	Rand io.Reader

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
	// Tamper-evidence, enforced. The journal's hash chain is the audit trail's
	// integrity guarantee; verifying it here — before any record is served to
	// replay — turns "tamper-evident" from an available check into a fail-closed
	// one: a journal whose chain does not verify (a compromised or buggy durable
	// store rewrote a record) is refused rather than replayed as truth. Replay
	// already walks the whole journal, so this is the same order of work.
	if err := journaled.Verify(journal); err != nil {
		return nil, fmt.Errorf("journal integrity check failed: %w", err)
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
	// The world sources sit below replay (so their values are journaled and
	// replay verbatim) and above the task and routing layers.
	now := f.Now
	if now == nil {
		now = time.Now
	}
	entropy := f.Rand
	if entropy == nil {
		entropy = rand.Reader
	}
	withWorld := &worldDispatcher[K]{next: below, now: now, rand: entropy}
	// Savepoint markers sit below replay (so they are journaled) and above the
	// task and routing layers (so they never become durable tasks or dispatch
	// a child).
	withSavepoints := &savepointDispatcher[K]{next: withWorld}

	// The grant set is the complete mediation surface: everything this process's
	// chain can serve — drivers, delegation routes, and the runtime's own
	// protocol capabilities — is granted explicitly; anything else is denied
	// by the Validator before it reaches a driver.
	stack := monitor.Stack[ID, K]{
		Grants:      func(K) []sys.Capability { return withSavepoints.Capabilities() },
		Taints:      f.Taints,
		OpenIntents: f.OpenIntents,
	}
	return stack.ForProcess(tape, withSavepoints)
}
