// Package host owns the per-process dispatcher stack. It takes the caller-supplied
// driver chain and completes it, for one process, with durable task approval and
// savepoint markers, then hands the whole thing to monitor.Stack.ForProcess so
// the processor's canonical monitor chain (Validator → Flow.Guard → replay →
// Flow.Stamp → Declassifier → drivers) is assembled in the one correct order —
// never by hand. The per-process piece is the tape: a journaled.Tape over the
// process's journal, stamped with the process's header (ABI, program digest, PID).
//
// It owns only the wiring of that stack; the task store, taint state, and
// everything a process needs from the layer above are injected.
package host

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

// Environment is everything one process needs that only the layer above can
// know. All four answer the same question — given this process's credential,
// what is its X — so they are one collaborator rather than four hooks.
type Environment[K any] interface {
	// Drivers supplies everything below the task layer: progress reporting and
	// the application's own capability drivers, together with the grant table
	// those drivers were built from. The table travels with the chain because the
	// flow monitor — which sits far above it, on the other side of the journal —
	// judges each call against the very index that routes it.
	Drivers(ctx context.Context, cred K) (sys.Dispatcher[K], *capability.Table, error)
	// ProcessJournal is the process's live journal, which the tape reads and
	// writes through.
	ProcessJournal(ctx context.Context, cred K) (journaled.Journal, error)
	// Header is the journal writer identity for this process revision: the
	// syscall ABI, the program it is bound to, and the process.
	Header(cred K) journaled.Header
	// TaskScope is the credential in the task store's scope shape.
	TaskScope(cred K) durable.TaskScope
}

// Config wires a Factory. Environment, Taints, Tasks and TaskSecret are
// required; everything else has a default or is a hook.
type Config[ID comparable, K capcompute.PID[ID]] struct {
	// Environment is the application half of this seam.
	Environment Environment[K]
	// Taints is the shared cross-process taint state — one for all processes,
	// since flow policy is about what has crossed between them.
	Taints *monitor.Taints[ID]
	// Tasks is the durable approval store, and TaskSecret stamps the tokens
	// that authorise resolving one.
	Tasks      durable.TaskStore
	TaskSecret []byte
	TaskTTL    time.Duration

	// Wrap stacks the runtime's protocol layers above the task layer and below
	// the savepoint markers — the agent lifecycle, whose input payload
	// advertises the whole capability surface beneath it. Nil adds no layer.
	Wrap func(K, sys.Dispatcher[K], *capability.Table) (sys.Dispatcher[K], error)
	// OpenIntents overrides the replay open-intent policy — what to do with an
	// effect journaled without a recorded completion, met on crash-resume. Nil
	// retries every open intent.
	OpenIntents replay.OpenIntentPolicy
	// Now and Rand feed the journaled world sources (sys.now / sys.random);
	// nil defaults to the real clock and crypto/rand.
	Now  func() time.Time
	Rand io.Reader
}

// Factory builds one process's complete dispatcher chain. The resulting chain,
// innermost first:
//
//	Drivers ← task ← Wrap ← world ← savepoints ← [Stack: Flow.Stamp/Declassifier ← replay ← Flow.Guard ← Validator]
type Factory[ID comparable, K capcompute.PID[ID]] struct {
	config Config[ID, K]
}

// New checks the wiring once, here, so NewDispatcher — which runs on every
// process activation — can trust it and get on with the work.
func New[ID comparable, K capcompute.PID[ID]](config Config[ID, K]) (*Factory[ID, K], error) {
	switch {
	case config.Environment == nil:
		return nil, errors.New("host: Environment is required")
	case config.Taints == nil:
		return nil, errors.New("host: Taints is required (share one across processes)")
	case config.Tasks == nil:
		return nil, errors.New("host: Tasks is required")
	case len(config.TaskSecret) == 0:
		return nil, errors.New("host: TaskSecret is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Rand == nil {
		config.Rand = rand.Reader
	}
	// The factory owns its copy, so a caller mutating the slice afterwards
	// cannot change the tokens this process's tasks are stamped with.
	config.TaskSecret = append([]byte(nil), config.TaskSecret...)
	return &Factory[ID, K]{config: config}, nil
}

func (f *Factory[ID, K]) NewDispatcher(ctx context.Context, cred K) (sys.Dispatcher[K], error) {
	drivers, table, err := f.config.Environment.Drivers(ctx, cred)
	if err != nil {
		return nil, err
	}
	if drivers == nil {
		return nil, errors.New("dispatcher provider returned nil dispatcher")
	}
	journal, err := f.config.Environment.ProcessJournal(ctx, cred)
	if err != nil {
		return nil, err
	}
	// A malformed journal is refused before any record is served to replay
	// rather than replayed as truth: records without a header, positions out of
	// order, or intents and completions that do not alternate mean the store
	// handed back something replay cannot reason about. Replay already walks the
	// whole journal, so this is the same order of work.
	if err := journaled.Verify(journal); err != nil {
		return nil, fmt.Errorf("journal integrity check failed: %w", err)
	}
	tape, err := journaled.NewTape(journal, f.config.Environment.Header(cred))
	if err != nil {
		return nil, err
	}
	var below sys.Dispatcher[K] = &task.Dispatcher[K]{
		Next:        drivers,
		Store:       f.config.Tasks,
		Journal:     journal,
		Scope:       f.config.Environment.TaskScope,
		Now:         f.config.Now,
		TokenSecret: f.config.TaskSecret,
		TaskTTL:     f.config.TaskTTL,
	}
	if f.config.Wrap != nil {
		below, err = f.config.Wrap(cred, below, table)
		if err != nil {
			return nil, err
		}
	}
	// The world sources sit below replay (so their values are journaled and
	// replay verbatim) and above the task and routing layers.
	withWorld, err := newWorldDispatcher[K](below, f.config.Now, f.config.Rand, table)
	if err != nil {
		return nil, err
	}
	// Savepoint markers sit below replay (so they are journaled) and above the
	// task and routing layers (so they never become durable tasks or reach a
	// driver).
	withSavepoints := &savepointDispatcher[K]{next: withWorld}

	// The table is the complete mediation surface: everything this process's
	// chain can serve — the drivers it routes to and the runtime's own protocol
	// syscalls, each declared by the layer that serves it — is granted
	// explicitly; anything else is denied by the Validator before it reaches a
	// handler.
	stack := monitor.Stack[ID, K]{
		Taints:      f.config.Taints,
		OpenIntents: f.config.OpenIntents,
	}
	return stack.ForProcess(tape, table, withSavepoints)
}
