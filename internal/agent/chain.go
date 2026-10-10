package agent

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// newDispatcher builds one process's dispatcher chain for one quantum. A call
// passes the layers outermost first:
//
//	Validator     is the call granted, do its arguments match the schema
//	Flow.Guard    may the run's taint flow into this call
//	replay        serve a recorded result, or journal the call and run it
//	Flow.Stamp    label the result with its provenance
//	savepoint     sys.begin, sys.commit                 (savepoint.go)
//	world         sys.now, sys.random                   (world.go)
//	lifecycle     sys.input, sys.output, sys.abort      (lifecycle.go)
//	task          turn a yield from below into a durable task
//	Declassifier  sys.declassify
//	progress      sys.log                               (progress.go)
//	timer         sys.timer                             (timer.go)
//	drivers       the manifest's capabilities
//
// Everything below replay is journaled. The task layer sits below the protocol
// layers, so the intent at the journal's tail is the call that yielded.
//
// The code builds the chain from the bottom up. Each layer admits the syscalls
// it serves into the process's table as it is built, so the table the Validator
// enforces names exactly what the chain serves.
func (r *Runtime) newDispatcher(ctx context.Context, cred durable.ProcessContext, program compiledProgram) (sys.Dispatcher[durable.ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	spec := proc.manifest.Clone()
	input := proc.input
	// A manifest with history:false sees only its own input.
	var history []HistoryMessage
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
	var chain sys.Dispatcher[durable.ProcessContext] = capability.NewDispatcher[durable.ProcessContext](table)
	// Every process gets sys.timer. A grant only tunes it.
	timerGrant, ok := spec.FindSyscall(manifest.TimerSyscall)
	if !ok {
		timerGrant = manifest.Syscall{Syscall: manifest.TimerSyscall}
	}
	if chain, err = newTimerDispatcher(chain, timerGrant, table); err != nil {
		return nil, err
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

	// Replay trusts the journal's structure, so a damaged journal is refused
	// before any record is served.
	if err := journaled.Verify(journal); err != nil {
		return nil, fmt.Errorf("journal integrity check failed: %w", err)
	}
	return monitor.Wrap(r.taints, journaled.NewTape(journal), table, chain), nil
}

// reconcileGrants refuses a table in which the dispatcher provider serves a
// capability the manifest did not grant. The Validator enforces the table, so a
// provider that served more would widen the process's authority past its
// manifest. Serving less is no leak: the guest just cannot call it.
//
// It runs before the runtime's own layers admit their syscalls, so it checks
// the provider's capabilities only.
func reconcileGrants(advertised []capability.Descriptor, manifest manifest.Manifest) error {
	granted := make(map[string]struct{}, len(manifest.Syscalls))
	for _, leaf := range manifest.LeafSyscalls() {
		granted[leaf.Syscall] = struct{}{}
	}
	var leaked []string
	for _, capability := range advertised {
		if _, ok := granted[capability.Name]; !ok {
			leaked = append(leaked, capability.Name)
		}
	}
	if len(leaked) > 0 {
		slices.Sort(leaked)
		return fmt.Errorf("%w: dispatcher provider advertises capabilities the manifest did not grant: %s",
			errs.Invalid, strings.Join(leaked, ", "))
	}
	return nil
}
