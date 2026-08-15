package monitor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Flow is the information-flow cross-cut (the CaMeL reference monitor as a
// runtime primitive). It owns exactly two pieces of state, neither durable:
//
//   - which labels each process has observed — the taint, rebuilt by replaying
//     the journal on resume, never persisted in its own right;
//   - what each operation permits — read from the process's grant table, which
//     is rebuilt from the manifest at wiring time.
//
// The guest is opaque, so flow is judged conservatively: every label a process
// observes taints everything it later emits.
//
// One concern, two decorators, and the split is the replay boundary rather than
// a design choice. Guard must sit above the tape: a denial is a decision that
// has to re-derive identically on every pass, so it is never journaled. Stamp
// must sit below it: labels are partly produced by the handlers themselves — an
// internet fetch labels by which credential matched, a session's input by what
// its predecessors read — so they cannot be re-derived from the index and must
// be journaled with the completion record. Getting either on the wrong side
// silently breaks a law, which is why Stack assembles them and callers do not.
type Flow[ID comparable, K capcompute.PID[ID]] struct {
	taints *Taints[ID]
	table  *capability.Table
}

// NewFlow binds the shared taint state to one process's grant table. A nil
// table means no operation declares any policy — the flow rules are then inert,
// not absent: taint still accumulates and still crosses into later runs.
func NewFlow[ID comparable, K capcompute.PID[ID]](taints *Taints[ID], table *capability.Table) *Flow[ID, K] {
	return &Flow[ID, K]{taints: taints, table: table}
}

// Guard refuses a syscall whose operation forbids a label this run has already
// observed, before any handler runs. It belongs above the replay layer.
func (f *Flow[ID, K]) Guard(next sys.Dispatcher[K]) sys.Dispatcher[K] {
	return &flowGuard[ID, K]{flow: f, next: next}
}

// Stamp records the source classes an operation's results carry, and folds
// every observed label into the run's taint. It belongs below the replay layer.
func (f *Flow[ID, K]) Stamp(next sys.Dispatcher[K]) sys.Dispatcher[K] {
	return &flowStamp[ID, K]{flow: f, next: next}
}

// forbidden reports the labels this call may not carry and the name to blame.
func (f *Flow[ID, K]) forbidden(call sys.Syscall) ([]string, string) {
	if f.table == nil {
		return nil, call.Name
	}
	return f.table.Forbidden(call)
}

func (f *Flow[ID, K]) labels(call sys.Syscall) []string {
	if f.table == nil {
		return nil
	}
	return f.table.Labels(call)
}

type flowGuard[ID comparable, K capcompute.PID[ID]] struct {
	flow *Flow[ID, K]
	next sys.Dispatcher[K]
}

func (g *flowGuard[ID, K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit:
		return g.next.Dispatch(ctx, cred, syscall, auth)
	}

	pid := cred.PID()
	forbid, sink := g.flow.forbidden(syscall)
	if tainted := g.flow.taints.intersection(pid, forbid); len(tainted) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into %q", tainted, sink)), nil
	}

	// Hand the run's taint downstream: handlers that store guest-derived data
	// persist it with the value, so provenance survives into later sessions
	// instead of being laundered.
	result, err := g.next.Dispatch(sys.WithTaint(ctx, g.flow.taints.snapshot(pid)), cred, syscall, auth)
	if err != nil {
		return result, err
	}
	if syscall.Name == sys.SyscallDeclassify && result.Status() == sys.StatusResult {
		// The approved, journaled crossing — fresh or replayed — lifts the
		// labels instead of accumulating them.
		var crossed DeclassifyResult
		if err := json.Unmarshal(result.Result(), &crossed); err != nil {
			return sys.SyscallResult{}, fmt.Errorf("decode declassify result: %w", err)
		}
		g.flow.taints.Declassify(pid, crossed.Declassified...)
		return result, nil
	}
	g.flow.taints.observe(pid, result.Labels())
	return result, nil
}

type flowStamp[ID comparable, K capcompute.PID[ID]] struct {
	flow *Flow[ID, K]
	next sys.Dispatcher[K]
}

func (s *flowStamp[ID, K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	result, err := s.next.Dispatch(ctx, cred, syscall, auth)
	if err != nil {
		return result, err
	}
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit, sys.SyscallDeclassify:
		return result, nil // control syscalls carry no data provenance
	}
	// The deriving syscall, plus the source classes the resolved operation
	// declares: a filesystem read over a secrets root labels differently from a
	// list of the same root.
	labels := append([]string{sys.SyscallLabelPrefix + syscall.Name}, s.flow.labels(syscall)...)
	return result.WithLabels(labels...), nil
}
