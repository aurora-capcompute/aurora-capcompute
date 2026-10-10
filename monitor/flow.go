package monitor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Flow is the information-flow monitor. It reads two things, neither of them
// durable: the labels each process has observed (its taint, rebuilt by replay
// on resume) and what each operation permits (the grant table).
//
// The guest is opaque, so flow is judged conservatively: every label a process
// observes taints everything it emits later.
//
// It has two decorators, on the two sides of the replay layer. Guard sits above:
// a denial is derived again on every pass and never journaled. Stamp sits
// below: some labels come from the handlers themselves (which credential an
// internet fetch used, what a session's earlier runs read), so they cannot be
// derived again and are journaled with the result.
type Flow[K comparable] struct {
	taints *Taints[K]
	table  *capability.Table
}

// NewFlow binds the shared taint state to one process's grant table.
func NewFlow[K comparable](taints *Taints[K], table *capability.Table) *Flow[K] {
	return &Flow[K]{taints: taints, table: table}
}

// Guard refuses a syscall whose operation forbids a label this run has already
// observed, before any handler runs. It belongs above the replay layer.
func (f *Flow[K]) Guard(next sys.Dispatcher[K]) sys.Dispatcher[K] {
	return &flowGuard[K]{flow: f, next: next}
}

// Stamp records the source classes an operation's results carry, and folds
// every observed label into the run's taint. It belongs below the replay layer.
func (f *Flow[K]) Stamp(next sys.Dispatcher[K]) sys.Dispatcher[K] {
	return &flowStamp[K]{flow: f, next: next}
}

type flowGuard[K comparable] struct {
	flow *Flow[K]
	next sys.Dispatcher[K]
}

// Dispatch refuses a call whose operation forbids a label the run holds, then
// folds the result's labels into the run's taint.
func (g *flowGuard[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit:
		return g.next.Dispatch(ctx, cred, syscall, auth)
	}

	forbid, sink := g.flow.table.Forbidden(syscall)
	if tainted := g.flow.taints.intersection(cred, forbid); len(tainted) > 0 {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
			"flow policy: this run has observed %v, which may not flow into %q", tainted, sink)), nil
	}

	// Hand the run's taint downstream: handlers that store guest-derived data
	// persist it with the value, so provenance survives into later sessions
	// instead of being laundered.
	result, err := g.next.Dispatch(capability.WithTaint(ctx, g.flow.taints.Snapshot(cred)), cred, syscall, auth)
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
		g.flow.taints.Declassify(cred, crossed.Declassified...)
		return result, nil
	}
	g.flow.taints.observe(cred, result.Labels())
	return result, nil
}

type flowStamp[K comparable] struct {
	flow *Flow[K]
	next sys.Dispatcher[K]
}

// Dispatch stamps a result with its provenance: the syscall that produced it,
// and the source classes its operation declares.
func (s *flowStamp[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	result, err := s.next.Dispatch(ctx, cred, syscall, auth)
	if err != nil {
		return result, err
	}
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit, sys.SyscallDeclassify:
		return result, nil // control syscalls carry no data provenance
	}
	labels := append([]string{capability.SyscallLabelPrefix + syscall.Name}, s.flow.table.Labels(syscall)...)
	return result.WithLabels(labels...), nil
}
