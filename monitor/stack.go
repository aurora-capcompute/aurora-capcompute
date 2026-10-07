package monitor

import (
	"errors"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Stack wires the processor's canonical dispatcher chain. The order is the
// load-bearing part, so it lives in code instead of prose:
//
//	Validator → Flow.Guard → [replay] → Flow.Stamp → Declassifier → drivers
//
// Above the replay layer sit the pieces whose decisions must re-derive
// deterministically on every pass and never enter the journal: validation and
// flow denials replay identically from the same grant set and taint. Below
// the replay layer sit the pieces whose outcomes must be journaled exactly
// once and served from the tape thereafter: stamped labels and approved
// declassification crossings.
// Assembling this by hand and getting one layer on the wrong side silently
// breaks a law; ForProcess cannot. That the flow cross-cut appears twice is why
// it is one object with two decorators rather than two types: the state they
// share is the same state, and only the journal separates them.
//
// The Stack holds the chain's cross-process components (grant source, taint
// state); ForProcess completes it with the two per-process pieces — the tape
// and the process's grant table — and the drivers built from that table.
type Stack[ID comparable, K capcompute.PID[ID]] struct {
	// Taints is the shared cross-process taint state. Required — flow policy
	// is not optional in the canonical chain; grant nothing with Forbid sets
	// and it is inert.
	Taints *Taints[ID]
	// OpenIntents overrides the open-intent policy (default: retry).
	OpenIntents replay.OpenIntentPolicy
}

// ForProcess assembles the chain for one process around its tape, its grant
// table and the drivers that serve it. The table is what the flow layer reads
// its policy from; passing the same one the drivers were built from is what
// keeps the monitor's view of an operation and the handler's identical.
func (s Stack[ID, K]) ForProcess(tape replay.Tape, table *capability.Table, drivers sys.Dispatcher[K]) (sys.Dispatcher[K], error) {
	if table == nil {
		return nil, errors.New("stack: the grant table is required")
	}
	if s.Taints == nil {
		return nil, errors.New("stack: Taints is required (share one across processes)")
	}
	if drivers == nil {
		return nil, errors.New("stack: drivers are required")
	}

	flow := NewFlow[ID, K](s.Taints, table)

	// Below the replay layer: journaled once, replayed thereafter.
	below := flow.Stamp(NewDeclassifier[K](drivers))

	journaled := replay.NewDispatcher(tape, below)
	if s.OpenIntents != nil {
		journaled.WithOpenIntentPolicy(s.OpenIntents)
	}

	// Above the replay layer: re-derived on every pass, never journaled.
	return NewValidator(table, flow.Guard(journaled)), nil
}
