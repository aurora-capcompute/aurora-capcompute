package monitor

import (
	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Wrap puts the processor's canonical monitor chain around one process's
// layers, its tape and its grant table. The order is the load-bearing part, so
// it lives in code instead of prose:
//
//	Validator → Flow.Guard → [replay] → Flow.Stamp → Declassifier → beneath
//
// Above the replay layer sit the pieces whose decisions must re-derive
// deterministically on every pass and never enter the journal: validation and
// flow denials replay identically from the same grant set and taint. Below
// the replay layer sit the pieces whose outcomes must be journaled exactly
// once and served from the tape thereafter: stamped labels and approved
// declassification crossings. Assembling this by hand and getting one layer on
// the wrong side silently breaks a law; Wrap cannot. That the flow cross-cut
// appears twice is why it is one object with two decorators rather than two
// types: the state they share is the same state, and only the journal
// separates them.
//
// taints is shared across processes; the table is the one the layers beneath
// were built from, so the monitor's view of an operation and the handler's are
// identical.
func Wrap[K comparable](
	taints *Taints[K],
	tape replay.Tape,
	table *capability.Table,
	beneath sys.Dispatcher[K],
) sys.Dispatcher[K] {
	flow := NewFlow(taints, table)
	// Below the replay layer: journaled once, replayed thereafter.
	journaled := replay.NewDispatcher(tape, flow.Stamp(NewDeclassifier(beneath)))
	// Above the replay layer: re-derived on every pass, never journaled.
	return NewValidator(table, flow.Guard(journaled))
}
