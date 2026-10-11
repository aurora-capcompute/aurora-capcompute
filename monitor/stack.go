// Package monitor is the reference monitor around one process's dispatcher
// chain: the Validator (is the call granted, are its arguments well formed) and
// the flow monitor (which labels the run has observed, and from which calls).
package monitor

import (
	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Wrap builds the monitor chain around one process's layers:
//
//	Validator → Flow.Track → [replay] → Flow.Stamp → beneath
//
// The order is the point. Above the replay layer is what is derived again on
// every pass and never journaled: validation, and the taint that results fold
// into. Below it are the outcomes that are journaled once and replayed after
// that: the stamped labels and everything beneath, including the approval a
// tainted call waits for.
//
// taints is shared by every process. table is the one the layers beneath were
// built from, so the monitor and the handlers see the same operations.
func Wrap[K comparable](
	taints *Taints[K],
	tape replay.Tape,
	table *capability.Table,
	beneath sys.Dispatcher[K],
) sys.Dispatcher[K] {
	flow := NewFlow(taints, table)
	// Below the replay layer: journaled once, replayed thereafter.
	journaled := replay.NewDispatcher(tape, flow.Stamp(beneath))
	// Above the replay layer: re-derived on every pass, never journaled.
	return NewValidator(table, flow.Track(journaled))
}
