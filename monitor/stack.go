package monitor

import (
	"errors"

	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Stack wires the kernel's canonical dispatcher chain. The order is the
// load-bearing part, so it lives in code instead of prose:
//
//	Validator → FlowMonitor → [replay] → Labeler → Declassifier → drivers
//
// Above the replay layer sit the pieces whose decisions must re-derive
// deterministically on every pass and never enter the journal: validation and
// flow denials replay identically from the same grant set and taint. Below
// the replay layer sit the pieces whose outcomes must be journaled exactly
// once and served from the tape thereafter: stamped labels and approved
// declassification crossings — which also need the tape's idempotency keys.
// Assembling this by hand and getting one layer on the wrong side silently
// breaks a kernel law; ForProcess cannot.
//
// The Stack holds the chain's cross-process components (grant source, taint
// state); ForProcess completes it with the one per-process piece — the tape —
// and the process's drivers.
type Stack[ID comparable, K capcompute.PID[ID]] struct {
	// Grants is the manifest seam: the capability set granted to a cred.
	// Required — a stack without a grant source is not a reference monitor.
	Grants GrantSource[K]
	// Taints is the shared cross-process taint state. Required — flow policy
	// is not optional in the canonical chain; grant nothing with Forbid sets
	// and it is inert.
	Taints *Taints[ID]
	// OpenIntents overrides the open-intent policy (default: retry under the
	// original idempotency key).
	OpenIntents replay.OpenIntentPolicy
}

// ForProcess assembles the chain for one process around its tape and drivers.
func (s Stack[ID, K]) ForProcess(tape replay.Tape, drivers sys.Dispatcher[K]) (sys.Dispatcher[K], error) {
	if s.Grants == nil {
		return nil, errors.New("stack: Grants is required")
	}
	if s.Taints == nil {
		return nil, errors.New("stack: Taints is required (share one across processes)")
	}
	if drivers == nil {
		return nil, errors.New("stack: drivers are required")
	}

	// Below the replay layer: journaled once, replayed thereafter.
	below := NewLabeler[K](NewDeclassifier[K](drivers))

	journaled := replay.NewDispatcher(tape, below)
	if s.OpenIntents != nil {
		journaled.WithOpenIntentPolicy(s.OpenIntents)
	}

	// Above the replay layer: re-derived on every pass, never journaled.
	return NewValidator(s.Grants, NewFlowMonitor(s.Taints, journaled)), nil
}
