package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Taints is the cross-process taint state: every label each process has
// observed. It is shared by all of a host's per-process monitor chains (Stack
// holds one), while the FlowMonitor decorator that consumes it is wired per
// process — state and wiring have different lifetimes, so they are different
// types.
type Taints[ID comparable] struct {
	mu       sync.Mutex
	observed map[ID]map[string]struct{}
}

func NewTaints[ID comparable]() *Taints[ID] {
	return &Taints[ID]{observed: make(map[ID]map[string]struct{})}
}

// Declassify removes labels from a process's accumulated taint — an explicit,
// governed crossing of a label boundary (DIFC declassification). Guests reach
// it through the sys.declassify syscall (the Declassifier decorator), whose
// approved result replays through the FlowMonitor and lands here; the direct
// method remains for host-side administrative use.
func (t *Taints[ID]) Declassify(pid ID, labels ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	for _, label := range labels {
		delete(taint, label)
	}
}

// ForgetProcess releases a terminated process's taint state.
func (t *Taints[ID]) ForgetProcess(pid ID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.observed, pid)
}

func (t *Taints[ID]) observe(pid ID, labels []string) {
	if len(labels) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	if taint == nil {
		taint = make(map[string]struct{})
		t.observed[pid] = taint
	}
	for _, label := range labels {
		taint[label] = struct{}{}
	}
}

func (t *Taints[ID]) intersection(pid ID, forbid []string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	var tainted []string
	for _, label := range forbid {
		if _, ok := taint[label]; ok {
			tainted = append(tainted, label)
		}
	}
	sort.Strings(tainted)
	return tainted
}

// Snapshot returns the labels a process has accumulated — its current taint — so
// a caller can carry that provenance elsewhere (e.g. onto session history a later
// run will observe, keeping the flow policy intact across that boundary).
func (t *Taints[ID]) Snapshot(pid ID) []string { return t.snapshot(pid) }

func (t *Taints[ID]) snapshot(pid ID) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	labels := make([]string, 0, len(taint))
	for label := range taint {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

// DeclassifyRequest is the args payload of the reserved sys.declassify
// syscall: which labels to lift from the run's taint, and why — the reason is
// required because it is what the approving human reads and what the journal
// preserves.
type DeclassifyRequest struct {
	Labels []string `json:"labels"`
	Reason string   `json:"reason"`
}

// DeclassifyResult is the journaled outcome of an approved declassification.
type DeclassifyResult struct {
	Declassified []string `json:"declassified"`
}

var declassifyInputSchema = json.RawMessage(`{
	"type": "object",
	"required": ["labels", "reason"],
	"properties": {
		"labels": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
		"reason": {"type": "string", "minLength": 1}
	},
	"additionalProperties": false
}`)

// Declassifier serves the reserved sys.declassify syscall — DIFC
// declassification as a governed operation. Every crossing requires a human
// approval (there is no unapproved path: an unattended declassify would just
// be flow-policy bypass), and the approved crossing is a journaled syscall
// result, so replay re-applies it without asking again. It must sit *below*
// the replay layer; the FlowMonitor above performs the actual taint removal
// when the result passes through it.
type Declassifier[K any] struct {
	next sys.Dispatcher[K]
}

func NewDeclassifier[K any](next sys.Dispatcher[K]) *Declassifier[K] {
	return &Declassifier[K]{next: next}
}

func (d *Declassifier[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != sys.SyscallDeclassify {
		return d.next.Dispatch(ctx, cred, syscall, auth)
	}
	var request DeclassifyRequest
	if err := json.Unmarshal(syscall.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode declassify args: %v", err)), nil
	}
	if len(request.Labels) == 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "declassify: labels are required"), nil
	}
	if strings.TrimSpace(request.Reason) == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "declassify: a reason is required"), nil
	}
	if auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve declassifying %v: %s", request.Labels, request.Reason)), nil
	}

	crossed := append([]string(nil), request.Labels...)
	sort.Strings(crossed)
	result, err := json.Marshal(DeclassifyResult{Declassified: crossed})
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(result), nil
}

// Capabilities publishes sys.declassify (schema'd) alongside the chain's own
// capabilities; whether a given run may call it is the manifest's decision,
// enforced by the Validator's grant set like any capability.
func (d *Declassifier[K]) Capabilities() []sys.Capability {
	return append(d.next.Capabilities(), sys.Capability{
		Name:        sys.SyscallDeclassify,
		Description: "lift labels from this run's taint after human approval; the crossing is journaled with its reason",
		InputSchema: declassifyInputSchema,
	})
}
