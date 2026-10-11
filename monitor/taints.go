package monitor

import (
	"slices"
	"sync"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
)

// Taints is every label each process revision has observed, with the calls that
// produced it. One Taints serves all of a host's processes, while a Flow is
// built per process. Nothing removes a label from a live process.
type Taints[K comparable] struct {
	mu       sync.Mutex
	observed map[K]capability.Taint
}

// NewTaints keys taint by the credential itself: one credential names one
// process revision.
func NewTaints[K comparable]() *Taints[K] {
	return &Taints[K]{observed: make(map[K]capability.Taint)}
}

// ForgetProcess releases a terminated process's taint state.
func (t *Taints[K]) ForgetProcess(pid K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.observed, pid)
}

// observe adds labels to a process's taint, each with the call that produced it.
func (t *Taints[K]) observe(pid K, labels []string, source string) {
	if len(labels) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	if taint == nil {
		taint = make(capability.Taint)
		t.observed[pid] = taint
	}
	for _, label := range labels {
		if !slices.Contains(taint[label], source) {
			taint[label] = append(taint[label], source)
		}
	}
}

// taint returns a copy of a process's taint, safe to hand to the calls below.
func (t *Taints[K]) taint(pid K) capability.Taint {
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := make(capability.Taint, len(t.observed[pid]))
	for label, sources := range t.observed[pid] {
		taint[label] = slices.Clone(sources)
	}
	return taint
}

// Snapshot returns a process's labels, sorted, so a caller can carry them
// elsewhere (for example onto the session history a later run reads).
func (t *Taints[K]) Snapshot(pid K) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.observed[pid].Labels()
}
