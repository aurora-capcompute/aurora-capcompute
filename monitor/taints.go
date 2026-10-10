package monitor

import (
	"maps"
	"slices"
	"sync"
)

// Taints is every label each process revision has observed. One Taints serves
// all of a host's processes, while a Flow is built per process.
type Taints[K comparable] struct {
	mu       sync.Mutex
	observed map[K]map[string]struct{}
}

// NewTaints keys taint by the credential itself: one credential names one
// process revision.
func NewTaints[K comparable]() *Taints[K] {
	return &Taints[K]{observed: make(map[K]map[string]struct{})}
}

// Declassify removes labels from a process's taint. A guest reaches it through
// an approved sys.declassify: Flow.Guard calls it when the result passes.
func (t *Taints[K]) Declassify(pid K, labels ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	for _, label := range labels {
		delete(taint, label)
	}
}

// ForgetProcess releases a terminated process's taint state.
func (t *Taints[K]) ForgetProcess(pid K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.observed, pid)
}

// observe adds labels to a process's taint.
func (t *Taints[K]) observe(pid K, labels []string) {
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

// intersection is the labels of forbid that the process holds, sorted.
func (t *Taints[K]) intersection(pid K, forbid []string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	taint := t.observed[pid]
	var tainted []string
	for _, label := range forbid {
		if _, ok := taint[label]; ok {
			tainted = append(tainted, label)
		}
	}
	slices.Sort(tainted)
	return tainted
}

// Snapshot returns a process's taint, sorted, so a caller can carry it
// elsewhere (for example onto the session history a later run reads).
func (t *Taints[K]) Snapshot(pid K) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Sorted(maps.Keys(t.observed[pid]))
}
