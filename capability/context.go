package capability

import (
	"context"
	"maps"
	"slices"
)

// Taint is every label a process has observed, and for each label the calls
// whose results carried it, in the order the process made them. The guest is
// opaque, so anything the process sends may derive from any of these labels.
type Taint map[string][]string

// Labels returns the observed labels, sorted.
func (t Taint) Labels() []string {
	return slices.Sorted(maps.Keys(t))
}

type taintContextKey struct{}

// WithTaint attaches the process's taint to the dispatch context. The flow
// monitor sets it before it delegates.
//
// It lives here rather than in the monitor, so a driver can read it without
// importing the monitor.
func WithTaint(ctx context.Context, taint Taint) context.Context {
	return context.WithValue(ctx, taintContextKey{}, taint)
}

// TaintFrom returns the process's taint. A context without one has observed
// nothing: the chain has no flow monitor. A driver that stores guest data (for
// example core.scratch) stores the labels with it, so a later read carries the
// data's provenance again.
func TaintFrom(ctx context.Context) Taint {
	taint, _ := ctx.Value(taintContextKey{}).(Taint)
	return taint
}
