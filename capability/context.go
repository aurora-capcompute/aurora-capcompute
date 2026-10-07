// Context handoff across the dispatcher chain — what a Handler is given beyond
// its arguments: the flow monitor hands it the process's accumulated taint.
//
// It lives beside Handler rather than beside the monitor that sets it: a driver
// must be able to read it without importing the monitor.
package capability

import "context"

type taintContextKey struct{}

// WithTaint attaches the process's accumulated taint — every label it has
// observed so far — to the dispatch context. The flow monitor sets it before
// delegating; because the guest is opaque, anything the process emits (including
// a value it stores) may derive from any of these labels.
func WithTaint(ctx context.Context, labels []string) context.Context {
	return context.WithValue(ctx, taintContextKey{}, labels)
}

// Taint returns the process's accumulated taint. Drivers that *store* guest-
// derived data (e.g. core.scratch) persist it with the value, so a later read
// restamps the data's provenance instead of laundering it.
func Taint(ctx context.Context) []string {
	labels, _ := ctx.Value(taintContextKey{}).([]string)
	return labels
}
