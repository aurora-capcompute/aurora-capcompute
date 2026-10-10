package capability

import "context"

type taintContextKey struct{}

// WithTaint attaches the process's taint — every label it has observed so far —
// to the dispatch context. The flow monitor sets it before it delegates. The
// guest is opaque, so anything the process writes may derive from any of these
// labels.
//
// It lives here rather than in the monitor, so a driver can read it without
// importing the monitor.
func WithTaint(ctx context.Context, labels []string) context.Context {
	return context.WithValue(ctx, taintContextKey{}, labels)
}

// Taint returns the process's taint. A driver that stores guest data (for
// example core.scratch) stores the taint with it, so a later read carries the
// data's provenance again.
func Taint(ctx context.Context) []string {
	labels, _ := ctx.Value(taintContextKey{}).([]string)
	return labels
}
