// Context handoffs across the dispatcher chain — what a Handler is given beyond
// its arguments. The replay layer hands it the in-flight intent identity; the
// flow monitor hands it the process's accumulated taint.
//
// They live beside Handler rather than beside the layers that set them: a driver
// must be able to read both without importing the journal or the monitor.
package capability

import "context"

type idempotencyKeyContextKey struct{}

// WithIdempotencyKey attaches the intent identity of the in-flight syscall —
// (process, position, call-hash) — to the dispatch context. The replay layer sets
// it before delegating; it is stable across crash-retries of the same intent.
func WithIdempotencyKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, idempotencyKeyContextKey{}, key)
}

// IdempotencyKey returns the intent identity for the in-flight syscall.
// Drivers performing effects should hand it to the effect side (or dedup on
// it) so an at-least-once retry of an open intent does not double-execute.
func IdempotencyKey(ctx context.Context) (string, bool) {
	key, ok := ctx.Value(idempotencyKeyContextKey{}).(string)
	return key, ok
}

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
