// Package aurora is the module's public surface: an implementation-neutral
// orchestration runtime on the capcompute processor. It owns session and process
// lifecycle, the intent/completion replay journal over the event log, durable
// approval tasks, retries, delegation, scheduling, event subscriptions, and
// execution of caller-supplied Wasm programs — all folded from a single
// append-only event log, with no mutable row store.
//
// It owns no capabilities, dispatchers, stores, or channels: programs,
// dispatchers, the event log, leases, and the processor's process table are
// injected through Config, and a final product is an assembly — a main()
// composing this runtime with concrete stores, capability drivers, and
// whatever communication channels that product speaks. None of those live
// here. The types here are thin re-exports of the internal/agent runtime.
package aurora

import (
	"context"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent"
)

func NewRuntime(ctx context.Context, config Config) (Runtime, error) {
	return agent.NewRuntime(ctx, config)
}

func ValidateManifest(m Manifest, provider DispatcherProvider) (Manifest, error) {
	return agent.ValidateManifest(m, provider)
}
