// Package aurora is the module's public surface: an implementation-neutral
// orchestration runtime on the capcompute processor. It owns session and process
// lifecycle, the intent/completion replay journal over the event log, durable
// approval tasks and timers, retries, scheduling, and execution of
// caller-supplied Wasm programs — all folded from a single append-only event
// log, with no mutable row store.
//
// It owns no capabilities, dispatchers, stores, or channels: programs,
// dispatchers and the event log are injected through Config, and a final
// product is an assembly — a main() composing this runtime with concrete
// stores, capability drivers, and whatever communication channels that product
// speaks. The types here are thin re-exports of the internal/agent runtime.
package aurora

import (
	"context"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

func NewRuntime(ctx context.Context, config Config) (Runtime, error) {
	return agent.NewRuntime(ctx, config)
}

// ValidateManifest checks a manifest as CreateProcess does and returns its
// canonical form, so an assembly can refuse a bad manifest at boot.
func ValidateManifest(spec Manifest, dispatchers DispatcherProvider) (Manifest, error) {
	return manifest.Validate(spec, dispatchers)
}
