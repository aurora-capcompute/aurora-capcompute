package agent

// The runtime's two halves of the run queue's seam, tested without a guest.
// Everything here stops short of instantiating wasm, so these run even where the
// Rust toolchain and the program sources are unavailable — which is most places,
// and which is why the paths below used to go unexercised entirely.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/process"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
)

// seamRuntime is a runtime with no programs registered: enough to exercise
// activation's lookup, which fails at the program binding rather than at wasm.
func seamRuntime(t *testing.T) *Runtime {
	t.Helper()
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: &runtimeDispatchers{},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("seam-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	return runtime
}

// A refused spawn still delivers an outcome on the handle rather than stranding
// the caller: with no program registered, the registry refuses, and that refusal
// has to come back as a failed quantum.
func TestSpawnRefusalReachesTheCaller(t *testing.T) {
	runtime := seamRuntime(t)

	cred := ProcessContext{
		TenantID:  DefaultTenantID,
		SessionID: "s1",
		ProcessID: "p1",
		Revision:  1,
	}
	handle, err := runtime.scheduler.Spawn(
		ProgramID("unloaded@1"), cred.Digest, cred, 0, runtime.factory.NewDispatcher)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	select {
	case result := <-handle.Result():
		if result.Status != process.Failed {
			t.Fatalf("status = %s, want failed", result.Status)
		}
		if !errors.Is(result.Error, errs.NotFound) {
			t.Fatalf("err = %v, want the registry's refusal", result.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no result delivered")
	}
}
