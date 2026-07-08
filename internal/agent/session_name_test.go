package agent

import (
	"context"
	"testing"
	"time"
)

func bootSessionRuntime(t *testing.T, store *runtimeStore) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers:  &runtimeDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("boot runtime: %v", err)
	}
	return runtime
}

// A session's explicit name is its handle: unique per tenant, renamable, and an
// empty name is always allowed (the id is then the handle, and unnamed sessions
// coexist).
func TestSessionNameCreateRenameUniqueness(t *testing.T) {
	runtime := bootSessionRuntime(t, newRuntimeStore())
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	alpha, err := runtime.CreateSession("alpha", nil)
	if err != nil || alpha.Name != "alpha" {
		t.Fatalf("create alpha = %+v, %v", alpha, err)
	}
	if _, err := runtime.CreateSession("alpha", nil); err == nil {
		t.Fatal("a duplicate name must be rejected")
	}
	// Renaming frees the old name.
	if renamed, err := runtime.RenameSession(alpha.ID, "beta"); err != nil || renamed.Name != "beta" {
		t.Fatalf("rename = %+v, %v", renamed, err)
	}
	if _, err := runtime.CreateSession("alpha", nil); err != nil {
		t.Fatalf("alpha should be free after the rename: %v", err)
	}
	// Unnamed sessions coexist — "" is never a collision.
	if a, err := runtime.CreateSession("", nil); err != nil || a.Name != "" {
		t.Fatalf("unnamed = %+v, %v", a, err)
	}
	if _, err := runtime.CreateSession("", nil); err != nil {
		t.Fatalf("a second unnamed session must be allowed: %v", err)
	}
}

// A named session persists as a session.state event, so its name — and the last
// rename — survive a restart even though it never ran a process.
func TestSessionNamePersistsAcrossRestart(t *testing.T) {
	store := newRuntimeStore()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first := bootSessionRuntime(t, store)
	created, err := first.CreateSession("myproj", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := first.RenameSession(created.ID, "renamed"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	second := bootSessionRuntime(t, store)
	t.Cleanup(func() { _ = second.Close(context.Background()) })
	restored, err := second.GetSession(created.ID)
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if restored.Name != "renamed" {
		t.Fatalf("restored name = %q, want the last rename to survive", restored.Name)
	}
	// A process-less session has no derived title, but must round-trip to the
	// same placeholder the live runtime assigns at creation — not an empty string.
	if restored.Title != defaultSessionTitle {
		t.Fatalf("restored title = %q, want %q to survive restart", restored.Title, defaultSessionTitle)
	}
}
