package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute/sys"
)

// testProgram is a conversational test program as an app hands it over: string
// message in, string answer out. Callers that only care about behavior take this
// as-is; a test probing interface handling edits a field.
func testProgram(id string, wasm []byte) ProgramData {
	return ProgramData{
		ID:          ProgramID(id),
		SourceCode:  wasm,
		Description: "a test program",
		Input:       json.RawMessage(`{"type":"string"}`),
		Output:      json.RawMessage(`{"type":"string"}`),
	}
}

// addTestProgram registers one conversational program on a runtime. The runtime
// boots with none — it reads no filesystem — so every test that runs a process
// adds its program first.
func addTestProgram(t *testing.T, runtime *Runtime, id string, wasm []byte) {
	t.Helper()
	if err := runtime.AddProgram(context.Background(), testProgram(id, wasm)); err != nil {
		t.Fatalf("add program %s: %v", id, err)
	}
}

// A process is bound to the exact program identity it was created from, and the
// registry is the one place that binding is checked on the way to a guest: the
// execute path carries the process's digest all the way down and has no
// pre-flight of its own. A spawn naming an identity the registry no longer holds
// must be refused rather than run under whatever bytes are registered now.
func TestSpawnRefusesAStaleDigest(t *testing.T) {
	wasm := buildProgram(t)
	registry := direct.NewRegistry[ProgramID, ProcessContext](0)
	defer registry.Close(context.Background())

	bound, err := registry.Add(context.Background(), testProgram("program@1", wasm))
	if err != nil {
		t.Fatalf("add program: %v", err)
	}
	// The binding check runs before anything is instantiated, so a dispatcher
	// that refuses is enough to tell "stopped at the binding" from "got past it".
	noDispatcher := errors.New("no dispatcher")
	mkDispatcher := func(context.Context, ProcessContext) (sys.Dispatcher[ProcessContext], error) {
		return nil, noDispatcher
	}

	stale := direct.Digest{ArtifactDigest: "stale", SourceCodeDigest: bound.SourceCodeDigest}
	if _, err := registry.Spawn(
		context.Background(), ProgramID("program@1"), stale, ProcessContext{}, mkDispatcher,
	); !errors.Is(err, errs.Conflict) {
		t.Fatalf("spawn under a stale digest = %v, want a conflict", err)
	}
	if _, err := registry.Spawn(
		context.Background(), ProgramID("program@1"), bound, ProcessContext{}, mkDispatcher,
	); !errors.Is(err, noDispatcher) {
		t.Fatalf("spawn under the bound digest = %v, want it past the binding check", err)
	}
}
