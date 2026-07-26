package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/program"
)

// testProgram is a conversational test program as an app hands it over: string
// message in, string answer out. Callers that only care about behavior take this
// as-is; a test probing interface handling edits a field.
func testProgram(id string, wasm []byte) program.Data {
	return program.Data{
		ID:          id,
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
