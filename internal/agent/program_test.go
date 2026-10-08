package agent

import (
	"encoding/json"
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
