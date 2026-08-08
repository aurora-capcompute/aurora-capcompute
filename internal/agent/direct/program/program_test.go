package program

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
)

// testProgram is a conversational test program as an app hands it over: string
// message in, string answer out. A test probing interface handling edits a field.
func testProgram(id string, wasm []byte) Data {
	return Data{
		ID:          id,
		SourceCode:  wasm,
		Description: "a test program",
		Input:       json.RawMessage(`{"type":"string"}`),
		Output:      json.RawMessage(`{"type":"string"}`),
	}
}

// Preparing a program pins the content digest and compiles the declared
// interface — no wasm execution, so fake bytes suffice. The prepared artifact
// carries no bytes: those become the compiled image.
func TestLoadProgramPreparesInterfaceAndPinsDigest(t *testing.T) {
	data := testProgram("program@1", []byte("wasm-bytes"))
	artifact, err := Load(data)
	if err != nil {
		t.Fatalf("load program: %v", err)
	}
	if artifact.Digest != identity(data.SourceCode, artifact.Input, artifact.Output) {
		t.Fatalf("digest = %q, want the (wasm, schemas) identity", artifact.Digest)
	}
	if artifact.Description != "a test program" || artifact.Input.compiled == nil || artifact.Output.compiled == nil {
		t.Fatalf("interface not prepared: %+v", artifact)
	}
	if !bytes.Equal(artifact.Input.Document, json.RawMessage(`{"type":"string"}`)) {
		t.Fatalf("input document = %s", artifact.Input.Document)
	}
	if artifact.Image() != nil {
		t.Fatal("Load must not attach an image: compiling the wasm is the caller's")
	}
}

// TestProgramIdentityCoversCodeAndSchemas: identity covers the bytes and both
// declared schemas, so changing either is a program change — the seam the
// immutability law binds to.
func TestProgramIdentityCoversCodeAndSchemas(t *testing.T) {
	digest := func(data Data) string {
		t.Helper()
		artifact, err := Load(data)
		if err != nil {
			t.Fatalf("load %+v: %v", data, err)
		}
		return artifact.Digest
	}
	base := testProgram("program@1", []byte("same-bytes"))

	otherCode := base
	otherCode.SourceCode = []byte("other-bytes")
	if digest(base) == digest(otherCode) {
		t.Fatal("different wasm must yield a different identity")
	}

	otherInput := base
	otherInput.Input = json.RawMessage(`{"type":"object"}`)
	if digest(base) == digest(otherInput) {
		t.Fatal("a changed input schema must yield a different identity")
	}

	otherOutput := base
	otherOutput.Output = json.RawMessage(`{"type":"object"}`)
	if digest(base) == digest(otherOutput) {
		t.Fatal("a changed output schema must yield a different identity")
	}

	if digest(base) != digest(testProgram("program@1", []byte("same-bytes"))) {
		t.Fatal("identity must be stable for the same bytes and schemas")
	}
}

// TestProgramIdentityIgnoresDescription: the description says what a program is
// for, not what it accepts or returns, so rewording it is not a contract change
// and must not strand the program's processes.
func TestProgramIdentityIgnoresDescription(t *testing.T) {
	base, err := Load(testProgram("program@1", []byte("same-bytes")))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	data := testProgram("program@1", []byte("same-bytes"))
	data.Description = "the very same program, described afresh"
	reworded, err := Load(data)
	if err != nil {
		t.Fatalf("load reworded: %v", err)
	}
	if base.Digest != reworded.Digest {
		t.Fatal("rewording the description changed the identity")
	}
}

// TestProgramIdentityIgnoresManifestFormatting: identity is computed over the
// normalized schemas, so reindenting the manifest a program shipped in is not a
// program change.
func TestProgramIdentityIgnoresManifestFormatting(t *testing.T) {
	compact := testProgram("program@1", []byte("same-bytes"))
	compact.Output = json.RawMessage(`{"type":"object","properties":{"answer":{"type":"string"}}}`)

	pretty := compact
	pretty.Description = "  a test program\n"
	pretty.Input = json.RawMessage("{\n\t\"type\": \"string\"\n}")
	pretty.Output = json.RawMessage("{\n  \"type\": \"object\",\n  \"properties\": {\n    \"answer\": { \"type\": \"string\" }\n  }\n}")

	normalizedCompact, err := Load(compact)
	if err != nil {
		t.Fatalf("load compact: %v", err)
	}
	normalizedPretty, err := Load(pretty)
	if err != nil {
		t.Fatalf("load pretty: %v", err)
	}
	if normalizedPretty.Digest != normalizedCompact.Digest {
		t.Fatalf("reformatting the manifest changed identity: %q != %q", normalizedPretty.Digest, normalizedCompact.Digest)
	}
}

// A program must carry an id, bytes, and a well-formed interface — checks that
// gate registration before any process runs.
func TestLoadProgramRejectsInvalid(t *testing.T) {
	valid := testProgram("program@1", []byte("w"))
	tests := []struct {
		name    string
		program Data
	}{
		{name: "no id", program: func() Data { p := valid; p.ID = " "; return p }()},
		{name: "no wasm", program: func() Data { p := valid; p.SourceCode = nil; return p }()},
		{name: "no description", program: func() Data { p := valid; p.Description = ""; return p }()},
		{name: "no input schema", program: func() Data { p := valid; p.Input = nil; return p }()},
		{name: "no output schema", program: func() Data { p := valid; p.Output = nil; return p }()},
		{name: "malformed schema", program: func() Data {
			p := valid
			p.Input = json.RawMessage(`not json`)
			return p
		}()},
		{name: "uncompilable schema", program: func() Data {
			p := valid
			p.Output = json.RawMessage(`{"type":"nonsense"}`)
			return p
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(test.program); err == nil || !errors.Is(err, errs.Invalid) {
				t.Fatalf("Load = %v, want errs.Invalid", err)
			}
		})
	}
}

// TestLoadedProgramsBookkeeping covers the registry itself: an id is taken by one
// program, re-asserting the identical program is a no-op, and a different program
// under a taken id is refused (the caller removes the old one first).
func TestLoadedProgramsBookkeeping(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.Resolve("absent"); err == nil {
		t.Fatal("resolving against an empty registry should error")
	}
	if _, ok := registry.Remove("absent"); ok {
		t.Fatal("removing an unregistered program reported a removal")
	}

	first, err := Load(testProgram("a", []byte("one")))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	added, err := registry.Add(first)
	if err != nil || !added {
		t.Fatalf("add = %v, %v", added, err)
	}

	// Re-asserting the identical program changes nothing and is not an error.
	again, err := Load(testProgram("a", []byte("one")))
	if err != nil {
		t.Fatalf("load again: %v", err)
	}
	added, err = registry.Add(again)
	if err != nil || added {
		t.Fatalf("re-adding the identical program = %v, %v; want (false, nil)", added, err)
	}

	// A different program under the same id is refused.
	changed, err := Load(testProgram("a", []byte("two")))
	if err != nil {
		t.Fatalf("load changed: %v", err)
	}
	if _, err := registry.Add(changed); !errors.Is(err, errs.Conflict) {
		t.Fatalf("add under a taken id = %v, want errs.Conflict", err)
	}

	if got := registry.List(); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("list = %v", got)
	}
	if _, ok := registry.Remove("a"); !ok {
		t.Fatal("removing a registered program reported no removal")
	}
	if got := registry.List(); len(got) != 0 {
		t.Fatalf("registry not empty after removal: %v", got)
	}
}

// TestValidateTextStringFirstRule: a payload validates against an interface
// schema as a plain string first (the conversational case), and only when that
// fails is it parsed as JSON and checked as structured data — so text that
// happens to look like JSON still counts as a string for a string schema, and
// a structured schema accepts a JSON document but rejects prose.
func TestValidateTextStringFirstRule(t *testing.T) {
	strSchema, err := PrepareSchema("input", json.RawMessage(`{"type":"string"}`))
	if err != nil {
		t.Fatalf("compile string schema: %v", err)
	}
	for _, text := range []string{"hello", "42", `{"a":1}`} {
		if err := strSchema.Validate(text); err != nil {
			t.Fatalf("string schema rejected %q (string-first should accept any string): %v", text, err)
		}
	}

	objSchema, err := PrepareSchema("input", json.RawMessage(
		`{"type":"object","required":["task"],"properties":{"task":{"type":"string"}}}`))
	if err != nil {
		t.Fatalf("compile object schema: %v", err)
	}
	if err := objSchema.Validate(`{"task":"x"}`); err != nil {
		t.Fatalf("object schema rejected a matching JSON document: %v", err)
	}
	if err := objSchema.Validate("just prose"); err == nil {
		t.Fatal("object schema accepted non-JSON prose")
	}
	if err := objSchema.Validate(`{"other":1}`); err == nil {
		t.Fatal("object schema accepted JSON missing a required field")
	}
}
