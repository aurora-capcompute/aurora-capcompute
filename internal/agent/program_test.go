package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

type staticPrograms struct {
	defaultID string
	sources   []ProgramSource
}

func (b staticPrograms) DefaultID() string { return b.defaultID }
func (b staticPrograms) List(context.Context) ([]ProgramSource, error) {
	return b.sources, nil
}

// fakeRecord builds a registry record without wasm — for the bookkeeping tests
// (put/remove/default recomputation), which are independent of the interface
// and schema machinery loadProgram runs.
func fakeRecord(id string, wasm []byte) programRecord {
	return programRecord{
		source:   ProgramSource{ID: id, Wasm: wasm},
		artifact: ProgramArtifact{ID: id, Digest: digestOf(wasm)},
	}
}

func TestLoadProgramsCopiesBytesAndPinsDigestAndInterface(t *testing.T) {
	wasm := buildProgram(t)
	raw := append([]byte(nil), wasm...)
	programs, err := loadPrograms(context.Background(), staticPrograms{
		defaultID: "program@1",
		sources:   []ProgramSource{{ID: "program@1", Wasm: raw}},
	})
	if err != nil {
		t.Fatalf("load programs: %v", err)
	}
	raw[0] = 'X' // mutating the caller's slice must not touch the registry's copy
	source, err := programs.Source("program@1")
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	if !bytes.Equal(source.Wasm, wasm) {
		t.Fatal("source bytes changed under the registry")
	}
	sum := sha256.Sum256(wasm)
	artifact, err := programs.Resolve("program@1")
	if err != nil {
		t.Fatalf("resolve artifact: %v", err)
	}
	if artifact.Digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %q", artifact.Digest)
	}
	// The bundled interface was extracted from the wasm's describe export.
	if artifact.Description == "" || len(artifact.Input) == 0 || len(artifact.Output) == 0 {
		t.Fatalf("interface not extracted: %+v", artifact.ProgramInterface)
	}
}

// A program that lists at least one source must name a valid default; sources
// must carry bytes and unique ids; and each program's bytes must be a real
// wasm that can describe itself — checks that gate registration before any
// process runs.
func TestLoadProgramsRejectsInvalidProviders(t *testing.T) {
	tests := []struct {
		name     string
		provider ProgramProvider
	}{
		{name: "empty wasm", provider: staticPrograms{defaultID: "program@1", sources: []ProgramSource{{ID: "program@1"}}}},
		{name: "duplicate", provider: staticPrograms{defaultID: "program@1", sources: []ProgramSource{
			{ID: "program@1", Wasm: []byte("one")},
			{ID: "program@1", Wasm: []byte("two")},
		}}},
		{name: "undescribable", provider: staticPrograms{defaultID: "program@1", sources: []ProgramSource{
			{ID: "program@1", Wasm: []byte("not wasm")},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadPrograms(context.Background(), test.provider); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// A provider that lists a describable program but names no default is refused
// once the program has passed the interface extraction.
func TestLoadProgramsRequiresDefault(t *testing.T) {
	wasm := buildProgram(t)
	if _, err := loadPrograms(context.Background(), staticPrograms{
		sources: []ProgramSource{{ID: "program@1", Wasm: wasm}},
	}); err == nil {
		t.Fatal("expected missing-default error")
	}
}

// TestLoadedProgramsMutation covers the registry bookkeeping SetPrograms relies on
// (put/remove/digest diffing and default recomputation), independent of wasm
// compilation and interface extraction.
func TestLoadedProgramsMutation(t *testing.T) {
	programs, err := loadPrograms(context.Background(), nil)
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if d := programs.digests(); len(d) != 0 {
		t.Fatalf("empty digests = %v", d)
	}

	// First program becomes the default.
	programs.put(fakeRecord("b", []byte("two")))
	if programs.DefaultID() != "b" {
		t.Fatalf("default = %q, want b", programs.DefaultID())
	}
	// A lexicographically smaller id does not displace an existing valid default.
	programs.put(fakeRecord("a", []byte("one")))
	if programs.DefaultID() != "b" {
		t.Fatalf("default changed to %q, want sticky b", programs.DefaultID())
	}
	if d := programs.digests(); d["a"] != digestOf([]byte("one")) || d["b"] != digestOf([]byte("two")) {
		t.Fatalf("digests = %v", d)
	}

	// Removing the default falls back to the lexicographically first remaining id.
	programs.remove("b")
	if programs.DefaultID() != "a" {
		t.Fatalf("default after removing b = %q, want a", programs.DefaultID())
	}
	// Emptying the registry clears the default.
	programs.remove("a")
	if programs.DefaultID() != "" || len(programs.List()) != 0 {
		t.Fatalf("registry not empty: default=%q list=%v", programs.DefaultID(), programs.List())
	}
}

// TestValidateTextStringFirstRule: a payload validates against an interface
// schema as a plain string first (the conversational case), and only when that
// fails is it parsed as JSON and checked as structured data — so text that
// happens to look like JSON still counts as a string for a string schema, and
// a structured schema accepts a JSON document but rejects prose.
func TestValidateTextStringFirstRule(t *testing.T) {
	strSchema, err := compileSchema("input", json.RawMessage(`{"type":"string"}`))
	if err != nil {
		t.Fatalf("compile string schema: %v", err)
	}
	for _, text := range []string{"hello", "42", `{"a":1}`} {
		if err := validateText(strSchema, text); err != nil {
			t.Fatalf("string schema rejected %q (string-first should accept any string): %v", text, err)
		}
	}

	objSchema, err := compileSchema("input", json.RawMessage(
		`{"type":"object","required":["task"],"properties":{"task":{"type":"string"}}}`))
	if err != nil {
		t.Fatalf("compile object schema: %v", err)
	}
	if err := validateText(objSchema, `{"task":"x"}`); err != nil {
		t.Fatalf("object schema rejected a matching JSON document: %v", err)
	}
	if err := validateText(objSchema, "just prose"); err == nil {
		t.Fatal("object schema accepted non-JSON prose")
	}
	if err := validateText(objSchema, `{"other":1}`); err == nil {
		t.Fatal("object schema accepted JSON missing a required field")
	}
}

// A nil provider or one with no programs boots an empty registry: the runtime can
// start with no program, and program runs fail with a clear error until one is
// registered (e.g. via a Program CRD through SetPrograms).
func TestLoadProgramsAllowsEmpty(t *testing.T) {
	for _, provider := range []ProgramProvider{nil, staticPrograms{}} {
		programs, err := loadPrograms(context.Background(), provider)
		if err != nil {
			t.Fatalf("empty provider: %v", err)
		}
		if programs.DefaultID() != "" {
			t.Fatalf("empty registry default = %q, want \"\"", programs.DefaultID())
		}
		if _, err := programs.Resolve(""); err == nil {
			t.Fatal("resolving against an empty registry should error")
		}
		if got := programs.List(); len(got) != 0 {
			t.Fatalf("empty registry list = %v", got)
		}
	}
}
