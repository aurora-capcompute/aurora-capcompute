package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestLoadProgramsCopiesBytesAndPinsDigest(t *testing.T) {
	raw := []byte("wasm")
	programs, err := loadPrograms(context.Background(), staticPrograms{
		defaultID: "program@1",
		sources:   []ProgramSource{{ID: "program@1", Wasm: raw}},
	})
	if err != nil {
		t.Fatalf("load programs: %v", err)
	}
	raw[0] = 'X'
	source, err := programs.Source("program@1")
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	if string(source.Wasm) != "wasm" {
		t.Fatalf("source bytes changed: %q", source.Wasm)
	}
	sum := sha256.Sum256([]byte("wasm"))
	artifact, err := programs.Resolve("program@1")
	if err != nil {
		t.Fatalf("resolve artifact: %v", err)
	}
	if artifact.Digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %q", artifact.Digest)
	}
}

func TestLoadProgramsRejectsInvalidProviders(t *testing.T) {
	tests := []struct {
		name     string
		provider ProgramProvider
	}{
		// A provider that lists at least one program must still name a valid default
		// and supply well-formed, unique sources.
		{name: "missing default", provider: staticPrograms{sources: []ProgramSource{{ID: "program@1", Wasm: []byte("wasm")}}}},
		{name: "empty wasm", provider: staticPrograms{defaultID: "program@1", sources: []ProgramSource{{ID: "program@1"}}}},
		{name: "duplicate", provider: staticPrograms{defaultID: "program@1", sources: []ProgramSource{
			{ID: "program@1", Wasm: []byte("one")},
			{ID: "program@1", Wasm: []byte("two")},
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

// TestLoadedProgramsMutation covers the registry bookkeeping SetPrograms relies on
// (put/remove/digest diffing and default recomputation), independent of wasm
// compilation.
func TestLoadedProgramsMutation(t *testing.T) {
	programs, err := loadPrograms(context.Background(), nil)
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if d := programs.digests(); len(d) != 0 {
		t.Fatalf("empty digests = %v", d)
	}

	// First program becomes the default.
	programs.put("b", []byte("two"), digestOf([]byte("two")))
	if programs.DefaultID() != "b" {
		t.Fatalf("default = %q, want b", programs.DefaultID())
	}
	// A lexicographically smaller id does not displace an existing valid default.
	programs.put("a", []byte("one"), digestOf([]byte("one")))
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
