package agent

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestSpawnInputToString covers the inverse of the string-first rule: the typed
// spawn `input` collapses to the canonical process-input string.
func TestSpawnInputToString(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"string", `"do the task"`, "do the task", false},
		{"quoted json stays a string", `"{\"a\":1}"`, `{"a":1}`, false},
		{"object compacts", `{ "city": "paris", "n": 3 }`, `{"city":"paris","n":3}`, false},
		{"number scalar", `42`, "42", false},
		{"empty raw", ``, "", true},
		{"whitespace only", `   `, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := spawnInputToString(json.RawMessage(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSpawnADTSchema proves the spawn capability's input_schema is a well-formed
// discriminated union that the processor Validator (which compiles and enforces it
// before dispatch) accepts: one branch per program, `input` typed per program.
func TestSpawnADTSchema(t *testing.T) {
	stringInput := json.RawMessage(`{"type":"string"}`)
	objectInput := json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}`)
	adt := spawnADTSchema([]json.RawMessage{
		spawnBranchSchema("echo", stringInput),
		spawnBranchSchema("weather", objectInput),
	})
	schema := compileSpawnSchema(t, adt)

	assertValid(t, schema, `{"program":"echo","input":"hello"}`, true)                   // string program, string input
	assertValid(t, schema, `{"program":"weather","input":{"city":"paris"}}`, true)       // object program, object input
	assertValid(t, schema, `{"program":"echo","input":{"city":"paris"}}`, false)         // wrong input type for the program
	assertValid(t, schema, `{"program":"weather","input":"paris"}`, false)               // wrong input type for the program
	assertValid(t, schema, `{"program":"nope","input":"x"}`, false)                      // unlisted program
	assertValid(t, schema, `{"program":"echo"}`, false)                                  // missing input
	assertValid(t, schema, `{"program":"echo","input":"hi","system_prompt":"x"}`, false) // no sidecar fields
}

func compileSpawnSchema(t *testing.T, raw json.RawMessage) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal ADT schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("spawn.json", doc); err != nil {
		t.Fatalf("add ADT schema: %v", err)
	}
	schema, err := compiler.Compile("spawn.json")
	if err != nil {
		t.Fatalf("compile ADT schema (the Validator would reject this): %v", err)
	}
	return schema
}

func assertValid(t *testing.T, schema *jsonschema.Schema, doc string, want bool) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(doc)))
	if err != nil {
		t.Fatalf("unmarshal %q: %v", doc, err)
	}
	err = schema.Validate(value)
	if want && err != nil {
		t.Fatalf("expected %s to validate, got %v", doc, err)
	}
	if !want && err == nil {
		t.Fatalf("expected %s to be rejected", doc)
	}
}

// TestProgramShareDefaults: a program node's share settings default to sharing
// (the runtime's standing behavior); an explicit false withholds.
func TestProgramShareDefaults(t *testing.T) {
	var omitted manifest.Manifest
	if !omitted.SharesHistory() || !omitted.SharesCapabilities() {
		t.Fatal("omitted settings should share both history and capabilities")
	}
	no, yes := false, true
	off := manifest.Manifest{History: &no, ShareCapabilities: &no}
	if off.SharesHistory() || off.SharesCapabilities() {
		t.Fatal("explicit false should withhold")
	}
	on := manifest.Manifest{History: &yes}
	if !on.SharesHistory() || !on.SharesCapabilities() {
		t.Fatal("explicit true / omitted should share")
	}
}

// TestBuildChildManifestCapabilitiesGate: capabilities:false hides every grant
// on the child's own manifest (off its menu, still dispatchable); the spawnable
// spec is never mutated, and the version is filled from the root's.
func TestBuildChildManifestCapabilitiesGate(t *testing.T) {
	spec := manifest.Manifest{
		Program: "child",
		Syscalls: []manifest.Syscall{
			{Syscall: "net.http"},
			{Syscall: "core.openaiApi", Hidden: true},
		},
	}
	shared := buildChildManifest(spec, true)
	if shared.Syscalls[0].Hidden || !shared.Syscalls[1].Hidden {
		t.Fatalf("shared grants should keep their authored hidden flags: %+v", shared.Syscalls)
	}
	hidden := buildChildManifest(spec, false)
	for i, grant := range hidden.Syscalls {
		if !grant.Hidden {
			t.Fatalf("grant %d (%s) should be hidden", i, grant.Syscall)
		}
	}
	if hidden.Version != manifest.Version {
		t.Fatalf("child version = %d, want %d", hidden.Version, manifest.Version)
	}
	if spec.Syscalls[0].Hidden {
		t.Fatal("buildChildManifest mutated the spawnable spec")
	}
}

// TestSpawnGrantTakesNoSettings: the context settings live on the program node
// now, so a sys.spawn grant that carries them on the grant is rejected, while a
// grant with a program that carries them validates.
func TestSpawnGrantTakesNoSettings(t *testing.T) {
	onGrant := manifest.Manifest{
		Version: manifest.Version,
		Syscalls: []manifest.Syscall{{
			Syscall:  manifest.SpawnSyscall,
			Config:   json.RawMessage(`{"history":false}`),
			Programs: []manifest.Manifest{{Program: "child"}},
		}},
	}
	if _, err := manifest.Validate(onGrant, &testDispatchers{}); err == nil {
		t.Fatal("expected grant-level spawn settings to be rejected")
	}
	no := false
	onProgram := manifest.Manifest{
		Version: manifest.Version,
		Program: "parent",
		Syscalls: []manifest.Syscall{{
			Syscall:  manifest.SpawnSyscall,
			Programs: []manifest.Manifest{{Program: "child", History: &no, ShareCapabilities: &no}},
		}},
	}
	if _, err := manifest.Validate(onProgram, &testDispatchers{}); err != nil {
		t.Fatalf("program-level spawn settings should validate: %v", err)
	}
}
