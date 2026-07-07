package agent

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestSpawnInputToMessage covers the inverse of the string-first rule: the typed
// spawn `input` collapses to the canonical process-input string.
func TestSpawnInputToMessage(t *testing.T) {
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
			got, err := spawnInputToMessage(json.RawMessage(tc.input))
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
// discriminated union that the kernel Validator (which compiles and enforces it
// before dispatch) accepts: one branch per program, `input` typed per program.
func TestSpawnADTSchema(t *testing.T) {
	stringInput := json.RawMessage(`{"type":"string"}`)
	objectInput := json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}`)
	adt := spawnADTSchema([]json.RawMessage{
		spawnBranchSchema("echo", stringInput),
		spawnBranchSchema("weather", objectInput),
	})
	schema := compileSpawnSchema(t, adt)

	assertValid(t, schema, `{"program":"echo","input":"hello"}`, true)          // string program, string input
	assertValid(t, schema, `{"program":"weather","input":{"city":"paris"}}`, true) // object program, object input
	assertValid(t, schema, `{"program":"echo","input":{"city":"paris"}}`, false)   // wrong input type for the program
	assertValid(t, schema, `{"program":"weather","input":"paris"}`, false)         // wrong input type for the program
	assertValid(t, schema, `{"program":"nope","input":"x"}`, false)                // unlisted program
	assertValid(t, schema, `{"program":"echo"}`, false)                            // missing input
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
