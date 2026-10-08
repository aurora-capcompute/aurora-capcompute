package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute"
	extism "github.com/extism/go-sdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type ProgramID string

func (p ProgramID) String() string { return string(p) }

// ProgramData is a program as an app hands it over: the wasm bytes and the
// interface that ships beside them — a one-line description plus the JSON Schema
// documents of its input message and its answer. Conversational programs declare
// `{"type":"string"}`; structured programs declare object schemas.
type ProgramData struct {
	ID          ProgramID
	SourceCode  []byte
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

// Program is a registered program as a caller may see it: its identity and the
// interface it declared. The compiled schemas and the wasm image stay in the
// registry.
type Program struct {
	ID ProgramID
	// Digest is the program's identity: a hash over its wasm and both of its
	// schemas. A process is bound to it for life.
	Digest      string
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

type compiledProgram struct {
	Program
	input  *jsonschema.Schema
	output *jsonschema.Schema
	image  *capcompute.Program
}

func (p compiledProgram) validateInput(input string) error {
	return p.validate("input", p.input, input)
}

func (p compiledProgram) validateOutput(answer string) error {
	return p.validate("output", p.output, answer)
}

// validate checks text against a schema, string-first: the text as a string
// instance, else the text as a JSON document.
func (p compiledProgram) validate(what string, schema *jsonschema.Schema, text string) error {
	if schema.Validate(text) == nil {
		return nil
	}
	raw := []byte(text)
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("null")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err == nil {
		err = schema.Validate(value)
	} else {
		err = fmt.Errorf("not valid JSON: %w", err)
	}
	if err != nil {
		return fmt.Errorf("%w: %s rejected by program %q %s schema: %v", errs.Invalid, what, p.ID, what, err)
	}
	return nil
}

// programRegistry holds the compiled programs a runtime can run. It is built
// once, before the runtime serves, and never changes, so it needs no lock.
type programRegistry map[ProgramID]compiledProgram

// newProgramRegistry compiles every program. An id may appear once.
func newProgramRegistry(ctx context.Context, programs []ProgramData) (programRegistry, error) {
	registry := make(programRegistry, len(programs))
	for _, data := range programs {
		if _, taken := registry[data.ID]; taken {
			registry.close(ctx)
			return nil, fmt.Errorf("%w: program %q is listed twice", errs.Invalid, data.ID)
		}
		program, err := compileProgram(ctx, data)
		if err != nil {
			registry.close(ctx)
			return nil, err
		}
		registry[data.ID] = program
	}
	return registry, nil
}

func compileProgram(ctx context.Context, data ProgramData) (compiledProgram, error) {
	description := strings.TrimSpace(data.Description)
	if description == "" {
		return compiledProgram{}, fmt.Errorf("%w: program %q interface: a description is required", errs.Invalid, data.ID)
	}
	input, inputSchema, err := compileSchema("input", data.Input)
	if err != nil {
		return compiledProgram{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, data.ID, err)
	}
	output, outputSchema, err := compileSchema("output", data.Output)
	if err != nil {
		return compiledProgram{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, data.ID, err)
	}
	wasmSum := sha256.Sum256(data.SourceCode)
	image, err := capcompute.NewProgram(ctx, capcompute.Config{
		Image: extism.Manifest{
			Wasm: []extism.Wasm{extism.WasmData{Data: data.SourceCode, Hash: hex.EncodeToString(wasmSum[:]), Name: data.ID.String()}},
		},
		PluginConfig:   extism.PluginConfig{EnableWasi: true},
		MaxMemoryPages: processMemoryPages,
	})
	if err != nil {
		return compiledProgram{}, fmt.Errorf("compile program %q: %w", data.ID, err)
	}
	identity := sha256.New()
	for _, part := range [][]byte{data.SourceCode, input, output} {
		sum := sha256.Sum256(part)
		identity.Write(sum[:])
	}
	return compiledProgram{
		Program: Program{
			ID:          data.ID,
			Digest:      hex.EncodeToString(identity.Sum(nil)),
			Description: description,
			Input:       input,
			Output:      output,
		},
		input:  inputSchema,
		output: outputSchema,
		image:  image,
	}, nil
}

// compileSchema compacts a schema document and compiles it.
func compileSchema(what string, document json.RawMessage) (json.RawMessage, *jsonschema.Schema, error) {
	if len(bytes.TrimSpace(document)) == 0 {
		return nil, nil, fmt.Errorf("an %s schema is required", what)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, document); err != nil {
		return nil, nil, fmt.Errorf("%s schema: %w", what, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(compact.Bytes()))
	if err != nil {
		return nil, nil, fmt.Errorf("%s schema: %w", what, err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(what+".json", doc); err != nil {
		return nil, nil, fmt.Errorf("%s schema: %w", what, err)
	}
	schema, err := compiler.Compile(what + ".json")
	if err != nil {
		return nil, nil, fmt.Errorf("%s schema: %w", what, err)
	}
	return json.RawMessage(compact.Bytes()), schema, nil
}

// bound returns the program a process was created from, and refuses when the
// registry no longer holds that exact identity: a process never runs under
// changed code.
func (r programRegistry) bound(id ProgramID, digest string) (compiledProgram, error) {
	program, ok := r[id]
	if !ok {
		return compiledProgram{}, fmt.Errorf("%w: program %q is not loaded", errs.Conflict, id)
	}
	if program.Digest != digest {
		return compiledProgram{}, fmt.Errorf(
			"%w: program %q changed (loaded %s, process bound to %s): a process is immutable — its code and interface are fixed; spawn a new process from the new program",
			errs.Conflict, id, program.Digest, digest)
	}
	return program, nil
}

func (r programRegistry) list() []Program {
	out := make([]Program, 0, len(r))
	for _, program := range r {
		out = append(out, program.Program)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// close releases every image.
func (r programRegistry) close(ctx context.Context) []error {
	var failures []error
	for _, program := range r {
		if err := program.image.Close(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}
