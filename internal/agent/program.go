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
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const DefaultProgramID = "aurora-default@1"

// ProgramSource is a program as an app loads it: the wasm bytes and the
// interface manifest that ships beside them (the `<name>.json` next to
// `<name>.wasm`). The interface is declarative data — the runtime never
// executes the program to discover it.
type ProgramSource struct {
	ID        string
	Wasm      []byte
	Interface json.RawMessage
}

// ProgramInterface is a program's declared contract: what its input message and
// its answer look like (JSON Schemas), plus a one-line description. A caller —
// model or human — reads it to know what to pass a program. Conversational
// programs declare `{"type":"string"}`; structured programs declare object
// schemas and callers pass/receive JSON text.
type ProgramInterface struct {
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Output      json.RawMessage `json:"output"`
}

type ProgramArtifact struct {
	ID string `json:"id"`
	// Digest is the program's content identity: sha256 over the wasm bytes and
	// the interface manifest together. A process binds to it, so changing either
	// the code or the declared contract is a new program.
	Digest string `json:"digest"`
	ProgramInterface
}

type ProgramProvider interface {
	DefaultID() string
	List(context.Context) ([]ProgramSource, error)
}

// programRecord is one registered program: its bytes, its artifact (digest +
// interface), and the interface's compiled schemas, ready to validate against.
type programRecord struct {
	source   ProgramSource
	artifact ProgramArtifact
	input    *jsonschema.Schema
	output   *jsonschema.Schema
}

// loadedPrograms is the runtime's program registry. It is mutable (programs can be
// added, replaced, or removed at runtime via Runtime.SetPrograms) and guards its
// own state with an RWMutex, because it is read on paths that do not hold the
// Runtime mutex (e.g. CreateSession).
type loadedPrograms struct {
	mu        sync.RWMutex
	defaultID string
	programs  map[string]programRecord
}

// digestOf returns the sha256 of a program's wasm bytes — the integrity hash
// the runtime hands the wasm engine.
func digestOf(wasm []byte) string {
	sum := sha256.Sum256(wasm)
	return hex.EncodeToString(sum[:])
}

// programIdentity is a program's content identity: the digest a process is
// bound to. It covers both the wasm bytes and the interface manifest, because
// the interface is part of the program's contract — changing either the code or
// the declared schema is a new program, and a process created under the old
// identity is stranded (a legitimate audit target never runs under a changed
// contract). The wasm's own digest (digestOf) stays the bytes' integrity hash.
func programIdentity(wasm []byte, ifaceRaw json.RawMessage) string {
	wasmSum := sha256.Sum256(wasm)
	ifaceSum := sha256.Sum256(ifaceRaw)
	both := sha256.New()
	both.Write(wasmSum[:])
	both.Write(ifaceSum[:])
	return hex.EncodeToString(both.Sum(nil))
}

// loadProgram builds one registry record from a program's bytes and its
// declared interface manifest: copy the bytes, digest them, parse and validate
// the interface, and compile its schemas. No wasm execution — the interface is
// data the app supplies, not something the program computes.
func loadProgram(id string, wasm []byte, ifaceRaw json.RawMessage) (programRecord, error) {
	wasm = append([]byte(nil), wasm...)
	iface, err := parseInterface(ifaceRaw)
	if err != nil {
		return programRecord{}, fmt.Errorf("program %q: %w", id, err)
	}
	input, err := compileSchema("input", iface.Input)
	if err != nil {
		return programRecord{}, fmt.Errorf("program %q interface: %w", id, err)
	}
	output, err := compileSchema("output", iface.Output)
	if err != nil {
		return programRecord{}, fmt.Errorf("program %q interface: %w", id, err)
	}
	return programRecord{
		source:   ProgramSource{ID: id, Wasm: wasm, Interface: append(json.RawMessage(nil), ifaceRaw...)},
		artifact: ProgramArtifact{ID: id, Digest: programIdentity(wasm, ifaceRaw), ProgramInterface: iface},
		input:    input,
		output:   output,
	}, nil
}

// parseInterface decodes and lightly validates a program's interface manifest:
// a description is required, and both schemas must be present (they compile
// separately). A program that ships without a well-formed interface is refused.
func parseInterface(raw json.RawMessage) (ProgramInterface, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ProgramInterface{}, fmt.Errorf("an interface manifest is required (description + input/output schemas)")
	}
	var iface ProgramInterface
	if err := json.Unmarshal(raw, &iface); err != nil {
		return ProgramInterface{}, fmt.Errorf("decode interface: %w", err)
	}
	iface.Description = strings.TrimSpace(iface.Description)
	if iface.Description == "" {
		return ProgramInterface{}, fmt.Errorf("interface: a description is required")
	}
	return iface, nil
}

// compileSchema compiles one interface schema document.
func compileSchema(what string, raw json.RawMessage) (*jsonschema.Schema, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("an %s schema is required", what)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%s schema: %w", what, err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(what+".json", doc); err != nil {
		return nil, fmt.Errorf("%s schema: %w", what, err)
	}
	schema, err := compiler.Compile(what + ".json")
	if err != nil {
		return nil, fmt.Errorf("%s schema: %w", what, err)
	}
	return schema, nil
}

// validateText checks a payload against an interface schema with the
// string-first rule: text that satisfies the schema as a plain string value is
// valid (the conversational case); otherwise the text must parse as JSON and
// the parsed value must satisfy the schema (the structured case).
func validateText(schema *jsonschema.Schema, text string) error {
	stringErr := schema.Validate(text)
	if stringErr == nil {
		return nil
	}
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(text))
	if err != nil {
		return stringErr
	}
	return schema.Validate(value)
}

// loadPrograms snapshots the provider into a registry. A nil provider or an empty
// program list yields an empty registry (no default): the runtime then boots with
// no program and program processes fail with a clear error until one is registered. When
// the provider lists at least one program, its declared default must be present.
func loadPrograms(ctx context.Context, provider ProgramProvider) (*loadedPrograms, error) {
	loaded := &loadedPrograms{programs: make(map[string]programRecord)}
	if provider == nil {
		return loaded, nil
	}
	list, err := provider.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}
	for _, source := range list {
		id := strings.TrimSpace(source.ID)
		if id == "" || len(source.Wasm) == 0 {
			return nil, fmt.Errorf("%w: program id and wasm bytes are required", ErrInvalid)
		}
		if _, exists := loaded.programs[id]; exists {
			return nil, fmt.Errorf("%w: duplicate program %q", ErrInvalid, id)
		}
		record, err := loadProgram(id, source.Wasm, source.Interface)
		if err != nil {
			return nil, err
		}
		loaded.programs[id] = record
	}
	if len(loaded.programs) > 0 {
		defaultID := strings.TrimSpace(provider.DefaultID())
		if defaultID == "" {
			return nil, fmt.Errorf("%w: default program id is required", ErrInvalid)
		}
		if _, ok := loaded.programs[defaultID]; !ok {
			return nil, fmt.Errorf("%w: default program %q is not registered", ErrInvalid, defaultID)
		}
		loaded.defaultID = defaultID
	}
	return loaded, nil
}

func (r *loadedPrograms) DefaultID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultID
}

// record resolves a program id (empty means the default) to its registry record.
func (r *loadedPrograms) record(id string) (programRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if strings.TrimSpace(id) == "" {
		id = r.defaultID
	}
	if id == "" {
		return programRecord{}, fmt.Errorf("%w: no program registered", ErrInvalid)
	}
	record, ok := r.programs[id]
	if !ok {
		return programRecord{}, fmt.Errorf("%w: program %q is not registered", ErrInvalid, id)
	}
	return record, nil
}

func (r *loadedPrograms) Resolve(id string) (ProgramArtifact, error) {
	record, err := r.record(id)
	if err != nil {
		return ProgramArtifact{}, err
	}
	return record.artifact, nil
}

func (r *loadedPrograms) Source(id string) (ProgramSource, error) {
	record, err := r.record(id)
	if err != nil {
		return ProgramSource{}, err
	}
	source := record.source
	source.Wasm = append([]byte(nil), source.Wasm...)
	source.Interface = append(json.RawMessage(nil), source.Interface...)
	return source, nil
}

// ValidateInput checks a process input against the program's declared input
// schema.
func (r *loadedPrograms) ValidateInput(id, input string) error {
	record, err := r.record(id)
	if err != nil {
		return err
	}
	if err := validateText(record.input, input); err != nil {
		return fmt.Errorf("%w: input rejected by program %q input schema: %v", ErrInvalid, record.artifact.ID, err)
	}
	return nil
}

// ValidateOutput checks a process answer against the program's declared
// output schema.
func (r *loadedPrograms) ValidateOutput(id, answer string) error {
	record, err := r.record(id)
	if err != nil {
		return err
	}
	if err := validateText(record.output, answer); err != nil {
		return fmt.Errorf("%w: answer rejected by program %q output schema: %v", ErrInvalid, record.artifact.ID, err)
	}
	return nil
}

// answerValidator returns the sys.output validation hook for one program.
func (r *loadedPrograms) answerValidator(id string) func(string) error {
	return func(answer string) error { return r.ValidateOutput(id, answer) }
}

// Interface returns a registered program's declared interface, if it is loaded.
func (r *loadedPrograms) Interface(id string) (ProgramInterface, bool) {
	record, err := r.record(id)
	if err != nil {
		return ProgramInterface{}, false
	}
	return record.artifact.ProgramInterface, true
}

func (r *loadedPrograms) List() []ProgramArtifact {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProgramArtifact, 0, len(r.programs))
	for _, record := range r.programs {
		out = append(out, record.artifact)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// digests returns the current id→digest map, for diffing a desired program set
// against what is registered.
func (r *loadedPrograms) digests() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.programs))
	for id, record := range r.programs {
		out[id] = record.artifact.Digest
	}
	return out
}

// put registers or replaces a program. The caller built the record with
// loadProgram, so bytes, interface, and schemas are already validated.
func (r *loadedPrograms) put(record programRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.programs[record.artifact.ID] = record
	r.recomputeDefaultLocked()
}

// remove unregisters a program.
func (r *loadedPrograms) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.programs, id)
	r.recomputeDefaultLocked()
}

// recomputeDefaultLocked keeps a stable default: the existing one if it still
// exists, else the lexicographically first registered program, else empty.
func (r *loadedPrograms) recomputeDefaultLocked() {
	if _, ok := r.programs[r.defaultID]; ok && r.defaultID != "" {
		return
	}
	ids := make([]string, 0, len(r.programs))
	for id := range r.programs {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		r.defaultID = ""
		return
	}
	sort.Strings(ids)
	r.defaultID = ids[0]
}
