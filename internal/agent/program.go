package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ProgramData is a program as an app hands it over: the wasm bytes and the
// interface that ships beside them — a one-line description plus the JSON Schema
// documents of its input message and its answer. Conversational programs declare
// `{"type":"string"}`; structured programs declare object schemas and callers
// pass/receive JSON text. Raw and unprepared: nothing here is compiled, hashed or
// normalized, and the interface is declarative data the app supplies rather than
// something the runtime executes the program to discover.
type ProgramData struct {
	ID          string
	SourceCode  []byte
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

// ProgramArtifact is a registered program: what the runtime made of the data it
// was given, and what it reports back (Programs). The identity is pinned, the
// schemas are normalized and compiled, and the wasm bytes have become the
// compiled image — one entry holds everything a process needs to run under this
// id, so a registered program can never be half-present.
type ProgramArtifact struct {
	ID string
	// Digest is the program's content identity: sha256 over the wasm bytes and
	// the two normalized schema documents. A process binds to it, so changing the
	// code or either declared schema is a new program and strands the old one's
	// processes. The description is deliberately outside it — rewording what a
	// program is for does not change what it accepts or returns.
	Digest      string
	Description string
	Input       Schema
	Output      Schema
	// image is the compiled wasm the processor instantiates processes from. It is
	// the registry's to open (AddProgram) and to close (RemoveProgram, Close);
	// copies of an artifact share it.
	image *capcompute.Program
}

// Schema is one declared JSON Schema: the document as the program declared it,
// normalized, and its compiled form. Both are needed and neither is derivable
// from the other: the compiled schema validates payloads, while the document is
// what a caller is shown and what the spawn ADT embeds verbatim for the processor
// Validator to enforce (a compiled schema cannot be turned back into its source).
type Schema struct {
	Document json.RawMessage
	compiled *jsonschema.Schema
}

// validate checks a payload against this schema with the string-first rule: text
// that satisfies the schema as a plain string value is valid (the conversational
// case); otherwise the text must parse as JSON and the parsed value must satisfy
// the schema (the structured case).
func (s Schema) validate(text string) error {
	stringErr := s.compiled.Validate(text)
	if stringErr == nil {
		return nil
	}
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(text))
	if err != nil {
		return stringErr
	}
	return s.compiled.Validate(value)
}

// loadedPrograms is the runtime's program registry. It is mutable (programs are
// added and removed at runtime via Runtime.AddProgram / Runtime.RemoveProgram)
// and guards its own state with an RWMutex, because it is read on paths that do
// not hold the Runtime mutex (e.g. CreateSession). It holds no default: a
// process names the program it runs.
type loadedPrograms struct {
	mu       sync.RWMutex
	programs map[string]ProgramArtifact
}

func newPrograms() *loadedPrograms {
	return &loadedPrograms{programs: make(map[string]ProgramArtifact)}
}

// digestOf returns the sha256 of a program's wasm bytes — the integrity hash
// the runtime hands the wasm engine.
func digestOf(wasm []byte) string {
	sum := sha256.Sum256(wasm)
	return hex.EncodeToString(sum[:])
}

// programIdentity is a program's content identity: the digest a process is bound
// to. It covers the wasm bytes and both normalized schema documents, because
// those are the program's contract — changing the code or a declared schema is a
// new program, and a process created under the old identity is stranded (a
// legitimate audit target never runs under a changed contract). The description
// is not part of it: rewording what a program is for changes nothing about what
// it accepts or returns, so it must not strand anything. The schemas are hashed
// normalized, so reformatting the manifest they were loaded from is not a
// program change either. The wasm's own digest (digestOf) stays the bytes'
// integrity hash.
func programIdentity(sourceCode []byte, input, output Schema) string {
	identity := sha256.New()
	// Each part enters as its own fixed-width sum, so no shuffling of bytes
	// between the parts can collide.
	for _, part := range [][]byte{sourceCode, input.Document, output.Document} {
		sum := sha256.Sum256(part)
		identity.Write(sum[:])
	}
	return hex.EncodeToString(identity.Sum(nil))
}

// loadProgram prepares the data an app supplied into a registrable program:
// check the id and the bytes, normalize and validate the declared interface,
// compile its schemas, and pin the identity over code and contract. No wasm
// execution — the interface is data the app supplies, not something the program
// computes. The bytes stay with the caller, which compiles them into the image.
func loadProgram(data ProgramData) (ProgramArtifact, error) {
	id := strings.TrimSpace(data.ID)
	if id == "" || len(data.SourceCode) == 0 {
		return ProgramArtifact{}, fmt.Errorf("%w: program id and wasm bytes are required", ErrInvalid)
	}
	description := strings.TrimSpace(data.Description)
	if description == "" {
		return ProgramArtifact{}, fmt.Errorf("%w: program %q interface: a description is required", ErrInvalid, id)
	}
	input, err := prepareSchema("input", data.Input)
	if err != nil {
		return ProgramArtifact{}, fmt.Errorf("%w: program %q interface: %v", ErrInvalid, id, err)
	}
	output, err := prepareSchema("output", data.Output)
	if err != nil {
		return ProgramArtifact{}, fmt.Errorf("%w: program %q interface: %v", ErrInvalid, id, err)
	}
	return ProgramArtifact{
		ID:          id,
		Digest:      programIdentity(data.SourceCode, input, output),
		Description: description,
		Input:       input,
		Output:      output,
	}, nil
}

// prepareSchema turns one declared schema document into a Schema: required,
// compacted — so a program's identity turns on what the schema says and not on
// how it was laid out — and compiled, ready to validate against.
func prepareSchema(what string, document json.RawMessage) (Schema, error) {
	if len(bytes.TrimSpace(document)) == 0 {
		return Schema{}, fmt.Errorf("an %s schema is required", what)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, document); err != nil {
		return Schema{}, fmt.Errorf("%s schema: %w", what, err)
	}
	schema := Schema{Document: json.RawMessage(buf.Bytes())}
	compiled, err := compileDocument(what, schema.Document)
	if err != nil {
		return Schema{}, err
	}
	schema.compiled = compiled
	return schema, nil
}

// compileDocument compiles one JSON Schema document.
func compileDocument(what string, raw json.RawMessage) (*jsonschema.Schema, error) {
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

// validateCompensationArgs holds a deferred inverse's args to the same input
// schema its forward call would face. The rollback path that fires the inverse
// at abort time does not re-run the Validator, so this is where a compensation
// with args that violate the capability's schema (its authority boundary) is
// refused — at registration, before it can be journaled and later executed.
func validateCompensationArgs(capability sys.Capability, rawArgs json.RawMessage) error {
	if len(capability.InputSchema) == 0 {
		return nil
	}
	schema, err := compileDocument("compensation", capability.InputSchema)
	if err != nil {
		return fmt.Errorf("compile %s schema: %w", capability.Name, err)
	}
	args := rawArgs
	if len(bytes.TrimSpace(args)) == 0 {
		args = json.RawMessage("null")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(args))
	if err != nil {
		return fmt.Errorf("%s args are not valid JSON: %w", capability.Name, err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("%s args violate its input schema: %w", capability.Name, err)
	}
	return nil
}

// Resolve resolves a program id to its registered program. loadProgram took the
// registry's own copy of the wasm bytes and nothing mutates them afterwards, so
// the returned value shares them.
func (r *loadedPrograms) Resolve(id string) (ProgramArtifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	program, ok := r.programs[strings.TrimSpace(id)]
	if !ok {
		return ProgramArtifact{}, fmt.Errorf("%w: program %q is not registered", ErrInvalid, id)
	}
	return program, nil
}

// ValidateInput checks a process input against the program's declared input
// schema.
func (r *loadedPrograms) ValidateInput(id, input string) error {
	program, err := r.Resolve(id)
	if err != nil {
		return err
	}
	if err := program.Input.validate(input); err != nil {
		return fmt.Errorf("%w: input rejected by program %q input schema: %v", ErrInvalid, program.ID, err)
	}
	return nil
}

// ValidateOutput checks a process answer against the program's declared
// output schema.
func (r *loadedPrograms) ValidateOutput(id, answer string) error {
	program, err := r.Resolve(id)
	if err != nil {
		return err
	}
	if err := program.Output.validate(answer); err != nil {
		return fmt.Errorf("%w: answer rejected by program %q output schema: %v", ErrInvalid, program.ID, err)
	}
	return nil
}

// answerValidator returns the sys.output validation hook for one program.
func (r *loadedPrograms) answerValidator(id string) func(string) error {
	return func(answer string) error { return r.ValidateOutput(id, answer) }
}

func (r *loadedPrograms) List() []ProgramArtifact {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProgramArtifact, 0, len(r.programs))
	for _, program := range r.programs {
		out = append(out, program)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// add registers a completed program (built by loadProgram). Registering an id
// that is already taken is refused — a program is replaced by removing it first,
// which settles the processes bound to it — except when the identity is
// identical, which is a no-op so a control plane can re-assert its desired set
// without disturbing anything.
func (r *loadedPrograms) add(program ProgramArtifact) (added bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, taken := r.programs[program.ID]; taken {
		if existing.Digest == program.Digest {
			return false, nil
		}
		return false, fmt.Errorf("%w: program %q is registered with a different identity (%s); remove it first",
			ErrConflict, program.ID, shortDigest(existing.Digest))
	}
	r.programs[program.ID] = program
	return true, nil
}

// remove unregisters a program and hands it back, so the caller can release the
// compiled image it holds. ok is false when the id was not registered.
func (r *loadedPrograms) remove(id string) (removed ProgramArtifact, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed, ok = r.programs[id]
	if !ok {
		return ProgramArtifact{}, false
	}
	delete(r.programs, id)
	return removed, true
}

// drain empties the registry and returns everything it held, for shutdown.
func (r *loadedPrograms) drain() []ProgramArtifact {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ProgramArtifact, 0, len(r.programs))
	for id, program := range r.programs {
		out = append(out, program)
		delete(r.programs, id)
	}
	return out
}
