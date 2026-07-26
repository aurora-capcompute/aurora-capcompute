// Package program is the runtime's program concern: what a program is, what the
// runtime makes of one, and the registry of the ones currently registered.
//
// A program arrives as Data — wasm bytes plus a declared interface — and Load
// turns it into an Artifact: identity pinned, schemas normalized and compiled.
// The registry is the only place a program id resolves, and an Artifact carries
// its compiled image, so a registered program is never half-present.
//
// Nothing here reads a file, parses configuration, or speaks a wire protocol:
// the application hands over bytes and schema documents it obtained however it
// likes, and this package prepares them.
package program

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/aurora-capcompute/capcompute"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
)

// Data is a program as an app hands it over: the wasm bytes and the interface
// that ships beside them — a one-line description plus the JSON Schema documents
// of its input message and its answer. Conversational programs declare
// `{"type":"string"}`; structured programs declare object schemas and callers
// pass/receive JSON text. Raw and unprepared: nothing here is compiled, hashed
// or normalized, and the interface is declarative data the app supplies rather
// than something the runtime executes the program to discover.
type Data struct {
	ID          string
	SourceCode  []byte
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

// Artifact is a registered program: what the runtime made of the data it was
// given, and what it reports back. The identity is pinned, the schemas are
// normalized and compiled, and the wasm bytes have become the compiled image —
// one entry holds everything a process needs to run under this id, so a
// registered program can never be half-present.
type Artifact struct {
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
	// the registry's to open (Runtime.AddProgram) and to close
	// (Runtime.RemoveProgram, Runtime.Close); copies of an artifact share it.
	image *capcompute.Program
}

// Image is the compiled wasm a process is instantiated from, nil until the
// runtime compiles and attaches it.
func (a Artifact) Image() *capcompute.Program { return a.image }

// WithImage returns the artifact with its compiled image attached. The runtime
// calls it between Load and Registry.Add: compiling needs the bytes, which only
// the caller still holds.
func (a Artifact) WithImage(image *capcompute.Program) Artifact {
	a.image = image
	return a
}

// Schema is one declared JSON Schema: the document as the program declared it,
// normalized, and its compiled form. Both are needed and neither is derivable
// from the other: the compiled schema validates payloads, while the document is
// what a caller is shown and what the spawn ADT embeds verbatim for the
// processor Validator to enforce (a compiled schema cannot be turned back into
// its source). A zero Schema has a document but no compiled form only if it was
// built by hand rather than by PrepareSchema; both validators refuse it rather
// than panicking.
type Schema struct {
	Document json.RawMessage
	compiled *jsonschema.Schema
}

// Validate checks a payload against this schema with the string-first rule: text
// that satisfies the schema as a plain string value is valid (the conversational
// case); otherwise the text must parse as JSON and the parsed value must satisfy
// the schema (the structured case).
func (s Schema) Validate(text string) error {
	if s.compiled == nil {
		return fmt.Errorf("%w: schema is not compiled", errs.Invalid)
	}
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

// ValidateJSON checks a JSON document against this schema, without the
// string-first rule — for payloads that are structured by construction (a
// capability's arguments) rather than a program's conversational text. Empty
// input is checked as JSON null, so a schema that requires fields rejects it.
func (s Schema) ValidateJSON(raw json.RawMessage) error {
	if s.compiled == nil {
		return fmt.Errorf("%w: schema is not compiled", errs.Invalid)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("null")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	return s.compiled.Validate(value)
}

// DigestOf returns the sha256 of a program's wasm bytes — the integrity hash the
// runtime hands the wasm engine.
func DigestOf(wasm []byte) string {
	sum := sha256.Sum256(wasm)
	return hex.EncodeToString(sum[:])
}

// ShortDigest abbreviates an identity for an error message.
func ShortDigest(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}

// Identity is a program's content identity: the digest a process is bound to. It
// covers the wasm bytes and both normalized schema documents, because those are
// the program's contract — changing the code or a declared schema is a new
// program, and a process created under the old identity is stranded (a
// legitimate audit target never runs under a changed contract). The description
// is not part of it: rewording what a program is for changes nothing about what
// it accepts or returns, so it must not strand anything. The schemas are hashed
// normalized, so reformatting the manifest they were loaded from is not a
// program change either. The wasm's own digest (DigestOf) stays the bytes'
// integrity hash.
func Identity(sourceCode []byte, input, output Schema) string {
	identity := sha256.New()
	// Each part enters as its own fixed-width sum, so no shuffling of bytes
	// between the parts can collide.
	for _, part := range [][]byte{sourceCode, input.Document, output.Document} {
		sum := sha256.Sum256(part)
		identity.Write(sum[:])
	}
	return hex.EncodeToString(identity.Sum(nil))
}

// Load prepares the data an app supplied into a registrable program: check the
// id and the bytes, normalize and validate the declared interface, compile its
// schemas, and pin the identity over code and contract. No wasm execution — the
// interface is data the app supplies, not something the program computes. The
// bytes stay with the caller, which compiles them into the image (WithImage).
func Load(data Data) (Artifact, error) {
	id := strings.TrimSpace(data.ID)
	if id == "" || len(data.SourceCode) == 0 {
		return Artifact{}, fmt.Errorf("%w: program id and wasm bytes are required", errs.Invalid)
	}
	description := strings.TrimSpace(data.Description)
	if description == "" {
		return Artifact{}, fmt.Errorf("%w: program %q interface: a description is required", errs.Invalid, id)
	}
	input, err := PrepareSchema("input", data.Input)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, id, err)
	}
	output, err := PrepareSchema("output", data.Output)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, id, err)
	}
	return Artifact{
		ID:          id,
		Digest:      Identity(data.SourceCode, input, output),
		Description: description,
		Input:       input,
		Output:      output,
	}, nil
}

// PrepareSchema turns one declared schema document into a Schema: required,
// compacted — so a program's identity turns on what the schema says and not on
// how it was laid out — and compiled, ready to validate against.
func PrepareSchema(what string, document json.RawMessage) (Schema, error) {
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

// Registry is the runtime's set of registered programs. It is mutable (programs
// are added and removed at runtime via Runtime.AddProgram / RemoveProgram) and
// guards its own state with an RWMutex, because it is read on paths that do not
// hold the Runtime mutex (e.g. CreateSession). It holds no default: a process
// names the program it runs.
type Registry struct {
	mu       sync.RWMutex
	programs map[string]Artifact
}

func NewRegistry() *Registry {
	return &Registry{programs: make(map[string]Artifact)}
}

// Resolve resolves a program id to its registered program. Load took the
// registry's own copy of the schema documents and nothing mutates them
// afterwards, so the returned value shares them.
func (r *Registry) Resolve(id string) (Artifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	program, ok := r.programs[strings.TrimSpace(id)]
	if !ok {
		return Artifact{}, fmt.Errorf("%w: program %q is not registered", errs.Invalid, id)
	}
	return program, nil
}

// ValidateInput checks a process input against the program's declared input
// schema.
func (r *Registry) ValidateInput(id, input string) error {
	program, err := r.Resolve(id)
	if err != nil {
		return err
	}
	if err := program.Input.Validate(input); err != nil {
		return fmt.Errorf("%w: input rejected by program %q input schema: %v", errs.Invalid, program.ID, err)
	}
	return nil
}

// ValidateOutput checks a process answer against the program's declared output
// schema.
func (r *Registry) ValidateOutput(id, answer string) error {
	program, err := r.Resolve(id)
	if err != nil {
		return err
	}
	if err := program.Output.Validate(answer); err != nil {
		return fmt.Errorf("%w: answer rejected by program %q output schema: %v", errs.Invalid, program.ID, err)
	}
	return nil
}

// AnswerValidator returns the sys.output validation hook for one program.
func (r *Registry) AnswerValidator(id string) func(string) error {
	return func(answer string) error { return r.ValidateOutput(id, answer) }
}

// List returns every registered program, ordered by id.
func (r *Registry) List() []Artifact {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Artifact, 0, len(r.programs))
	for _, program := range r.programs {
		out = append(out, program)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Add registers a completed program (built by Load, with its image attached).
// Registering an id that is already taken is refused — a program is replaced by
// removing it first, which settles the processes bound to it — except when the
// identity is identical, which is a no-op so a control plane can re-assert its
// desired set without disturbing anything.
func (r *Registry) Add(program Artifact) (added bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, taken := r.programs[program.ID]; taken {
		if existing.Digest == program.Digest {
			return false, nil
		}
		return false, fmt.Errorf("%w: program %q is registered with a different identity (%s); remove it first",
			errs.Conflict, program.ID, ShortDigest(existing.Digest))
	}
	r.programs[program.ID] = program
	return true, nil
}

// Remove unregisters a program and hands it back, so the caller can release the
// compiled image it holds. ok is false when the id was not registered.
func (r *Registry) Remove(id string) (removed Artifact, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed, ok = r.programs[id]
	if !ok {
		return Artifact{}, false
	}
	delete(r.programs, id)
	return removed, true
}

// Drain empties the registry and returns everything it held, for shutdown.
func (r *Registry) Drain() []Artifact {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Artifact, 0, len(r.programs))
	for id, program := range r.programs {
		out = append(out, program)
		delete(r.programs, id)
	}
	return out
}
