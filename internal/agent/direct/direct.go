package direct

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

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/compiler"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/process"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type ProgramID interface {
	comparable
	fmt.Stringer
}

type ProcessEntry interface {
	ArtifactDigest() string
	SourceCodeDigest() string
}

type Data[T ProgramID] struct {
	ID          T
	SourceCode  []byte
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

type Digest struct {
	ArtifactDigest   string
	SourceCodeDigest string
}

func load[T ProgramID](ctx context.Context, compiler compiler.Compiler, data Data[T]) (artifact[T], error) {
	description := strings.TrimSpace(data.Description)
	if description == "" {
		return artifact[T]{}, fmt.Errorf("%w: program %q interface: a description is required", errs.Invalid, data.ID)
	}
	input, err := prepareSchema("input", data.Input)
	if err != nil {
		return artifact[T]{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, data.ID, err)
	}
	output, err := prepareSchema("output", data.Output)
	if err != nil {
		return artifact[T]{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, data.ID, err)
	}
	image, err := compiler.Compile(ctx, data.ID.String(), data.SourceCode)
	if err != nil {
		return artifact[T]{}, err
	}
	return artifact[T]{
		ID:               data.ID,
		ArtifactDigest:   artifactDigest(data.SourceCode, input, output),
		SourceCodeDigest: sourceCodeDigest(data.SourceCode),
		Description:      description,
		Input:            input,
		Output:           output,
		Image:            image,
	}, nil
}

func artifactDigest(sourceCode []byte, input, output schema) string {
	identity := sha256.New()
	for _, part := range [][]byte{sourceCode, input.Document, output.Document} {
		sum := sha256.Sum256(part)
		identity.Write(sum[:])
	}
	return hex.EncodeToString(identity.Sum(nil))
}

func sourceCodeDigest(sourceCode []byte) string {
	identity := sha256.New()
	sum := sha256.Sum256(sourceCode)
	identity.Write(sum[:])
	return hex.EncodeToString(identity.Sum(nil))
}

// View is what a caller may see of a registered program: its identity and the
// interface it declared. The compiled schemas and the wasm image stay here.
type View[T ProgramID] struct {
	ID          T
	Digest      Digest
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

func (a artifact[T]) view() View[T] {
	return View[T]{
		ID:          a.ID,
		Digest:      Digest{ArtifactDigest: a.ArtifactDigest, SourceCodeDigest: a.SourceCodeDigest},
		Description: a.Description,
		Input:       a.Input.Document,
		Output:      a.Output.Document,
	}
}

type artifact[T ProgramID] struct {
	ID               T
	ArtifactDigest   string
	SourceCodeDigest string
	Description      string
	Input            schema
	Output           schema
	Image            *capcompute.Program
}

type schema struct {
	Document json.RawMessage
	compiled *jsonschema.Schema
}

func (s schema) validate(text string) error {
	if s.compiled == nil {
		return fmt.Errorf("%w: schema is not compiled", errs.Invalid)
	}
	if err := s.compiled.Validate(text); err == nil {
		return nil
	}
	return s.validateJSON(json.RawMessage(text))
}

func (s schema) validateJSON(raw json.RawMessage) error {
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

func prepareSchema(what string, document json.RawMessage) (schema, error) {
	if len(bytes.TrimSpace(document)) == 0 {
		return schema{}, fmt.Errorf("an %s schema is required", what)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, document); err != nil {
		return schema{}, fmt.Errorf("%s schema: %w", what, err)
	}
	s := schema{Document: json.RawMessage(buf.Bytes())}
	compiled, err := compileDocument(what, s.Document)
	if err != nil {
		return schema{}, err
	}
	s.compiled = compiled
	return s, nil
}

func compileDocument(what string, raw json.RawMessage) (*jsonschema.Schema, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("an %s schema is required", what)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%s schema: %w", what, err)
	}
	schemaCompiler := jsonschema.NewCompiler()
	if err := schemaCompiler.AddResource(what+".json", doc); err != nil {
		return nil, fmt.Errorf("%s schema: %w", what, err)
	}
	schema, err := schemaCompiler.Compile(what + ".json")
	if err != nil {
		return nil, fmt.Errorf("%s schema: %w", what, err)
	}
	return schema, nil
}

type Registry[T ProgramID, P ProcessEntry] interface {
	Add(ctx context.Context, data Data[T]) (Digest, error)
	Exists(id T) bool
	Get(id T) (View[T], bool)
	List() []View[T]
	// Remove unregisters a program and hands back the release of its image.
	// Unregistering and releasing are two steps because the caller settles the
	// processes bound to it in between: nothing can spawn once the id is gone,
	// and the image must outlive the ones still unwinding.
	Remove(id T) (release func(context.Context) error, ok bool)
	ValidateInput(id T, input string) error
	ValidateOutput(id T, answer string) error
	Close(ctx context.Context) []error
	Spawn(ctx context.Context, id T, processEntry P, mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error)) (process.Handle, error)
}

type registryImpl[T ProgramID, P ProcessEntry] struct {
	mu       sync.RWMutex
	programs map[T]artifact[T]
	compiler compiler.Compiler
}

func NewRegistry[T ProgramID, P ProcessEntry](memoryPages uint32) Registry[T, P] {
	return &registryImpl[T, P]{programs: make(map[T]artifact[T]), compiler: compiler.New(memoryPages)}
}

func (a *registryImpl[T, P]) Add(ctx context.Context, data Data[T]) (Digest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, taken := a.programs[data.ID]; taken {
		return Digest{}, fmt.Errorf("%w: program %q is already registered with identity %s; remove it first",
			errs.Conflict, data.ID, existing.ArtifactDigest)
	}
	art, err := load(ctx, a.compiler, data)
	if err != nil {
		return Digest{}, err
	}
	a.programs[data.ID] = art
	return Digest{ArtifactDigest: art.ArtifactDigest, SourceCodeDigest: art.SourceCodeDigest}, nil
}

func (a *registryImpl[T, P]) Exists(id T) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.programs[id]
	return ok
}

func (a *registryImpl[T, P]) Get(id T) (View[T], bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	art, ok := a.programs[id]
	if !ok {
		return View[T]{}, false
	}
	return art.view(), true
}

func (a *registryImpl[T, P]) List() []View[T] {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]View[T], 0, len(a.programs))
	for _, art := range a.programs {
		out = append(out, art.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out
}

func (a *registryImpl[T, P]) Remove(id T) (func(context.Context) error, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	art, ok := a.programs[id]
	if !ok {
		return nil, false
	}
	delete(a.programs, id)
	return art.Image.Close, true
}

func (a *registryImpl[T, P]) ValidateInput(id T, input string) error {
	return a.validate(id, "input", input, func(art artifact[T]) schema { return art.Input })
}

func (a *registryImpl[T, P]) ValidateOutput(id T, answer string) error {
	return a.validate(id, "output", answer, func(art artifact[T]) schema { return art.Output })
}

func (a *registryImpl[T, P]) validate(id T, what, text string, pick func(artifact[T]) schema) error {
	a.mu.RLock()
	art, ok := a.programs[id]
	a.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: program %q does not exist", errs.NotFound, id)
	}
	if err := pick(art).validate(text); err != nil {
		return fmt.Errorf("%w: %s rejected by program %q %s schema: %v", errs.Invalid, what, id, what, err)
	}
	return nil
}

func (a *registryImpl[T, P]) Close(ctx context.Context) []error {
	a.mu.Lock()
	defer a.mu.Unlock()
	errors := make([]error, 0, len(a.programs))
	for proc, program := range a.programs {
		err := program.Image.Close(ctx)
		if err != nil {
			errors = append(errors, err)
		}
		delete(a.programs, proc)
	}
	return errors
}

func (a *registryImpl[T, P]) Spawn(ctx context.Context, id T, processEntry P, mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error)) (process.Handle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if art, ok := a.programs[id]; ok {
		if art.ArtifactDigest != processEntry.ArtifactDigest() || art.SourceCodeDigest != processEntry.SourceCodeDigest() {
			return nil, fmt.Errorf("digest for program %s don't match", id.String())
		}
		return process.Spawn[P](ctx, processEntry, art.Image, mkDispatcher)
	}

	return nil, fmt.Errorf("%w: program %q does not exist", errs.NotFound, id)
}
