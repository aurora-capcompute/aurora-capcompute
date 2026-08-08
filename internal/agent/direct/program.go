package direct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/compiler"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type Proc interface {
	ID() string
	comparable
}

type Data[T Proc] struct {
	proc        T
	SourceCode  []byte
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

func load[T Proc](ctx context.Context, compiler *compiler.Compiler, data Data[T]) (artifact[T], error) {
	description := strings.TrimSpace(data.Description)
	if description == "" {
		return artifact[T]{}, fmt.Errorf("%w: program %q interface: a description is required", errs.Invalid, data.proc.ID())
	}
	input, err := prepareSchema("input", data.Input)
	if err != nil {
		return artifact[T]{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, data.proc.ID, err)
	}
	output, err := prepareSchema("output", data.Output)
	if err != nil {
		return artifact[T]{}, fmt.Errorf("%w: program %q interface: %v", errs.Invalid, data.proc.ID(), err)
	}
	image, err := compiler.Compile(ctx, data.proc.ID(), data.SourceCode)
	if err != nil {
		return artifact[T]{}, err
	}
	return artifact[T]{
		Proc:        data.proc,
		Digest:      identity(data.SourceCode, input, output),
		Description: description,
		Input:       input,
		Output:      output,
		Image:       image,
	}, nil
}

func identity(sourceCode []byte, input, output schema) string {
	identity := sha256.New()
	for _, part := range [][]byte{sourceCode, input.Document, output.Document} {
		sum := sha256.Sum256(part)
		identity.Write(sum[:])
	}
	return hex.EncodeToString(identity.Sum(nil))
}

type artifact[T Proc] struct {
	Proc        T
	Digest      string
	Description string
	Input       schema
	Output      schema
	Image       *capcompute.Program
}

type schema struct {
	Document json.RawMessage
	compiled *jsonschema.Schema
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

type Registry[T Proc] struct {
	mu       sync.RWMutex
	programs map[T]artifact[T]
	compiler *compiler.Compiler
}

func NewRegistry[T Proc]() *Registry[T] {
	return &Registry[T]{programs: make(map[T]artifact[T])}
}

func (a *Registry[T]) Add(ctx context.Context, data Data[T]) (added bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, taken := a.programs[data.proc]; taken {
		return false, fmt.Errorf("%w: program %q is already registered; remove it first",
			errs.Conflict, data.proc.ID, existing.Digest)
	}
	art, err := load(ctx, a.compiler, data)
	if err != nil {
		return false, err
	}
	a.programs[data.proc] = art
	return true, nil
}

func (a *Registry[T]) Remove(proc T) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.programs[proc]
	if !ok {
		return false
	}
	delete(a.programs, proc)
	return true
}

func (a *Registry[T]) Close(ctx context.Context) []error {
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
