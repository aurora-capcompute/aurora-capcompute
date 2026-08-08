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

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type Data struct {
	ID          string
	SourceCode  []byte
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

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
		Digest:      identity(data.SourceCode, input, output),
		Description: description,
		Input:       input,
		Output:      output,
	}, nil
}

func identity(sourceCode []byte, input, output Schema) string {
	identity := sha256.New()
	for _, part := range [][]byte{sourceCode, input.Document, output.Document} {
		sum := sha256.Sum256(part)
		identity.Write(sum[:])
	}
	return hex.EncodeToString(identity.Sum(nil))
}

type Artifact struct {
	ID          string
	Digest      string
	Description string
	Input       Schema
	Output      Schema
	Image       *capcompute.Program
}

type Schema struct {
	Document json.RawMessage
	compiled *jsonschema.Schema
}

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

type Registry struct {
	mu       sync.RWMutex
	programs map[string]Artifact
}

func NewRegistry() *Registry {
	return &Registry{programs: make(map[string]Artifact)}
}

func (a *Registry) Resolve(id string) (Artifact, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	program, ok := a.programs[strings.TrimSpace(id)]
	if !ok {
		return Artifact{}, fmt.Errorf("%w: program %q is not registered", errs.Invalid, id)
	}
	return program, nil
}

func (a *Registry) List() []Artifact {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Artifact, 0, len(a.programs))
	for _, program := range a.programs {
		out = append(out, program)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (a *Registry) Add(program Artifact) (added bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, taken := a.programs[program.ID]; taken {
		if existing.Digest == program.Digest {
			return false, nil
		}
		return false, fmt.Errorf("%w: program %q is registered with a different identity (%s); remove it first",
			errs.Conflict, program.ID, existing.Digest)
	}
	a.programs[program.ID] = program
	return true, nil
}

func (a *Registry) Remove(id string) (removed Artifact, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	removed, ok = a.programs[id]
	if !ok {
		return Artifact{}, false
	}
	delete(a.programs, id)
	return removed, true
}

func (a *Registry) Drain() []Artifact {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Artifact, 0, len(a.programs))
	for id, program := range a.programs {
		out = append(out, program)
		delete(a.programs, id)
	}
	return out
}
