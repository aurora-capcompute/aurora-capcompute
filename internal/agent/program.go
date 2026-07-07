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

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/wire"

	extism "github.com/extism/go-sdk"
)

const DefaultProgramID = "aurora-default@1"

type ProgramSource struct {
	ID   string
	Wasm []byte
}

// ProgramInterface is a program's bundled self-description, extracted from the
// wasm's pure `describe` export at registration: what the process's input
// message must look like and what its answer will look like, each as a JSON
// Schema. Conversational programs declare `{"type":"string"}`; structured
// programs declare object schemas and callers pass/receive JSON text. The
// interface travels inside the wasm, so the program's content digest — and the
// process↔program immutability law — covers it.
type ProgramInterface struct {
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Output      json.RawMessage `json:"output"`
}

type ProgramArtifact struct {
	ID     string `json:"id"`
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

// digestOf returns the canonical content digest recorded for a program's wasm.
func digestOf(wasm []byte) string {
	sum := sha256.Sum256(wasm)
	return hex.EncodeToString(sum[:])
}

// describedProgram is the content-derived half of a registry record: the
// interface a program's bytes declare and the schemas compiled from it.
type describedProgram struct {
	iface  ProgramInterface
	input  *jsonschema.Schema
	output *jsonschema.Schema
}

// interfaceCache memoizes interface extraction by content digest. A program's
// interface is a pure function of its bytes (same wasm → same describe output →
// same schemas), so extracting it — which instantiates the wasm — is done once
// per digest and reused for every later load of those bytes: a runtime restart,
// an artifact removed and re-added, the many runtimes a test binary spins up.
var interfaceCache = struct {
	mu sync.Mutex
	m  map[string]describedProgram
}{m: make(map[string]describedProgram)}

// describe extracts (and caches) a program's interface and compiled schemas for
// the given content digest.
func describe(ctx context.Context, digest string, wasm []byte) (describedProgram, error) {
	interfaceCache.mu.Lock()
	cached, ok := interfaceCache.m[digest]
	interfaceCache.mu.Unlock()
	if ok {
		return cached, nil
	}
	// Extract off-lock: instantiating the wasm is slow, and a duplicate race to
	// describe the same new digest is harmless — both compute the same result.
	iface, err := describeProgram(ctx, wasm)
	if err != nil {
		return describedProgram{}, err
	}
	input, err := compileSchema("input", iface.Input)
	if err != nil {
		return describedProgram{}, fmt.Errorf("interface: %w", err)
	}
	output, err := compileSchema("output", iface.Output)
	if err != nil {
		return describedProgram{}, fmt.Errorf("interface: %w", err)
	}
	described := describedProgram{iface: iface, input: input, output: output}
	interfaceCache.mu.Lock()
	interfaceCache.m[digest] = described
	interfaceCache.mu.Unlock()
	return described, nil
}

// loadProgram builds one registry record: copy the bytes, digest them, extract
// the bundled interface, and compile its schemas — so registration refuses a
// program that cannot describe itself.
func loadProgram(ctx context.Context, id string, wasm []byte) (programRecord, error) {
	wasm = append([]byte(nil), wasm...)
	digest := digestOf(wasm)
	described, err := describe(ctx, digest, wasm)
	if err != nil {
		return programRecord{}, fmt.Errorf("program %q: %w", id, err)
	}
	return programRecord{
		source:   ProgramSource{ID: id, Wasm: wasm},
		artifact: ProgramArtifact{ID: id, Digest: digest, ProgramInterface: described.iface},
		input:    described.input,
		output:   described.output,
	}, nil
}

// describeProgram calls the wasm's `describe` export. The call is pure by
// construction: the syscall import is bound to a stub that refuses, so a
// program that tries to dispatch during describe fails to register.
func describeProgram(ctx context.Context, wasm []byte) (ProgramInterface, error) {
	plugin, err := extism.NewPlugin(ctx, extism.Manifest{
		Wasm: []extism.Wasm{extism.WasmData{Data: wasm}},
	}, extism.PluginConfig{EnableWasi: true}, []extism.HostFunction{describeStub()})
	if err != nil {
		return ProgramInterface{}, fmt.Errorf("instantiate: %w", err)
	}
	defer plugin.Close(context.Background())
	_, out, err := plugin.Call("describe", nil)
	if err != nil {
		return ProgramInterface{}, fmt.Errorf("describe: %w", err)
	}
	var iface ProgramInterface
	if err := json.Unmarshal(out, &iface); err != nil {
		return ProgramInterface{}, fmt.Errorf("decode interface: %w", err)
	}
	iface.Description = strings.TrimSpace(iface.Description)
	if iface.Description == "" {
		return ProgramInterface{}, fmt.Errorf("interface: a description is required")
	}
	return iface, nil
}

// describeStub serves the guest's syscall import during describe with a
// refusal, keeping the call pure without leaving the import unsatisfied.
func describeStub() extism.HostFunction {
	host := extism.NewHostFunctionWithStack(
		"syscall",
		func(_ context.Context, plugin *extism.CurrentPlugin, stack []uint64) {
			offset, err := plugin.WriteBytes(wire.EncodeResponse(wire.Response{
				Abi:     sys.ABIVersion,
				Status:  wire.StatusFailed,
				Code:    string(sys.ErrnoDenied),
				Message: "describe is pure: syscalls are unavailable",
			}))
			if err != nil {
				panic(fmt.Errorf("write describe stub response: %w", err))
			}
			stack[0] = offset
		},
		[]extism.ValueType{extism.ValueTypePTR},
		[]extism.ValueType{extism.ValueTypePTR},
	)
	host.SetNamespace("extism:host/compute")
	return host
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
		record, err := loadProgram(ctx, id, source.Wasm)
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
	return source, nil
}

// ValidateInput checks a process input message against the program's declared
// input schema.
func (r *loadedPrograms) ValidateInput(id, message string) error {
	record, err := r.record(id)
	if err != nil {
		return err
	}
	if err := validateText(record.input, message); err != nil {
		return fmt.Errorf("%w: message rejected by program %q input schema: %v", ErrInvalid, record.artifact.ID, err)
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

// Interface returns a registered program's bundled interface, if it is loaded.
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
