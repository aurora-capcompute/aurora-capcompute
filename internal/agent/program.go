package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const DefaultProgramID = "aurora-default@1"

type ProgramSource struct {
	ID   string
	Wasm []byte
}

type ProgramArtifact struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type ProgramProvider interface {
	DefaultID() string
	List(context.Context) ([]ProgramSource, error)
}

// loadedPrograms is the runtime's program registry. It is mutable (programs can be
// added, replaced, or removed at runtime via Runtime.SetPrograms) and guards its
// own state with an RWMutex, because it is read on paths that do not hold the
// Runtime mutex (e.g. CreateSession).
type loadedPrograms struct {
	mu        sync.RWMutex
	defaultID string
	sources   map[string]ProgramSource
	artifacts map[string]ProgramArtifact
}

// digestOf returns the canonical content digest recorded for a program's wasm.
func digestOf(wasm []byte) string {
	sum := sha256.Sum256(wasm)
	return hex.EncodeToString(sum[:])
}

// loadPrograms snapshots the provider into a registry. A nil provider or an empty
// program list yields an empty registry (no default): the runtime then boots with
// no program and program processes fail with a clear error until one is registered. When
// the provider lists at least one program, its declared default must be present.
func loadPrograms(ctx context.Context, provider ProgramProvider) (*loadedPrograms, error) {
	loaded := &loadedPrograms{
		sources:   make(map[string]ProgramSource),
		artifacts: make(map[string]ProgramArtifact),
	}
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
		if _, exists := loaded.sources[id]; exists {
			return nil, fmt.Errorf("%w: duplicate program %q", ErrInvalid, id)
		}
		wasm := append([]byte(nil), source.Wasm...)
		loaded.sources[id] = ProgramSource{ID: id, Wasm: wasm}
		loaded.artifacts[id] = ProgramArtifact{ID: id, Digest: digestOf(wasm)}
	}
	if len(loaded.sources) > 0 {
		defaultID := strings.TrimSpace(provider.DefaultID())
		if defaultID == "" {
			return nil, fmt.Errorf("%w: default program id is required", ErrInvalid)
		}
		if _, ok := loaded.sources[defaultID]; !ok {
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

func (r *loadedPrograms) Resolve(id string) (ProgramArtifact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if strings.TrimSpace(id) == "" {
		id = r.defaultID
	}
	if id == "" {
		return ProgramArtifact{}, fmt.Errorf("%w: no program registered", ErrInvalid)
	}
	artifact, ok := r.artifacts[id]
	if !ok {
		return ProgramArtifact{}, fmt.Errorf("%w: program %q is not registered", ErrInvalid, id)
	}
	return artifact, nil
}

func (r *loadedPrograms) Source(id string) (ProgramSource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if strings.TrimSpace(id) == "" {
		id = r.defaultID
	}
	if id == "" {
		return ProgramSource{}, fmt.Errorf("%w: no program registered", ErrInvalid)
	}
	source, ok := r.sources[id]
	if !ok {
		return ProgramSource{}, fmt.Errorf("%w: program %q is not registered", ErrInvalid, id)
	}
	source.Wasm = append([]byte(nil), source.Wasm...)
	return source, nil
}

func (r *loadedPrograms) List() []ProgramArtifact {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProgramArtifact, 0, len(r.artifacts))
	for _, artifact := range r.artifacts {
		out = append(out, artifact)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// digests returns the current id→digest map, for diffing a desired program set
// against what is registered.
func (r *loadedPrograms) digests() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.artifacts))
	for id, artifact := range r.artifacts {
		out[id] = artifact.Digest
	}
	return out
}

// put registers or replaces a program. The caller has already validated id/wasm.
func (r *loadedPrograms) put(id string, wasm []byte, digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[id] = ProgramSource{ID: id, Wasm: wasm}
	r.artifacts[id] = ProgramArtifact{ID: id, Digest: digest}
	r.recomputeDefaultLocked()
}

// remove unregisters a program.
func (r *loadedPrograms) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sources, id)
	delete(r.artifacts, id)
	r.recomputeDefaultLocked()
}

// recomputeDefaultLocked keeps a stable default: the existing one if it still
// exists, else the lexicographically first registered program, else empty.
func (r *loadedPrograms) recomputeDefaultLocked() {
	if _, ok := r.sources[r.defaultID]; ok && r.defaultID != "" {
		return
	}
	ids := make([]string, 0, len(r.sources))
	for id := range r.sources {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		r.defaultID = ""
		return
	}
	sort.Strings(ids)
	r.defaultID = ids[0]
}
