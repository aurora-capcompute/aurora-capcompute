package agent

// The registered programs, as the runtime tracks them. Schemas are documents
// here; compiling and enforcing them is direct's, by program id.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
)

type ProgramID string

func (p ProgramID) String() string { return string(p) }

// ProgramData is a program as an app hands it over: the wasm bytes and the
// interface that ships beside them — a one-line description plus the JSON Schema
// documents of its input message and its answer. Conversational programs declare
// `{"type":"string"}`; structured programs declare object schemas.
type ProgramData = direct.Data[ProgramID]

type Program struct {
	ID          ProgramID
	Digest      direct.Digest
	Description string
	Input       json.RawMessage
	Output      json.RawMessage
}

// programs is the registered set, and the gate: an id removed from here can bind
// no new process, which is what lets RemoveProgram settle the processes still
// running before it releases the image.
type programs struct {
	mu   sync.RWMutex
	byID map[ProgramID]Program
}

func newPrograms() *programs { return &programs{byID: make(map[ProgramID]Program)} }

func (p *programs) resolve(id string) (Program, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	program, ok := p.byID[ProgramID(strings.TrimSpace(id))]
	if !ok {
		return Program{}, fmt.Errorf("%w: program %q is not registered", errs.Invalid, id)
	}
	return program, nil
}

func (p *programs) put(program Program) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[program.ID] = program
}

func (p *programs) remove(id string) (Program, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	trimmed := ProgramID(strings.TrimSpace(id))
	removed, ok := p.byID[trimmed]
	if !ok {
		return Program{}, false
	}
	delete(p.byID, trimmed)
	return removed, true
}

func (p *programs) list() []Program {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Program, 0, len(p.byID))
	for _, program := range p.byID {
		out = append(out, program)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
