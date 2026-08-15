package monitor

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Validator is the reference-monitor decorator: complete mediation for the
// dispatcher chain behind it (law #4). Before delegating it checks
// (1) the cred's grant set contains the syscall name — otherwise ErrnoDenied —
// and (2) the args validate against the granted capability's InputSchema —
// otherwise ErrnoInvalidArgs. Reserved control syscalls (sys.begin/sys.commit)
// pass through: they are processor markers, not capabilities.
//
// Policy refusals are results (StatusFailed), not Go errors: the guest sees a
// classified errno and can react; the process does not crash.
type Validator[K any] struct {
	table *capability.Table
	next  sys.Dispatcher[K]

	mu      sync.Mutex
	schemas map[string]*jsonschema.Schema // keyed by raw schema bytes
}

// NewValidator wraps next so every dispatch is checked against the process's
// grant table and the named syscall's input schema. The table is the grant set:
// there is no separate source to keep in step with what the chain was built
// from, because it is what the chain was built from.
func NewValidator[K any](table *capability.Table, next sys.Dispatcher[K]) *Validator[K] {
	return &Validator[K]{
		table:   table,
		next:    next,
		schemas: make(map[string]*jsonschema.Schema),
	}
}

func (v *Validator[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit:
		return v.next.Dispatch(ctx, cred, syscall, auth)
	}

	granted, ok := v.table.Descriptor(syscall.Name)
	if !ok {
		return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf("capability %q is not granted", syscall.Name)), nil
	}

	if len(granted.InputSchema) > 0 {
		schema, err := v.compiled(granted.InputSchema)
		if err != nil {
			// A schema that does not compile is a host configuration bug,
			// not a guest mistake.
			return sys.SyscallResult{}, fmt.Errorf("capability %q input schema: %w", syscall.Name, err)
		}
		args := syscall.Args
		if len(args) == 0 {
			args = []byte("null")
		}
		instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(args))
		if err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode args: %v", err)), nil
		}
		if err := schema.Validate(instance); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("args rejected by %q input schema: %v", syscall.Name, err)), nil
		}
	}

	return v.next.Dispatch(ctx, cred, syscall, auth)
}

func (v *Validator[K]) compiled(raw []byte) (*jsonschema.Schema, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if schema, ok := v.schemas[string(raw)]; ok {
		return schema, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("capability.json", doc); err != nil {
		return nil, err
	}
	schema, err := compiler.Compile("capability.json")
	if err != nil {
		return nil, err
	}
	v.schemas[string(raw)] = schema
	return schema, nil
}
