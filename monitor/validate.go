package monitor

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/aurora-capcompute/capcompute/sys"
)

// GrantSource reports the capabilities granted to a cred. The app supplies
// where grants live (the manifest, a policy store); the Validator supplies
// the enforcement.
type GrantSource[K any] func(cred K) []sys.Capability

// Validator is the reference-monitor decorator: complete mediation for the
// dispatcher chain behind it (kernel law #4). Before delegating it checks
// (1) the cred's grant set contains the syscall name — otherwise ErrnoDenied —
// and (2) the args validate against the granted capability's InputSchema —
// otherwise ErrnoInvalidArgs. Reserved control syscalls (sys.begin/sys.commit)
// pass through: they are kernel markers, not capabilities.
//
// Policy refusals are results (StatusFailed), not Go errors: the guest sees a
// classified errno and can react; the process does not crash.
type Validator[K any] struct {
	grants GrantSource[K]
	next   sys.Dispatcher[K]

	mu      sync.Mutex
	schemas map[string]*jsonschema.Schema // keyed by raw schema bytes
}

// NewValidator wraps next so every dispatch is checked against the cred's
// grant set and the capability's input schema.
func NewValidator[K any](grants GrantSource[K], next sys.Dispatcher[K]) *Validator[K] {
	return &Validator[K]{
		grants:  grants,
		next:    next,
		schemas: make(map[string]*jsonschema.Schema),
	}
}

func (v *Validator[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit:
		return v.next.Dispatch(ctx, cred, syscall, auth)
	}

	granted, ok := sys.FindCapability(v.grants(cred), syscall.Name)
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

func (v *Validator[K]) Capabilities() []sys.Capability {
	return v.next.Capabilities()
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
