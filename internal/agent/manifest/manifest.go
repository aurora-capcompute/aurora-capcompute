// Package manifest is the grant tree: what a process may do, declared as data.
//
// A Manifest is one program node — the program it runs plus its granted syscalls
// recursion that makes the whole tree one shape. Validate normalizes a tree and
// refuses one that grants what cannot be served, so an invalid manifest never
// reaches a process.
//
// The package interprets only the fields the runtime owns; a leaf grant's Config
// is opaque here and normalized by whoever serves that syscall, reached through
// the one-method Normalizer this package asks for.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute/sys"
)

const Version = 4

// reservedSyscallPrefix namespaces the processor/runtime syscalls. A manifest may
// grant only the runtime-served members in it (sys.timer, sys.declassify); any
// other sys.* leaf grant is refused so a driver cannot shadow a protocol call.
const reservedSyscallPrefix = "sys."

// The runtime-served syscalls a manifest may grant. Both live in the sys
// namespace because they are the runtime's own, not leaf I/O drivers:
// TimerSyscall yields the durable timer tasks, and DeclassifySyscall lets a
// program request a taint lift (the only governed way out of a flow label):
// granting it is opt-in per program, and every crossing still requires human
// approval and is journaled — the guest can request, never self-lift.
const (
	TimerSyscall      = sys.SyscallTimer
	DeclassifySyscall = sys.SyscallDeclassify
)

// TimerSettings is the Config shape of a sys.timer grant.
type TimerSettings struct {
	// MaxDurationMS bounds the requested duration (0 = a default of 24h).
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
}

// Manifest is one process node: Program names it and Syscalls is its grant
// recursion that makes the whole grant tree one shape — carrying no Version
// of its own: the root's governs. A child's failure is a recoverable
// observation to its parent's cognition; a program that must abort on it makes
// the spawn a hard call.
//
// A program node carries two optional context settings, honored wherever the
// program runs — as the root, or spawned as a child — so history and capability
// sharing live in one place per program rather than on the spawning grant.
// Everything else is configuration on the syscall grants.
type Manifest struct {
	Version int    `json:"version,omitempty"`
	Program string `json:"program,omitempty"`
	// History, when false, isolates this program's process from session history:
	// its sys.input omits the history, so it sees only its own input and inherits
	// no taint from a prior run (at the root) or from the parent's session (when
	// spawned). Unset (the default) shares history — the runtime's standing
	// behavior.
	History *bool `json:"history,omitempty"`
	// ShareCapabilities, when false, keeps this program's capability menu off its
	// sys.input: it still holds its granted syscalls, they are merely not
	// advertised (the program calls them directly). Unset (the default) advertises
	// them. (The field is `share_capabilities`, not `capabilities`, since a leaf
	// grant's `capabilities` is its operation list.)
	ShareCapabilities *bool `json:"share_capabilities,omitempty"`
	// BindingRef is an opaque application correlation reference (e.g. the
	// name of the control-plane binding that produced this manifest). The
	// runtime never interprets it.
	BindingRef string    `json:"binding_ref,omitempty"`
	Syscalls   []Syscall `json:"syscalls,omitempty"`
}

// sharesHistory reports whether this program's process inherits session history
// (the default when unset).
func (m Manifest) SharesHistory() bool { return m.History == nil || *m.History }

// sharesCapabilities reports whether this program's capability menu is advertised
// on its sys.input (the default when unset).
func (m Manifest) SharesCapabilities() bool {
	return m.ShareCapabilities == nil || *m.ShareCapabilities
}

// Syscall is one granted syscall — a tagged union discriminated by Syscall. The
// runtime owns two fields: Syscall (which family) and Hidden (dispatchable but
// off the discoverable menu). Everything else is Config: the family's own
// configuration, opaque to the runtime and interpreted by whoever serves the
// syscall — a leaf driver's `capabilities` list and knobs, a sys.timer grant's
// bound. Data-flow policy (labels/taints) lives inside a leaf's `capabilities`
// entries, in Config; the driver enforces it per call.
type Syscall struct {
	Syscall string
	Hidden  bool
	Config  json.RawMessage
}

// runtimeKeys are the grant fields the runtime owns; every other key of a grant
// object is the family's Config.
var runtimeKeys = map[string]struct{}{"syscall": {}, "hidden": {}}

func (s *Syscall) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["syscall"]; ok {
		if err := json.Unmarshal(v, &s.Syscall); err != nil {
			return err
		}
	}
	if v, ok := raw["hidden"]; ok {
		if err := json.Unmarshal(v, &s.Hidden); err != nil {
			return err
		}
	}
	rest := make(map[string]json.RawMessage, len(raw))
	for key, value := range raw {
		if _, runtime := runtimeKeys[key]; !runtime {
			rest[key] = value
		}
	}
	if len(rest) > 0 {
		config, err := json.Marshal(rest)
		if err != nil {
			return err
		}
		s.Config = config
	} else {
		s.Config = nil
	}
	return nil
}

func (s Syscall) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	if len(s.Config) > 0 {
		if err := json.Unmarshal(s.Config, &out); err != nil {
			return nil, err
		}
	}
	out["syscall"], _ = json.Marshal(s.Syscall)
	if s.Hidden {
		out["hidden"], _ = json.Marshal(true)
	}
	return json.Marshal(out)
}

// runtimeServed reports whether the runtime itself serves the granted
// syscall, rather than a driver built by the dispatcher provider.
func (s Syscall) runtimeServed() bool {
	return s.Syscall == TimerSyscall || s.Syscall == DeclassifySyscall
}

// LeafSyscalls returns the node's driver grants. Dispatcher providers build
// these via the registry; the sys.* grants are served by the runtime.
func (m Manifest) LeafSyscalls() []Syscall {
	out := make([]Syscall, 0, len(m.Syscalls))
	for _, s := range m.Syscalls {
		if !s.runtimeServed() {
			out = append(out, s)
		}
	}
	return out
}

// grant returns the node's grant of one syscall, if present. Validation
// guarantees at most one per syscall.
func (m Manifest) Grant(syscall string) (Syscall, bool) {
	for _, s := range m.Syscalls {
		if s.Syscall == syscall {
			return s, true
		}
	}
	return Syscall{}, false
}

// Normalizer canonicalizes one leaf grant's Config — the only thing validation
// needs from whoever serves that syscall. The runtime's dispatcher provider
// satisfies it; asking for just this keeps manifest validation independent of how
// a dispatcher is built, and of the process credential building one needs.
type Normalizer interface {
	Normalize(syscall string, config json.RawMessage) (json.RawMessage, error)
}

// Validate checks and normalizes a manifest tree, returning a clone the caller
// owns. A nil Normalizer is refused: an unnormalized leaf grant is one whose
// authority nobody has checked.
func Validate(spec Manifest, normalizer Normalizer) (Manifest, error) {
	if normalizer == nil {
		return Manifest{}, fmt.Errorf("%w: dispatcher provider is required", errs.Invalid)
	}
	if spec.Version != Version {
		return Manifest{}, fmt.Errorf("%w: manifest version must be %d", errs.Invalid, Version)
	}
	if err := validateNode(&spec, normalizer); err != nil {
		return Manifest{}, err
	}
	// The runtime keeps no default program — a process names the program it runs,
	// the way every spawnable child in the tree does.
	if spec.Program == "" {
		return Manifest{}, fmt.Errorf("%w: a program is required", errs.Invalid)
	}
	return spec.Clone(), nil
}

// validateNode normalizes one manifest node — the root, or a spawnable
func validateNode(node *Manifest, normalizer Normalizer) error {
	node.Program = strings.TrimSpace(node.Program)
	node.BindingRef = strings.TrimSpace(node.BindingRef)
	return validateSyscalls(node.Syscalls, normalizer)
}

// validateSyscalls normalizes a grant set: driver grants against their
// registrations, the runtime-served ones (spawn's programs, the timer's
// bound) in place. Nothing is named, so a syscall may be granted once.
func validateSyscalls(syscalls []Syscall, normalizer Normalizer) error {
	seen := make(map[string]struct{}, len(syscalls))
	for i := range syscalls {
		grant := &syscalls[i]
		grant.Syscall = strings.TrimSpace(grant.Syscall)
		if grant.Syscall == "" {
			return fmt.Errorf("%w: grant %d: a syscall is required", errs.Invalid, i)
		}
		// The sys.* namespace belongs to the processor and the runtime. A manifest
		// may grant only its two runtime-served members (sys.timer, sys.declassify);
		// every other sys.* name is a reserved protocol call (sys.input/output/
		// log/now/random/abort/declassify/begin/commit). Granting one
		// as a leaf would hand it to a driver, which could then shadow the
		// runtime's own protocol capability — so it is refused up front, the way
		// the reserved "syscall:" label namespace is (sys.NormalizeLabels).
		if strings.HasPrefix(grant.Syscall, reservedSyscallPrefix) && !grant.runtimeServed() {
			return fmt.Errorf("%w: syscall %q is in the reserved %q namespace and may not be granted", errs.Invalid, grant.Syscall, reservedSyscallPrefix)
		}
		if grant.Syscall == TimerSyscall {
			normalized, err := normalizeTimerSettings(grant.Config)
			if err != nil {
				return fmt.Errorf("%w: sys.timer settings: %v", errs.Invalid, err)
			}
			grant.Config = normalized
		} else if grant.Syscall == DeclassifySyscall {
			// Runtime-served by the processor Declassifier; the grant is a bare opt-in,
			// carrying no settings and no programs. Its authority is fully gated at
			// dispatch by the mandatory human approval.
			if len(bytes.TrimSpace(grant.Config)) > 0 {
				return fmt.Errorf("%w: %s takes no settings", errs.Invalid, DeclassifySyscall)
			}
			grant.Config = nil
		} else {
			normalized, err := normalizer.Normalize(grant.Syscall, grant.Config)
			if err != nil {
				return fmt.Errorf("%w: syscall %q config: %v", errs.Invalid, grant.Syscall, err)
			}
			grant.Config = append(json.RawMessage(nil), normalized...)
		}
		if _, exists := seen[grant.Syscall]; exists {
			return fmt.Errorf("%w: duplicate syscall %q", errs.Invalid, grant.Syscall)
		}
		seen[grant.Syscall] = struct{}{}
	}
	return nil
}

// normalizeTimerSettings validates a sys.timer grant's bound and returns its
// canonical form (nil when none). Unknown fields are rejected.
func normalizeTimerSettings(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var settings TimerSettings
	if err := decoder.Decode(&settings); err != nil {
		return nil, err
	}
	if settings.MaxDurationMS < 0 {
		return nil, fmt.Errorf("max_duration_ms must not be negative")
	}
	if settings.MaxDurationMS == 0 {
		return nil, nil
	}
	return json.Marshal(settings)
}

// Clone deep-copies a manifest's pointer fields, so a caller that retains the
// input manifest (or reuses one across CreateProcess calls) cannot later flip a
// stored clone's history/share_capabilities out from under a running process.
func (m Manifest) Clone() Manifest {
	out := m
	out.History = cloneBoolPtr(m.History)
	out.ShareCapabilities = cloneBoolPtr(m.ShareCapabilities)
	out.Syscalls = cloneSyscalls(m.Syscalls)
	return out
}

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneSyscalls(syscalls []Syscall) []Syscall {
	if len(syscalls) == 0 {
		return nil
	}
	out := make([]Syscall, len(syscalls))
	for i, grant := range syscalls {
		out[i] = grant
		out[i].Config = append(json.RawMessage(nil), grant.Config...)
	}
	return out
}
