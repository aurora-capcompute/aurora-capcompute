package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

const ManifestVersion = 4

// The runtime-served syscalls a manifest may grant. Both live in the sys
// namespace because they are the runtime's own, not leaf I/O drivers:
// SpawnSyscall's grant carries Programs — the manifests of the only programs
// this process may spawn, each with its own recursive grant set — and
// TimerSyscall yields the durable timer tasks the runtime itself leans on
// for abort-retry parks.
const (
	SpawnSyscall = sys.SyscallSpawn
	TimerSyscall = sys.SyscallTimer
)

// TimerSettings is the Config shape of a sys.timer grant.
type TimerSettings struct {
	// MaxDurationMS bounds the requested duration (0 = a default of 24h).
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
}

// SpawnSettings is the Config shape of a sys.spawn grant: it gates what a
// spawned child inherits in its sys.input. History controls whether the child
// sees the session history; ShareCapabilities controls whether the child's own
// capability menu is advertised to it. Both default to true (shared, the
// runtime's standing behavior) when omitted — set false to spawn an isolated
// child that sees only its input. The grants themselves are unaffected: a
// child with ShareCapabilities:false still holds its granted syscalls, they are
// merely off its discoverable menu. (The field is `share_capabilities`, not
// `capabilities`, since a leaf grant's `capabilities` is its operation list.)
type SpawnSettings struct {
	History           *bool `json:"history,omitempty"`
	ShareCapabilities *bool `json:"share_capabilities,omitempty"`
}

// shareHistory reports whether a spawned child inherits the session history
// (the default when unset).
func (s SpawnSettings) shareHistory() bool { return s.History == nil || *s.History }

// shareCapabilities reports whether a spawned child's capability menu is
// advertised on its sys.input (the default when unset).
func (s SpawnSettings) shareCapabilities() bool {
	return s.ShareCapabilities == nil || *s.ShareCapabilities
}

// Manifest is one process node: Program names it and Syscalls is its grant
// set. A spawnable child inside a sys.spawn grant is itself a Manifest — the
// recursion that makes the whole grant tree one shape — carrying no Version
// of its own: the root's governs. A child's failure is a recoverable
// observation to its parent's cognition; a program that must abort on it makes
// the spawn a hard call. A program node carries no persona and no settings: a
// process runs on exactly the input its interface declares, and the only
// configuration lives on the syscall grants.
type Manifest struct {
	Version int    `json:"version,omitempty"`
	Program string `json:"program,omitempty"`
	// BindingRef is an opaque application correlation reference (e.g. the
	// name of the control-plane binding that produced this manifest). The
	// runtime never interprets it.
	BindingRef string    `json:"binding_ref,omitempty"`
	Syscalls   []Syscall `json:"syscalls,omitempty"`
}

// Syscall is one granted syscall — a tagged union discriminated by Syscall. The
// runtime owns three fields: Syscall (which family), Hidden (dispatchable but
// off the discoverable menu), and Programs (a sys.spawn grant's spawnable
// children, each a recursive Manifest). Everything else is Config: the family's
// own configuration, opaque to the runtime and interpreted by whoever serves the
// syscall — a leaf driver's `capabilities` list and knobs, a sys.spawn grant's
// context-sharing settings, a sys.timer grant's bound. Data-flow policy
// (labels/taints) lives inside a leaf's `capabilities` entries, in Config; the
// driver enforces it per call.
type Syscall struct {
	Syscall  string
	Hidden   bool
	Programs []Manifest
	Config   json.RawMessage
}

// runtimeKeys are the grant fields the runtime owns; every other key of a grant
// object is the family's Config.
var runtimeKeys = map[string]struct{}{"syscall": {}, "hidden": {}, "programs": {}}

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
	if v, ok := raw["programs"]; ok {
		if err := json.Unmarshal(v, &s.Programs); err != nil {
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
	if len(s.Programs) > 0 {
		programs, err := json.Marshal(s.Programs)
		if err != nil {
			return nil, err
		}
		out["programs"] = programs
	}
	return json.Marshal(out)
}

// isSpawn reports whether a grant spawns child processes rather than naming
// a leaf I/O driver.
func (s Syscall) isSpawn() bool { return s.Syscall == SpawnSyscall }

// spawnSettings decodes a sys.spawn grant's context-sharing settings (validated
// and canonicalized at manifest time); a grant with no settings shares all.
func (s Syscall) spawnSettings() SpawnSettings {
	var out SpawnSettings
	if len(s.Config) > 0 {
		_ = json.Unmarshal(s.Config, &out)
	}
	return out
}

// runtimeServed reports whether the runtime itself serves the granted
// syscall, rather than a driver built by the dispatcher provider.
func (s Syscall) runtimeServed() bool {
	return s.Syscall == SpawnSyscall || s.Syscall == TimerSyscall
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
func (m Manifest) grant(syscall string) (Syscall, bool) {
	for _, s := range m.Syscalls {
		if s.Syscall == syscall {
			return s, true
		}
	}
	return Syscall{}, false
}

type DispatcherProvider interface {
	Normalize(syscall string, config json.RawMessage) (json.RawMessage, error)
	NewDispatcher(context.Context, ProcessContext, Manifest) (sys.Dispatcher[ProcessContext], error)
}

func ValidateManifest(manifest Manifest, provider DispatcherProvider) (Manifest, error) {
	if provider == nil {
		return Manifest{}, fmt.Errorf("%w: dispatcher provider is required", ErrInvalid)
	}
	if manifest.Version != ManifestVersion {
		return Manifest{}, fmt.Errorf("%w: manifest version must be %d", ErrInvalid, ManifestVersion)
	}
	if err := validateNode(&manifest, provider); err != nil {
		return Manifest{}, err
	}
	return cloneManifest(manifest), nil
}

// validateNode normalizes one manifest node — the root, or a spawnable
// program inside a sys.spawn grant — and recurses into its grant set.
func validateNode(node *Manifest, provider DispatcherProvider) error {
	node.Program = strings.TrimSpace(node.Program)
	node.BindingRef = strings.TrimSpace(node.BindingRef)
	return validateSyscalls(node.Syscalls, provider)
}

// validateSyscalls normalizes a grant set: driver grants against their
// registrations, the runtime-served ones (spawn's programs, the timer's
// bound) in place. Nothing is named, so a syscall may be granted once.
func validateSyscalls(syscalls []Syscall, provider DispatcherProvider) error {
	seen := make(map[string]struct{}, len(syscalls))
	for i := range syscalls {
		grant := &syscalls[i]
		grant.Syscall = strings.TrimSpace(grant.Syscall)
		if grant.Syscall == "" {
			return fmt.Errorf("%w: grant %d: a syscall is required", ErrInvalid, i)
		}
		if grant.isSpawn() {
			if len(grant.Programs) == 0 {
				return fmt.Errorf("%w: %s requires at least one program", ErrInvalid, SpawnSyscall)
			}
			normalized, err := normalizeSpawnSettings(grant.Config)
			if err != nil {
				return fmt.Errorf("%w: %s settings: %v", ErrInvalid, SpawnSyscall, err)
			}
			grant.Config = normalized
			programs := make(map[string]struct{}, len(grant.Programs))
			for j := range grant.Programs {
				child := &grant.Programs[j]
				if child.Version != 0 {
					return fmt.Errorf("%w: spawnable program %d carries a version; the root's governs", ErrInvalid, j)
				}
				if err := validateNode(child, provider); err != nil {
					return fmt.Errorf("spawnable program %d: %w", j, err)
				}
				if child.Program == "" {
					return fmt.Errorf("%w: spawnable program %d requires a program", ErrInvalid, j)
				}
				if _, dup := programs[child.Program]; dup {
					return fmt.Errorf("%w: duplicate spawnable program %q", ErrInvalid, child.Program)
				}
				programs[child.Program] = struct{}{}
			}
		} else if grant.Syscall == TimerSyscall {
			normalized, err := normalizeTimerSettings(grant.Config)
			if err != nil {
				return fmt.Errorf("%w: sys.timer settings: %v", ErrInvalid, err)
			}
			grant.Config = normalized
		} else {
			if len(grant.Programs) > 0 {
				return fmt.Errorf("%w: syscall %q: only %s carries programs", ErrInvalid, grant.Syscall, SpawnSyscall)
			}
			normalized, err := provider.Normalize(grant.Syscall, grant.Config)
			if err != nil {
				return fmt.Errorf("%w: syscall %q config: %v", ErrInvalid, grant.Syscall, err)
			}
			grant.Config = append(json.RawMessage(nil), normalized...)
		}
		if _, exists := seen[grant.Syscall]; exists {
			return fmt.Errorf("%w: duplicate syscall %q", ErrInvalid, grant.Syscall)
		}
		seen[grant.Syscall] = struct{}{}
	}
	return nil
}

// normalizeSpawnSettings validates a sys.spawn grant's settings and returns
// their canonical form (nil when none). Unknown fields are rejected so a typo
// (e.g. "capabilites") surfaces at manifest time rather than silently sharing
// everything.
func normalizeSpawnSettings(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var settings SpawnSettings
	if err := decoder.Decode(&settings); err != nil {
		return nil, err
	}
	if settings.History == nil && settings.ShareCapabilities == nil {
		return nil, nil
	}
	return json.Marshal(settings)
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

func cloneManifest(manifest Manifest) Manifest {
	out := manifest
	out.Syscalls = cloneSyscalls(manifest.Syscalls)
	return out
}

func cloneSyscalls(syscalls []Syscall) []Syscall {
	if len(syscalls) == 0 {
		return nil
	}
	out := make([]Syscall, len(syscalls))
	for i, grant := range syscalls {
		out[i] = grant
		out[i].Config = append(json.RawMessage(nil), grant.Config...)
		if len(grant.Programs) > 0 {
			out[i].Programs = make([]Manifest, len(grant.Programs))
			for j, child := range grant.Programs {
				out[i].Programs[j] = cloneManifest(child)
			}
		}
	}
	return out
}
