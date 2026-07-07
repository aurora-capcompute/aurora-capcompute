package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
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

// TimerSettings is the Settings shape of a sys.timer grant.
type TimerSettings struct {
	// MaxDurationMS bounds the requested duration (0 = a default of 24h).
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
}

// SpawnSettings is the Settings shape of a sys.spawn grant: it gates what a
// spawned child inherits in its sys.input. History controls whether the child
// sees the session history; Capabilities controls whether the child's own
// capability menu is advertised to it. Both default to true (shared, the
// runtime's standing behavior) when omitted — set false to spawn an isolated
// child that sees only its input. The grants themselves are unaffected: a
// child with Capabilities:false still holds its granted syscalls, they are
// merely off its discoverable menu.
type SpawnSettings struct {
	History      *bool `json:"history,omitempty"`
	Capabilities *bool `json:"capabilities,omitempty"`
}

// shareHistory reports whether a spawned child inherits the session history
// (the default when unset).
func (s SpawnSettings) shareHistory() bool { return s.History == nil || *s.History }

// shareCapabilities reports whether a spawned child's capability menu is
// advertised on its sys.input (the default when unset).
func (s SpawnSettings) shareCapabilities() bool { return s.Capabilities == nil || *s.Capabilities }

// Manifest is one process node: Program names it and Syscalls is its grant
// set. A spawnable child inside a sys.spawn grant is itself a Manifest — the
// recursion that makes the whole grant tree one shape — carrying no Version
// of its own: the root's governs. A child's failure is a recoverable
// observation to its parent's cognition; a program that must abort on it makes
// the spawn a hard call. A program node carries no persona and no settings: a
// process runs on exactly the input its interface declares, and the only
// configuration lives on the syscall grants (dispatcher constructor settings).
type Manifest struct {
	Version int    `json:"version,omitempty"`
	Program string `json:"program,omitempty"`
	// BindingRef is an opaque application correlation reference (e.g. the
	// name of the control-plane binding that produced this manifest). The
	// runtime never interprets it.
	BindingRef string    `json:"binding_ref,omitempty"`
	Syscalls   []Syscall `json:"syscalls,omitempty"`
}

// Syscall is one granted syscall. The manifest names nothing: a grant says
// which syscall the process gets and how it is configured, and each driver
// publishes its canonical capability names (net.http,
// memory.get/put/list, openai.*) — the runtime-served sys.* grants are their
// own names. A sys.spawn grant carries Programs (its spawnable children) and
// may carry Settings (a SpawnSettings gating what those children inherit).
//
// Labels and Forbid declare this grant's data-flow policy (DIFC): Labels are
// the source classes the grant's results carry ("untrusted_web", "secret") —
// the flow monitor stamps them onto every result and accumulates them into the
// run's taint; Forbid lists labels that may not flow into the grant's calls, so
// a run that has observed a forbidden label is refused before the driver runs.
// Each is a FlowLabels: a flat array applies to every operation the grant
// publishes, or an object targets specific operations by name (memory.put,
// net.http, …). They are declarable only on leaf driver grants — the data I/O —
// not on the runtime-served sys.* grants, which are control, not sources/sinks.
type Syscall struct {
	Syscall  string          `json:"syscall"`
	Settings json.RawMessage `json:"settings,omitempty"`
	Programs []Manifest      `json:"programs,omitempty"`
	Hidden   bool            `json:"hidden,omitempty"`
	Labels   FlowLabels      `json:"labels,omitempty"`
	Forbid   FlowLabels      `json:"forbid,omitempty"`
}

// FlowLabels is a grant's per-operation label policy — the value of `labels` or
// `forbid` on a leaf grant. It maps a published operation name (memory.get,
// net.http, …) to its label set; the reserved key "*" applies to every
// operation the grant publishes. On the wire it accepts either a flat array
// (sugar for {"*": [...]}, the whole grant) or an object of per-operation label
// lists, and round-trips back to the array form when only "*" is set.
type FlowLabels map[string][]string

func (f *FlowLabels) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*f = nil
		return nil
	}
	if trimmed[0] == '[' {
		var all []string
		if err := json.Unmarshal(trimmed, &all); err != nil {
			return err
		}
		*f = FlowLabels{"*": all}
		return nil
	}
	var byOp map[string][]string
	if err := json.Unmarshal(trimmed, &byOp); err != nil {
		return err
	}
	*f = FlowLabels(byOp)
	return nil
}

func (f FlowLabels) MarshalJSON() ([]byte, error) {
	if len(f) == 0 {
		return []byte("null"), nil
	}
	if all, ok := f["*"]; ok && len(f) == 1 {
		return json.Marshal(all)
	}
	return json.Marshal(map[string][]string(f))
}

// isSpawn reports whether a grant spawns child processes rather than naming
// a leaf I/O driver.
func (s Syscall) isSpawn() bool { return s.Syscall == SpawnSyscall }

// spawnSettings decodes a sys.spawn grant's context-sharing settings (validated
// and canonicalized at manifest time); a grant with no settings shares all.
func (s Syscall) spawnSettings() SpawnSettings {
	var out SpawnSettings
	if len(s.Settings) > 0 {
		_ = json.Unmarshal(s.Settings, &out)
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
	Normalize(syscall string, settings json.RawMessage) (json.RawMessage, error)
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
		// Data-flow labels/forbid classify data I/O; they belong on leaf driver
		// grants only, never on the runtime-served sys.* control syscalls.
		if grant.runtimeServed() && (len(grant.Labels) > 0 || len(grant.Forbid) > 0) {
			return fmt.Errorf("%w: %s: labels/forbid may only be declared on leaf driver grants", ErrInvalid, grant.Syscall)
		}
		if grant.isSpawn() {
			if len(grant.Programs) == 0 {
				return fmt.Errorf("%w: %s requires at least one program", ErrInvalid, SpawnSyscall)
			}
			if len(grant.Settings) > 0 {
				normalized, err := normalizeSpawnSettings(grant.Settings)
				if err != nil {
					return fmt.Errorf("%w: %s settings: %v", ErrInvalid, SpawnSyscall, err)
				}
				grant.Settings = normalized
			}
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
			var settings TimerSettings
			if len(grant.Settings) > 0 {
				if err := json.Unmarshal(grant.Settings, &settings); err != nil {
					return fmt.Errorf("%w: sys.timer settings: %v", ErrInvalid, err)
				}
			}
			if settings.MaxDurationMS < 0 {
				return fmt.Errorf("%w: sys.timer max_duration_ms must not be negative", ErrInvalid)
			}
		} else {
			if len(grant.Programs) > 0 {
				return fmt.Errorf("%w: syscall %q: only %s carries programs", ErrInvalid, grant.Syscall, SpawnSyscall)
			}
			normalized, err := provider.Normalize(grant.Syscall, grant.Settings)
			if err != nil {
				return fmt.Errorf("%w: syscall %q settings: %v", ErrInvalid, grant.Syscall, err)
			}
			grant.Settings = append(json.RawMessage(nil), normalized...)
			if grant.Labels, err = normalizeFlowLabels("labels", grant.Labels); err != nil {
				return fmt.Errorf("%w: syscall %q: %v", ErrInvalid, grant.Syscall, err)
			}
			if grant.Forbid, err = normalizeFlowLabels("forbid", grant.Forbid); err != nil {
				return fmt.Errorf("%w: syscall %q: %v", ErrInvalid, grant.Syscall, err)
			}
		}
		if _, exists := seen[grant.Syscall]; exists {
			return fmt.Errorf("%w: duplicate syscall %q", ErrInvalid, grant.Syscall)
		}
		seen[grant.Syscall] = struct{}{}
	}
	return nil
}

// normalizeSpawnSettings validates a sys.spawn grant's settings and returns
// their canonical form. Unknown fields are rejected so a typo (e.g. "capabilites")
// surfaces at manifest time rather than silently sharing everything.
func normalizeSpawnSettings(raw json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var settings SpawnSettings
	if err := decoder.Decode(&settings); err != nil {
		return nil, err
	}
	return json.Marshal(settings)
}

// normalizeLabels canonicalizes a grant's label or forbid set: trim, drop
// empties, de-duplicate, and sort. The "syscall:<name>" namespace is reserved
// for the automatic provenance the Labeler stamps, so a manifest may not
// declare it. An empty set normalizes to nil (omitted on the wire).
func normalizeLabels(what string, labels []string) ([]string, error) {
	seen := make(map[string]struct{}, len(labels))
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		if strings.HasPrefix(label, "syscall:") {
			return nil, fmt.Errorf("%s label %q uses the reserved \"syscall:\" prefix", what, label)
		}
		if _, dup := seen[label]; dup {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	if len(out) == 0 {
		return nil, nil
	}
	sort.Strings(out)
	return out, nil
}

// normalizeFlowLabels canonicalizes a per-operation label policy: each
// operation's label list is normalized (normalizeLabels), operation keys are
// trimmed, and operations that normalize to no labels are dropped. Operation
// names are not checked against the grant's published capabilities here — the
// registry does that when it builds the driver, where the names are known.
func normalizeFlowLabels(what string, policy FlowLabels) (FlowLabels, error) {
	if len(policy) == 0 {
		return nil, nil
	}
	out := make(FlowLabels, len(policy))
	for op, labels := range policy {
		op = strings.TrimSpace(op)
		if op == "" {
			return nil, fmt.Errorf("%s: an operation name is required (or \"*\" for every operation)", what)
		}
		normalized, err := normalizeLabels(what, labels)
		if err != nil {
			return nil, err
		}
		if len(normalized) == 0 {
			continue
		}
		out[op] = normalized
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func cloneFlowLabels(policy FlowLabels) FlowLabels {
	if len(policy) == 0 {
		return nil
	}
	out := make(FlowLabels, len(policy))
	for op, labels := range policy {
		out[op] = append([]string(nil), labels...)
	}
	return out
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
		out[i].Settings = append(json.RawMessage(nil), grant.Settings...)
		out[i].Labels = cloneFlowLabels(grant.Labels)
		out[i].Forbid = cloneFlowLabels(grant.Forbid)
		if len(grant.Programs) > 0 {
			out[i].Programs = make([]Manifest, len(grant.Programs))
			for j, child := range grant.Programs {
				out[i].Programs[j] = cloneManifest(child)
			}
		}
	}
	return out
}
