package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

const ManifestVersion = 4

// SpawnSyscall is the syscall granting process spawning. Its grant carries
// Programs — the manifests of the only programs this process may spawn, each
// with its own recursive grant set — and the runtime serves it as the
// `spawn` capability.
const SpawnSyscall = "core.spawn"

// Manifest is one process node. Program/SystemPrompt configure the node;
// Syscalls is its grant set. A spawnable child inside a core.spawn grant is
// itself a Manifest — the recursion that makes the whole grant tree one
// shape — carrying no Version of its own: the root's governs.
type Manifest struct {
	Version int    `json:"version,omitempty"`
	Program string `json:"program,omitempty"`
	// BindingRef is an opaque application correlation reference (e.g. the
	// name of the control-plane binding that produced this manifest). The
	// runtime never interprets it.
	BindingRef   string `json:"binding_ref,omitempty"`
	SystemPrompt string `json:"system_prompt,omitempty"`
	// OnFailure selects how this node's failure (when it is a spawned child)
	// is handled: OnFailureReport (default) surfaces it to the parent
	// program as a recoverable failed observation; OnFailurePropagate fails
	// the parent outright.
	OnFailure string    `json:"on_failure,omitempty"`
	Syscalls  []Syscall `json:"syscalls,omitempty"`
}

// Syscall is one granted syscall. The manifest names nothing: a grant says
// which syscall the process gets and how it is configured, and each driver
// publishes its canonical capability names (timer.set, memory.get/put/list,
// internet.read, openai.*, mcp.<server>.<tool>). A core.spawn grant carries
// Programs instead of Settings.
type Syscall struct {
	Syscall  string          `json:"syscall"`
	Settings json.RawMessage `json:"settings,omitempty"`
	Programs []Manifest      `json:"programs,omitempty"`
	Hidden   bool            `json:"hidden,omitempty"`
}

// Child failure-handling modes for Manifest.OnFailure.
const (
	OnFailureReport    = "report"
	OnFailurePropagate = "propagate"
)

// isSpawn reports whether a grant spawns child processes rather than naming
// a leaf I/O driver.
func (s Syscall) isSpawn() bool { return s.Syscall == SpawnSyscall }

// LeafSyscalls returns the node's non-spawn grants. Dispatcher providers
// build these via the registry; the core.spawn grant is served by the
// runtime instead.
func (m Manifest) LeafSyscalls() []Syscall {
	out := make([]Syscall, 0, len(m.Syscalls))
	for _, s := range m.Syscalls {
		if !s.isSpawn() {
			out = append(out, s)
		}
	}
	return out
}

// spawnGrant returns the node's core.spawn grant, if any. Validation
// guarantees at most one.
func (m Manifest) spawnGrant() (Syscall, bool) {
	for _, s := range m.Syscalls {
		if s.isSpawn() {
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
// program inside a core.spawn grant — and recurses into its grant set.
func validateNode(node *Manifest, provider DispatcherProvider) error {
	node.Program = strings.TrimSpace(node.Program)
	node.SystemPrompt = strings.TrimSpace(node.SystemPrompt)
	node.BindingRef = strings.TrimSpace(node.BindingRef)
	switch node.OnFailure {
	case "", OnFailureReport, OnFailurePropagate:
	default:
		return fmt.Errorf("%w: on_failure must be %q or %q", ErrInvalid, OnFailureReport, OnFailurePropagate)
	}
	return validateSyscalls(node.Syscalls, provider)
}

// validateSyscalls normalizes a grant set: leaf grants against their driver
// registrations, the spawn grant into its spawnable programs. Nothing is
// named, so a syscall may be granted once — except core.mcp, whose grants
// are distinguished by the server they bridge.
func validateSyscalls(syscalls []Syscall, provider DispatcherProvider) error {
	seen := make(map[string]struct{}, len(syscalls))
	for i := range syscalls {
		grant := &syscalls[i]
		grant.Syscall = strings.TrimSpace(grant.Syscall)
		if grant.Syscall == "" {
			return fmt.Errorf("%w: grant %d: a syscall is required", ErrInvalid, i)
		}
		key := grant.Syscall
		if grant.isSpawn() {
			if len(grant.Settings) > 0 {
				return fmt.Errorf("%w: core.spawn carries programs, not settings", ErrInvalid)
			}
			if len(grant.Programs) == 0 {
				return fmt.Errorf("%w: core.spawn requires at least one program", ErrInvalid)
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
		} else {
			if len(grant.Programs) > 0 {
				return fmt.Errorf("%w: syscall %q: only core.spawn carries programs", ErrInvalid, grant.Syscall)
			}
			normalized, err := provider.Normalize(grant.Syscall, grant.Settings)
			if err != nil {
				return fmt.Errorf("%w: syscall %q settings: %v", ErrInvalid, grant.Syscall, err)
			}
			grant.Settings = append(json.RawMessage(nil), normalized...)
			if grant.Syscall == "core.mcp" {
				key += "/" + mcpServerID(grant.Settings)
			}
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate syscall %q", ErrInvalid, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// mcpServerID reads the server a core.mcp grant bridges — the discriminator
// that lets one process reach several MCP servers.
func mcpServerID(settings json.RawMessage) string {
	var s struct {
		ServerID string `json:"server_id"`
	}
	_ = json.Unmarshal(settings, &s)
	return s.ServerID
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
		if len(grant.Programs) > 0 {
			out[i].Programs = make([]Manifest, len(grant.Programs))
			for j, child := range grant.Programs {
				out[i].Programs[j] = cloneManifest(child)
			}
		}
	}
	return out
}
