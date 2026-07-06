package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

const ManifestVersion = 3

// SpawnType is the syscall `type` for spawning a child process. A grant of
// this type is not a leaf I/O driver: the runtime serves it by spawning a
// child process that runs the named program under the grant's own syscall
// set — the limitations the child lives inside.
const SpawnType = "core.spawn"

// Manifest is one process node (root or child). Program/SystemPrompt
// configure this node; Syscalls is its grant set — every capability the
// process may dispatch, leaf I/O drivers and `core.spawn` grants alike, one
// shape for both.
type Manifest struct {
	Version int    `json:"version"`
	Name    string `json:"name,omitempty"`
	Program string `json:"program,omitempty"`
	// BindingRef is an opaque application correlation reference (e.g. the
	// name of the control-plane binding that produced this manifest). The
	// runtime never interprets it; it only propagates it to spawned child
	// manifests, like Tags on sessions.
	BindingRef   string `json:"binding_ref,omitempty"`
	SystemPrompt string `json:"system_prompt,omitempty"`
	// OnFailure selects how a failure of this node (when it is a spawned
	// child) is handled: OnFailureReport (default) surfaces it to the parent
	// program as a recoverable failed observation; OnFailurePropagate fails
	// the parent outright.
	OnFailure string    `json:"on_failure,omitempty"`
	Syscalls  []Syscall `json:"syscalls"`
}

// Syscall is one granted capability in a process's manifest. `Type` selects
// the driver implementation; `Name` is the syscall name the program
// dispatches. For a `core.spawn` grant, Settings decodes to SpawnSettings —
// the program to run and its policies — and Syscalls holds the child's own
// grant set.
type Syscall struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings,omitempty"`
	Syscalls []Syscall       `json:"syscalls,omitempty"`
	Hidden   bool            `json:"hidden,omitempty"`
}

// SpawnSettings is the Settings shape of a `core.spawn` grant.
type SpawnSettings struct {
	Program      string `json:"program,omitempty"`
	BindingRef   string `json:"binding_ref,omitempty"`
	SystemPrompt string `json:"system_prompt,omitempty"`
	OnFailure    string `json:"on_failure,omitempty"`
}

// Child failure-handling modes for SpawnSettings.OnFailure.
const (
	OnFailureReport    = "report"
	OnFailurePropagate = "propagate"
)

// isSpawn reports whether a grant spawns a child process rather than naming
// a leaf I/O driver.
func (s Syscall) isSpawn() bool { return s.Type == SpawnType }

// LeafSyscalls returns the node's non-spawn grants. Dispatcher providers
// build these via the registry; `core.spawn` grants are served by the
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

// spawnGrants returns the node's `core.spawn` grants (served by the spawn
// router).
func (m Manifest) spawnGrants() []Syscall {
	out := make([]Syscall, 0, len(m.Syscalls))
	for _, s := range m.Syscalls {
		if s.isSpawn() {
			out = append(out, s)
		}
	}
	return out
}

func decodeSpawnSettings(grant Syscall) (SpawnSettings, error) {
	var settings SpawnSettings
	if len(grant.Settings) > 0 {
		if err := json.Unmarshal(grant.Settings, &settings); err != nil {
			return SpawnSettings{}, err
		}
	}
	settings.Program = strings.TrimSpace(settings.Program)
	settings.BindingRef = strings.TrimSpace(settings.BindingRef)
	settings.SystemPrompt = strings.TrimSpace(settings.SystemPrompt)
	return settings, nil
}

type DispatcherProvider interface {
	Normalize(syscallType string, settings json.RawMessage) (json.RawMessage, error)
	NewDispatcher(context.Context, ProcessContext, Manifest) (sys.Dispatcher[ProcessContext], error)
}

func ValidateManifest(manifest Manifest, provider DispatcherProvider) (Manifest, error) {
	if provider == nil {
		return Manifest{}, fmt.Errorf("%w: dispatcher provider is required", ErrInvalid)
	}
	if manifest.Version != ManifestVersion {
		return Manifest{}, fmt.Errorf("%w: manifest version must be %d", ErrInvalid, ManifestVersion)
	}
	manifest.SystemPrompt = strings.TrimSpace(manifest.SystemPrompt)
	manifest.Program = strings.TrimSpace(manifest.Program)
	if err := validateSyscalls(manifest.Syscalls, provider); err != nil {
		return Manifest{}, err
	}
	return cloneManifest(manifest), nil
}

// validateSyscalls normalizes leaf grants and recursively validates spawn
// grants, enforcing unique names within each node.
func validateSyscalls(syscalls []Syscall, provider DispatcherProvider) error {
	seen := make(map[string]struct{}, len(syscalls))
	for i := range syscalls {
		grant := &syscalls[i]
		grant.Name = strings.TrimSpace(grant.Name)
		grant.Type = strings.TrimSpace(grant.Type)
		if grant.Type == "" {
			return fmt.Errorf("%w: syscall %d type is required", ErrInvalid, i)
		}
		if grant.isSpawn() {
			settings, err := decodeSpawnSettings(*grant)
			if err != nil {
				return fmt.Errorf("%w: spawn grant %d settings: %v", ErrInvalid, i, err)
			}
			if settings.Program == "" {
				return fmt.Errorf("%w: spawn grant %q requires settings.program", ErrInvalid, grant.Name)
			}
			if grant.Name == "" {
				grant.Name = settings.Program
			}
			switch settings.OnFailure {
			case "", OnFailureReport, OnFailurePropagate:
			default:
				return fmt.Errorf("%w: spawn grant %q on_failure must be %q or %q", ErrInvalid, grant.Name, OnFailureReport, OnFailurePropagate)
			}
			if err := validateSyscalls(grant.Syscalls, provider); err != nil {
				return fmt.Errorf("spawn grant %q: %w", grant.Name, err)
			}
		} else {
			if grant.Name == "" {
				return fmt.Errorf("%w: syscall %d name is required", ErrInvalid, i)
			}
			normalized, err := provider.Normalize(grant.Type, grant.Settings)
			if err != nil {
				return fmt.Errorf("%w: syscall %q (%s) settings: %v", ErrInvalid, grant.Name, grant.Type, err)
			}
			grant.Settings = append(json.RawMessage(nil), normalized...)
		}
		if _, exists := seen[grant.Name]; exists {
			return fmt.Errorf("%w: duplicate syscall name %q", ErrInvalid, grant.Name)
		}
		seen[grant.Name] = struct{}{}
	}
	return nil
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
		out[i].Syscalls = cloneSyscalls(grant.Syscalls)
	}
	return out
}
