// Package manifest is the grant set: what a process may do, declared as data.
//
// The package interprets only the fields the runtime owns; a leaf grant's Config
// is opaque here and checked by whoever serves that syscall, reached through the
// one-method ConfigValidator.
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

type Manifest struct {
	Version int    `json:"version,omitempty"`
	Program string `json:"program,omitempty"`
	// History, when false, isolates this program's process from session history:
	// its sys.input omits the history, so it sees only its own input and inherits
	// no taint from a prior run. Unset (the default) shares history — the
	// runtime's standing behavior.
	History  *bool     `json:"history,omitempty"`
	Syscalls []Syscall `json:"syscalls,omitempty"`
}

func (m Manifest) SharesHistory() bool { return m.History == nil || *m.History }

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

func (s Syscall) runtimeServed() bool {
	return s.Syscall == TimerSyscall || s.Syscall == DeclassifySyscall
}

func (m Manifest) LeafSyscalls() []Syscall {
	out := make([]Syscall, 0, len(m.Syscalls))
	for _, s := range m.Syscalls {
		if !s.runtimeServed() {
			out = append(out, s)
		}
	}
	return out
}

func (m Manifest) FindSyscall(syscall string) (Syscall, bool) {
	for _, s := range m.Syscalls {
		if s.Syscall == syscall {
			return s, true
		}
	}
	return Syscall{}, false
}

type ConfigValidator interface {
	ValidateConfig(syscall string, config json.RawMessage) error
}

// Validate checks a manifest at the door and returns its canonical form: names
// trimmed and settings normalized. It works on a copy, so the caller's manifest
// does not change.
func Validate(spec Manifest, validator ConfigValidator) (Manifest, error) {
	if spec.Version != Version {
		return Manifest{}, fmt.Errorf("%w: manifest version must be %d", errs.Invalid, Version)
	}
	spec = spec.Clone()
	spec.Program = strings.TrimSpace(spec.Program)
	if err := validateSyscalls(spec.Syscalls, validator); err != nil {
		return Manifest{}, err
	}
	if spec.Program == "" {
		return Manifest{}, fmt.Errorf("%w: a program is required", errs.Invalid)
	}
	return spec, nil
}

func validateSyscalls(syscalls []Syscall, validator ConfigValidator) error {
	seen := make(map[string]struct{}, len(syscalls))
	for i := range syscalls {
		syscall := &syscalls[i]
		syscall.Syscall = strings.TrimSpace(syscall.Syscall)

		if syscall.Syscall == "" {
			return fmt.Errorf("%w: grant %d: a syscall is required", errs.Invalid, i)
		}

		if _, exists := seen[syscall.Syscall]; exists {
			return fmt.Errorf("%w: duplicate syscall %q", errs.Invalid, syscall.Syscall)
		}

		if strings.HasPrefix(syscall.Syscall, reservedSyscallPrefix) && !syscall.runtimeServed() {
			return fmt.Errorf("%w: syscall %q is in the reserved %q namespace and may not be granted", errs.Invalid, syscall.Syscall, reservedSyscallPrefix)
		}

		switch syscall.Syscall {
		case TimerSyscall:
			normalized, err := normalizeTimerSettings(syscall.Config)
			if err != nil {
				return fmt.Errorf("%w: sys.timer settings: %v", errs.Invalid, err)
			}
			syscall.Config = normalized
		case DeclassifySyscall:
			if len(bytes.TrimSpace(syscall.Config)) > 0 {
				return fmt.Errorf("%w: %s takes no settings", errs.Invalid, DeclassifySyscall)
			}
			syscall.Config = nil
		default:
			if err := validator.ValidateConfig(syscall.Syscall, syscall.Config); err != nil {
				return fmt.Errorf("%w: syscall %q config: %v", errs.Invalid, syscall.Syscall, err)
			}
		}

		seen[syscall.Syscall] = struct{}{}
	}

	return nil
}

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

func (m Manifest) Clone() Manifest {
	out := m
	if m.History != nil {
		history := *m.History
		out.History = &history
	}
	out.Syscalls = cloneSyscalls(m.Syscalls)
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
	}
	return out
}
