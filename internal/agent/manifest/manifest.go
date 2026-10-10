// Package manifest is the grant set: what a process may do, declared as data.
//
// It reads only the fields the runtime owns. A grant's driver configuration is
// opaque here: the driver that serves the syscall checks it, through
// ConfigValidator.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Version is the manifest format this runtime reads.
const Version = 4

// reservedSyscallPrefix is the runtime's own namespace. A manifest may grant
// only TimerSyscall and DeclassifySyscall in it, so a driver cannot take the
// name of a protocol call.
const reservedSyscallPrefix = "sys."

// The runtime serves these to every process. A grant only tunes sys.timer.
const (
	TimerSyscall      = sys.SyscallTimer
	DeclassifySyscall = sys.SyscallDeclassify
)

// TimerSettings is the Config shape of a sys.timer grant.
type TimerSettings struct {
	// MaxDurationMS bounds the requested duration (0 = a default of 24h).
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
}

// Manifest is one process's grant: the program it runs and the syscalls it may
// call.
type Manifest struct {
	Version int    `json:"version,omitempty"`
	Program string `json:"program,omitempty"`
	// History false keeps the session history out of this process: its
	// sys.input carries no history, and it inherits no taint from earlier
	// runs. Unset shares the history.
	History  *bool     `json:"history,omitempty"`
	Syscalls []Syscall `json:"syscalls,omitempty"`
	// Skills reach the program through sys.input. They grant nothing.
	Skills []Skill `json:"skills,omitempty"`
}

// Skill tells the program how to use its grants for one kind of work.
type Skill struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Instructions string `json:"instructions,omitempty"`
}

// SharesHistory reports whether the process reads the session history.
func (m Manifest) SharesHistory() bool { return m.History == nil || *m.History }

// Syscall is one grant. In JSON it is a flat object: "syscall" names the
// syscall, "hidden" keeps it off the guest's tool menu, and every other key is
// the driver's configuration, kept in Config.
type Syscall struct {
	Syscall string
	Hidden  bool
	Config  json.RawMessage
}

// runtimeKeys are the grant keys the runtime owns. Every other key belongs to
// Config.
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
	s.Config = nil
	if len(rest) > 0 {
		s.Config, _ = json.Marshal(rest)
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

// runtimeServed reports whether the runtime serves this grant itself.
func (s Syscall) runtimeServed() bool {
	return s.Syscall == TimerSyscall || s.Syscall == DeclassifySyscall
}

// LeafSyscalls are the grants a driver serves: every grant the runtime does not
// serve itself.
func (m Manifest) LeafSyscalls() []Syscall {
	out := make([]Syscall, 0, len(m.Syscalls))
	for _, s := range m.Syscalls {
		if !s.runtimeServed() {
			out = append(out, s)
		}
	}
	return out
}

// FindSyscall returns the grant of one syscall, if the manifest has it.
func (m Manifest) FindSyscall(syscall string) (Syscall, bool) {
	for _, s := range m.Syscalls {
		if s.Syscall == syscall {
			return s, true
		}
	}
	return Syscall{}, false
}

// ConfigValidator checks a grant's driver configuration. The dispatcher
// provider is one.
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
	if err := validateSkills(spec.Skills); err != nil {
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

func validateSkills(skills []Skill) error {
	seen := make(map[string]struct{}, len(skills))
	for i := range skills {
		skill := &skills[i]
		skill.Name = strings.TrimSpace(skill.Name)
		if skill.Name == "" {
			return fmt.Errorf("%w: skill %d: a name is required", errs.Invalid, i)
		}
		if _, exists := seen[skill.Name]; exists {
			return fmt.Errorf("%w: duplicate skill %q", errs.Invalid, skill.Name)
		}
		seen[skill.Name] = struct{}{}
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
	out.Skills = slices.Clone(m.Skills)
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
