package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

type testDispatchers struct {
	normalized []string
}

func (p *testDispatchers) Normalize(syscall string, settings json.RawMessage) (json.RawMessage, error) {
	if syscall == "unknown" {
		return nil, fmt.Errorf("unsupported syscall")
	}
	p.normalized = append(p.normalized, syscall)
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (*testDispatchers) NewDispatcher(context.Context, ProcessContext, Manifest) (sys.Dispatcher[ProcessContext], error) {
	return nil, nil
}

func TestValidateManifestUsesInjectedProvider(t *testing.T) {
	provider := &testDispatchers{}
	manifest, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Program:  "program",
		Syscalls: []Syscall{{Syscall: " core.custom "}},
	}, provider)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if manifest.Syscalls[0].Syscall != "core.custom" {
		t.Fatalf("manifest = %+v", manifest)
	}
	if string(manifest.Syscalls[0].Settings) != "{}" {
		t.Fatalf("settings = %s", manifest.Syscalls[0].Settings)
	}
}

func TestValidateManifestRejectsMissingProviderAndUnknownSyscall(t *testing.T) {
	if _, err := ValidateManifest(Manifest{Version: ManifestVersion}, nil); err == nil {
		t.Fatal("expected missing provider error")
	}
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: "unknown"}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("expected unsupported syscall error")
	}
}

// Nothing is named, so a syscall may be granted once.
func TestValidateManifestRefusesDuplicateSyscalls(t *testing.T) {
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: "core.custom"}, {Syscall: "core.custom"}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("expected duplicate syscall error")
	}
}

// A sys.timer grant is the runtime's own: its settings validate here, not
// against a driver registration.
func TestValidateManifestValidatesTimerGrant(t *testing.T) {
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: TimerSyscall, Settings: json.RawMessage(`{"max_duration_ms":60000}`)}},
	}, &testDispatchers{}); err != nil {
		t.Fatalf("timer grant rejected: %v", err)
	}
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: TimerSyscall, Settings: json.RawMessage(`{"max_duration_ms":-1}`)}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("negative max_duration_ms accepted")
	}
}

// A sys.spawn grant carries programs — each a manifest of its own, program
// required, no version, recursively validated — plus optional context-sharing
// settings (history/capabilities), with unknown fields rejected.
func TestValidateManifestValidatesSpawnPrograms(t *testing.T) {
	valid := Manifest{
		Version: ManifestVersion,
		Program: "root",
		Syscalls: []Syscall{{
			Syscall:  SpawnSyscall,
			Settings: json.RawMessage(`{"history":false,"capabilities":false}`),
			Programs: []Manifest{{
				Program:  "scout",
				Syscalls: []Syscall{{Syscall: "core.custom"}},
			}},
		}},
	}
	if _, err := ValidateManifest(valid, &testDispatchers{}); err != nil {
		t.Fatalf("validate: %v", err)
	}

	cases := []struct {
		name  string
		grant Syscall
	}{
		{"no programs", Syscall{Syscall: SpawnSyscall}},
		{"unknown spawn setting", Syscall{Syscall: SpawnSyscall, Settings: json.RawMessage(`{"nope":true}`),
			Programs: []Manifest{{Program: "scout"}}}},
		{"program required", Syscall{Syscall: SpawnSyscall, Programs: []Manifest{{}}}},
		{"nested version", Syscall{Syscall: SpawnSyscall,
			Programs: []Manifest{{Program: "scout", Version: ManifestVersion}}}},
		{"duplicate programs", Syscall{Syscall: SpawnSyscall,
			Programs: []Manifest{{Program: "scout"}, {Program: "scout"}}}},
		{"bad nested grant", Syscall{Syscall: SpawnSyscall,
			Programs: []Manifest{{Program: "scout", Syscalls: []Syscall{{Syscall: "unknown"}}}}}},
		{"programs on a leaf", Syscall{Syscall: "core.custom",
			Programs: []Manifest{{Program: "scout"}}}},
	}
	for _, tc := range cases {
		if _, err := ValidateManifest(Manifest{
			Version:  ManifestVersion,
			Syscalls: []Syscall{tc.grant},
		}, &testDispatchers{}); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}
}

// Data-flow labels/forbid are declarable on leaf driver grants — a flat array
// (every operation) or a per-operation object — normalized (trimmed, deduped,
// sorted), and rejected on the runtime-served sys.* grants and the reserved
// "syscall:" namespace. Parsed from JSON to exercise the polymorphic decode.
func TestValidateManifestLabelsForbid(t *testing.T) {
	raw := `{"version":4,"syscalls":[
		{"syscall":"core.custom",
		 "labels":[" untrusted_web ","untrusted_web",""],
		 "forbid":{"memory.put":["secret","secret"],"*":["pii"]}}]}`
	var manifest Manifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m, err := ValidateManifest(manifest, &testDispatchers{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	grant := m.Syscalls[0]
	if got := grant.Labels["*"]; len(got) != 1 || got[0] != "untrusted_web" {
		t.Fatalf("labels[*] = %v, want [untrusted_web] (array sugar, trimmed + deduped)", got)
	}
	if got := grant.Forbid["memory.put"]; len(got) != 1 || got[0] != "secret" {
		t.Fatalf("forbid[memory.put] = %v, want [secret]", got)
	}
	if got := grant.Forbid["*"]; len(got) != 1 || got[0] != "pii" {
		t.Fatalf("forbid[*] = %v, want [pii]", got)
	}
	// A "*"-only policy round-trips back to the array form.
	if out, _ := json.Marshal(grant.Labels); string(out) != `["untrusted_web"]` {
		t.Fatalf("labels marshal = %s, want the array sugar", out)
	}

	cases := []struct {
		name  string
		grant Syscall
	}{
		{"reserved label prefix", Syscall{Syscall: "core.custom", Labels: FlowLabels{"*": {"syscall:core.custom"}}}},
		{"labels on spawn", Syscall{Syscall: SpawnSyscall, Labels: FlowLabels{"*": {"x"}}, Programs: []Manifest{{Program: "p"}}}},
		{"forbid on timer", Syscall{Syscall: TimerSyscall, Forbid: FlowLabels{"*": {"x"}}}},
	}
	for _, tc := range cases {
		if _, err := ValidateManifest(Manifest{
			Version:  ManifestVersion,
			Syscalls: []Syscall{tc.grant},
		}, &testDispatchers{}); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}
}
