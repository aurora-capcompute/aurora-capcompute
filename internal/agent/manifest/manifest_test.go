package manifest

import (
	"encoding/json"
	"fmt"
	"testing"
)

// testNormalizer is the only thing manifest validation asks of the layer above:
// canonicalize one leaf grant's config. Building a dispatcher — what the
// runtime's real provider also does — is none of this package's business, which
// is why the double needs no process credential and no dispatcher.
type testNormalizer struct {
	normalized []string
}

func (p *testNormalizer) Normalize(syscall string, config json.RawMessage) (json.RawMessage, error) {
	if syscall == "unknown" {
		return nil, fmt.Errorf("unsupported syscall")
	}
	p.normalized = append(p.normalized, syscall)
	if len(config) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), config...), nil
}

func TestValidateManifestUsesInjectedProvider(t *testing.T) {
	provider := &testNormalizer{}
	spec, err := Validate(Manifest{
		Version:  Version,
		Program:  "program",
		Syscalls: []Syscall{{Syscall: " core.custom "}},
	}, provider)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if spec.Syscalls[0].Syscall != "core.custom" {
		t.Fatalf("manifest = %+v", spec)
	}
	if string(spec.Syscalls[0].Config) != "{}" {
		t.Fatalf("config = %s", spec.Syscalls[0].Config)
	}
}

// A grant is a tagged union on `syscall`: the runtime owns syscall/hidden/
// programs; every other top-level key is the family's Config, captured verbatim
// and round-tripping through marshal/unmarshal.
func TestSyscallConfigCapture(t *testing.T) {
	raw := `{"syscall":"core.internet","hidden":true,"capabilities":[{"methods":["GET"],"domain":"*"}],"timeout_ms":5000}`
	var grant Syscall
	if err := json.Unmarshal([]byte(raw), &grant); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if grant.Syscall != "core.internet" || !grant.Hidden {
		t.Fatalf("runtime fields = %+v", grant)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(grant.Config, &config); err != nil {
		t.Fatalf("config: %v", err)
	}
	if _, ok := config["capabilities"]; !ok {
		t.Fatalf("capabilities not captured into Config: %s", grant.Config)
	}
	if _, ok := config["timeout_ms"]; !ok {
		t.Fatalf("timeout_ms not captured into Config: %s", grant.Config)
	}
	if _, leaked := config["syscall"]; leaked {
		t.Fatal("runtime key syscall leaked into Config")
	}
	// Re-marshal merges the runtime fields back with Config, and round-trips.
	out, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Syscall
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if back.Syscall != grant.Syscall || back.Hidden != grant.Hidden || string(back.Config) != string(grant.Config) {
		t.Fatalf("round-trip diverged: %+v vs %+v", back, grant)
	}
}

func TestValidateManifestRejectsMissingProviderAndUnknownSyscall(t *testing.T) {
	if _, err := Validate(Manifest{Version: Version}, nil); err == nil {
		t.Fatal("expected missing provider error")
	}
	if _, err := Validate(Manifest{
		Version:  Version,
		Syscalls: []Syscall{{Syscall: "unknown"}},
	}, &testNormalizer{}); err == nil {
		t.Fatal("expected unsupported syscall error")
	}
}

// Nothing is named, so a syscall may be granted once.
func TestValidateManifestRefusesDuplicateSyscalls(t *testing.T) {
	if _, err := Validate(Manifest{
		Version:  Version,
		Syscalls: []Syscall{{Syscall: "core.custom"}, {Syscall: "core.custom"}},
	}, &testNormalizer{}); err == nil {
		t.Fatal("expected duplicate syscall error")
	}
}

// A sys.timer grant is the runtime's own: its bound validates here, not
// against a driver registration.
func TestValidateManifestValidatesTimerGrant(t *testing.T) {
	if _, err := Validate(Manifest{
		Version:  Version,
		Program:  "program@1",
		Syscalls: []Syscall{{Syscall: TimerSyscall, Config: json.RawMessage(`{"max_duration_ms":60000}`)}},
	}, &testNormalizer{}); err != nil {
		t.Fatalf("timer grant rejected: %v", err)
	}
	if _, err := Validate(Manifest{
		Version:  Version,
		Syscalls: []Syscall{{Syscall: TimerSyscall, Config: json.RawMessage(`{"max_duration_ms":-1}`)}},
	}, &testNormalizer{}); err == nil {
		t.Fatal("negative max_duration_ms accepted")
	}
}

// A sys.spawn grant carries programs — each a manifest of its own, program
// required, no version, recursively validated — plus optional context-sharing
// settings (history/share_capabilities), with unknown fields rejected.
func TestValidateManifestValidatesSpawnPrograms(t *testing.T) {
	no := false
	valid := Manifest{
		Version: Version,
		Program: "root",
		Syscalls: []Syscall{{
			Syscall: SpawnSyscall,
			Programs: []Manifest{{
				Program:           "scout",
				History:           &no,
				ShareCapabilities: &no,
				Syscalls:          []Syscall{{Syscall: "core.custom"}},
			}},
		}},
	}
	if _, err := Validate(valid, &testNormalizer{}); err != nil {
		t.Fatalf("validate: %v", err)
	}

	cases := []struct {
		name  string
		grant Syscall
	}{
		{"no programs", Syscall{Syscall: SpawnSyscall}},
		{"settings on the grant", Syscall{Syscall: SpawnSyscall, Config: json.RawMessage(`{"history":false}`),
			Programs: []Manifest{{Program: "scout"}}}},
		{"program required", Syscall{Syscall: SpawnSyscall, Programs: []Manifest{{}}}},
		{"nested version", Syscall{Syscall: SpawnSyscall,
			Programs: []Manifest{{Program: "scout", Version: Version}}}},
		{"duplicate programs", Syscall{Syscall: SpawnSyscall,
			Programs: []Manifest{{Program: "scout"}, {Program: "scout"}}}},
		{"bad nested grant", Syscall{Syscall: SpawnSyscall,
			Programs: []Manifest{{Program: "scout", Syscalls: []Syscall{{Syscall: "unknown"}}}}}},
		{"programs on a leaf", Syscall{Syscall: "core.custom",
			Programs: []Manifest{{Program: "scout"}}}},
	}
	for _, tc := range cases {
		if _, err := Validate(Manifest{
			Version:  Version,
			Syscalls: []Syscall{tc.grant},
		}, &testNormalizer{}); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}
}
