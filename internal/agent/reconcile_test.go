package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

func leafCap(name string) sys.Capability { return sys.Capability{Name: name} }

// capsDispatcher advertises a fixed capability set; it never serves calls.
type capsDispatcher struct{ caps []sys.Capability }

func (capsDispatcher) Dispatch(context.Context, ProcessContext, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Fail("unused"), nil
}
func (d capsDispatcher) Capabilities() []sys.Capability { return d.caps }

// fixedProvider is a DispatcherProvider whose driver advertises a fixed
// capability set regardless of the manifest — the shape of an unfaithful
// (over-advertising) provider, the confused-deputy the guard defends against.
type fixedProvider struct{ caps []sys.Capability }

func (fixedProvider) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	return settings, nil
}
func (p fixedProvider) NewDispatcher(context.Context, ProcessContext, Manifest) (sys.Dispatcher[ProcessContext], error) {
	return capsDispatcher{caps: p.caps}, nil
}

// The reconciliation guard makes the manifest authoritative over what the
// dispatcher provider advertises: the guest's enforced grant set is the chain's
// advertised capabilities, so anything advertised beyond the manifest would be a
// silent authority widening.
func TestReconcileGrants(t *testing.T) {
	manifest := Manifest{Version: ManifestVersion, Syscalls: []Syscall{
		{Syscall: "core.openaiApi", Hidden: true},
		{Syscall: "core.internet"},
	}}

	t.Run("faithful advertisement is admitted", func(t *testing.T) {
		if err := reconcileGrants([]sys.Capability{leafCap("core.openaiApi"), leafCap("core.internet")}, manifest); err != nil {
			t.Fatalf("faithful provider rejected: %v", err)
		}
	})

	t.Run("under-advertisement is admitted (not a leak)", func(t *testing.T) {
		if err := reconcileGrants([]sys.Capability{leafCap("core.internet")}, manifest); err != nil {
			t.Fatalf("under-advertising provider rejected: %v", err)
		}
	})

	t.Run("over-advertisement is rejected and names the leak", func(t *testing.T) {
		err := reconcileGrants([]sys.Capability{leafCap("core.internet"), leafCap("core.filesystem")}, manifest)
		if err == nil || !strings.Contains(err.Error(), "core.filesystem") {
			t.Fatalf("err = %v, want a rejection naming core.filesystem", err)
		}
	})

	t.Run("a driver may not advertise a runtime-served capability", func(t *testing.T) {
		// sys.spawn is runtime-served, so it is not a leaf grant; a driver that
		// published it would be shadowing the runtime's own — refused.
		spawnManifest := Manifest{Version: ManifestVersion, Syscalls: []Syscall{
			{Syscall: SpawnSyscall, Programs: []Manifest{{Program: "child"}}},
		}}
		err := reconcileGrants([]sys.Capability{leafCap(SpawnSyscall)}, spawnManifest)
		if err == nil || !strings.Contains(err.Error(), SpawnSyscall) {
			t.Fatalf("err = %v, want a driver advertising %s to be rejected", err, SpawnSyscall)
		}
	})
}

// The guard is actually wired into process activation: a provider that
// advertises a capability the manifest did not grant fails processDrivers
// (fail-closed), so the leaked capability never becomes callable.
func TestProcessDriversRejectsOverAdvertisingProvider(t *testing.T) {
	r := &Runtime{
		dispatchers: fixedProvider{caps: []sys.Capability{leafCap("core.openaiApi"), leafCap("core.leak")}},
		processes: map[string]*processState{
			"p1": {id: "p1", manifest: Manifest{Version: ManifestVersion, Syscalls: []Syscall{
				{Syscall: "core.openaiApi", Hidden: true},
			}}},
		},
	}
	_, err := r.processDrivers(context.Background(), ProcessContext{ProcessID: "p1"})
	if err == nil || !strings.Contains(err.Error(), "core.leak") {
		t.Fatalf("processDrivers err = %v, want a fail-closed rejection naming core.leak", err)
	}
}

func TestProcessDriversAdmitsFaithfulProvider(t *testing.T) {
	r := &Runtime{
		dispatchers: fixedProvider{caps: []sys.Capability{leafCap("core.openaiApi")}},
		processes: map[string]*processState{
			"p1": {id: "p1", manifest: Manifest{Version: ManifestVersion, Syscalls: []Syscall{
				{Syscall: "core.openaiApi", Hidden: true},
			}}},
		},
	}
	if _, err := r.processDrivers(context.Background(), ProcessContext{ProcessID: "p1"}); err != nil {
		t.Fatalf("faithful provider rejected at activation: %v", err)
	}
}

// The reserved sys.* namespace belongs to the kernel and runtime. A manifest may
// grant only its runtime-served members (sys.spawn, sys.timer, sys.declassify);
// every other sys.* leaf grant is refused at validation, so a driver can never be
// built for a name that would shadow a protocol call.
func TestManifestRejectsReservedSyscallNamespace(t *testing.T) {
	provider := fixedProvider{}
	for _, name := range []string{"sys.log", "sys.now", "sys.input", "sys.output", "sys.begin", "sys.compensate"} {
		_, err := ValidateManifest(Manifest{Version: ManifestVersion, Syscalls: []Syscall{{Syscall: name}}}, provider)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("granting %q: err = %v, want a reserved-namespace rejection", name, err)
		}
	}

	// The two runtime-served members remain grantable.
	if _, err := ValidateManifest(Manifest{Version: ManifestVersion, Syscalls: []Syscall{
		{Syscall: SpawnSyscall, Programs: []Manifest{{Program: "child"}}},
	}}, provider); err != nil {
		t.Fatalf("sys.spawn grant rejected: %v", err)
	}
	if _, err := ValidateManifest(Manifest{Version: ManifestVersion, Syscalls: []Syscall{
		{Syscall: TimerSyscall},
	}}, provider); err != nil {
		t.Fatalf("sys.timer grant rejected: %v", err)
	}
	if _, err := ValidateManifest(Manifest{Version: ManifestVersion, Syscalls: []Syscall{
		{Syscall: DeclassifySyscall},
	}}, provider); err != nil {
		t.Fatalf("sys.declassify grant rejected: %v", err)
	}
}
