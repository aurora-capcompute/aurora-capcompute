package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
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
func (p fixedProvider) NewDispatcher(context.Context, ProcessContext, manifest.Manifest) (*capability.Table, error) {
	return tableOf(capsDispatcher{caps: p.caps}), nil
}

// The reconciliation guard makes the manifest authoritative over what the
// dispatcher provider advertises: the guest's enforced grant set is the chain's
// advertised capabilities, so anything advertised beyond the manifest would be a
// silent authority widening.
func TestReconcileGrants(t *testing.T) {
	spec := manifest.Manifest{Version: manifest.Version, Syscalls: []manifest.Syscall{
		{Syscall: "core.openaiApi", Hidden: true},
		{Syscall: "core.internet"},
	}}

	t.Run("faithful advertisement is admitted", func(t *testing.T) {
		if err := reconcileGrants([]sys.Capability{leafCap("core.openaiApi"), leafCap("core.internet")}, spec); err != nil {
			t.Fatalf("faithful provider rejected: %v", err)
		}
	})

	t.Run("under-advertisement is admitted (not a leak)", func(t *testing.T) {
		if err := reconcileGrants([]sys.Capability{leafCap("core.internet")}, spec); err != nil {
			t.Fatalf("under-advertising provider rejected: %v", err)
		}
	})

	t.Run("over-advertisement is rejected and names the leak", func(t *testing.T) {
		err := reconcileGrants([]sys.Capability{leafCap("core.internet"), leafCap("core.filesystem")}, spec)
		if err == nil || !strings.Contains(err.Error(), "core.filesystem") {
			t.Fatalf("err = %v, want a rejection naming core.filesystem", err)
		}
	})

	t.Run("a driver may not advertise a runtime-served capability", func(t *testing.T) {
		// sys.timer is runtime-served, so it is not a leaf grant; a driver that
		// published it would be shadowing the runtime's own — refused.
		timerManifest := manifest.Manifest{Version: manifest.Version, Syscalls: []manifest.Syscall{
			{Syscall: manifest.TimerSyscall},
		}}
		err := reconcileGrants([]sys.Capability{leafCap(manifest.TimerSyscall)}, timerManifest)
		if err == nil || !strings.Contains(err.Error(), manifest.TimerSyscall) {
			t.Fatalf("err = %v, want a driver advertising %s to be rejected", err, manifest.TimerSyscall)
		}
	})
}

// The guard is actually wired into process activation: a provider that
// advertises a capability the manifest did not grant fails Drivers
// (fail-closed), so the leaked capability never becomes callable.
func TestProcessDriversRejectsOverAdvertisingProvider(t *testing.T) {
	r := &Runtime{
		dispatchers: fixedProvider{caps: []sys.Capability{leafCap("core.openaiApi"), leafCap("core.leak")}},
		processes: map[string]*processState{
			"p1": {id: "p1", manifest: manifest.Manifest{Version: manifest.Version, Syscalls: []manifest.Syscall{
				{Syscall: "core.openaiApi", Hidden: true},
			}}},
		},
	}
	_, _, err := r.Drivers(context.Background(), ProcessContext{ProcessID: "p1"})
	if err == nil || !strings.Contains(err.Error(), "core.leak") {
		t.Fatalf("Drivers err = %v, want a fail-closed rejection naming core.leak", err)
	}
}

func TestProcessDriversAdmitsFaithfulProvider(t *testing.T) {
	r := &Runtime{
		dispatchers: fixedProvider{caps: []sys.Capability{leafCap("core.openaiApi")}},
		processes: map[string]*processState{
			"p1": {id: "p1", manifest: manifest.Manifest{Version: manifest.Version, Syscalls: []manifest.Syscall{
				{Syscall: "core.openaiApi", Hidden: true},
			}}},
		},
	}
	if _, _, err := r.Drivers(context.Background(), ProcessContext{ProcessID: "p1"}); err != nil {
		t.Fatalf("faithful provider rejected at activation: %v", err)
	}
}

// The reserved sys.* namespace belongs to the processor and runtime. A manifest may
// grant only its runtime-served members (sys.timer, sys.declassify);
// every other sys.* leaf grant is refused at validation, so a driver can never be
// built for a name that would shadow a protocol call.
func TestManifestRejectsReservedSyscallNamespace(t *testing.T) {
	provider := fixedProvider{}
	for _, name := range []string{"sys.log", "sys.now", "sys.input", "sys.output", "sys.begin"} {
		_, err := manifest.Validate(manifest.Manifest{Version: manifest.Version, Syscalls: []manifest.Syscall{{Syscall: name}}}, provider)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("granting %q: err = %v, want a reserved-namespace rejection", name, err)
		}
	}

	// The two runtime-served members remain grantable.
	if _, err := manifest.Validate(manifest.Manifest{Version: manifest.Version, Program: "parent", Syscalls: []manifest.Syscall{
		{Syscall: manifest.TimerSyscall},
	}}, provider); err != nil {
		t.Fatalf("sys.timer grant rejected: %v", err)
	}
	if _, err := manifest.Validate(manifest.Manifest{Version: manifest.Version, Program: "parent", Syscalls: []manifest.Syscall{
		{Syscall: manifest.DeclassifySyscall},
	}}, provider); err != nil {
		t.Fatalf("sys.declassify grant rejected: %v", err)
	}
}
