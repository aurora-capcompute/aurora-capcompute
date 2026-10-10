package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// activationRuntime holds one process whose manifest grants only the agent's
// cognition tool, with its chain's capabilities supplied by provider.
func activationRuntime(provider fixedProvider) *Runtime {
	log := newMemLog()
	return &Runtime{
		dispatchers: provider,
		log:         log,
		sessions:    map[string]*sessionState{"s1": {id: "s1", processIDs: []string{"p1"}}},
		processes: map[string]*processState{
			"p1": {id: "p1", sessionID: "s1", revision: 1,
				journal: newLogJournal(log, "s1", "p1", 1, newProcessHistory(), 0, time.Now),
				manifest: manifest.Manifest{Version: manifest.Version, Syscalls: []manifest.Syscall{
					{Syscall: "core.openaiApi", Hidden: true},
				}}},
		},
	}
}

// The guard is actually wired into process activation: a provider that
// advertises a capability the manifest did not grant fails the chain's build
// (fail-closed), so the leaked capability never becomes callable.
func TestActivationRejectsOverAdvertisingProvider(t *testing.T) {
	r := activationRuntime(fixedProvider{caps: []capability.Descriptor{leafCap("core.openaiApi"), leafCap("core.leak")}})
	_, err := r.newDispatcher(context.Background(), durable.ProcessContext{SessionID: "s1", ProcessID: "p1", Revision: 1}, compiledProgram{})
	if err == nil || !strings.Contains(err.Error(), "core.leak") {
		t.Fatalf("activation err = %v, want a fail-closed rejection naming core.leak", err)
	}
}

func TestActivationAdmitsFaithfulProvider(t *testing.T) {
	r := activationRuntime(fixedProvider{caps: []capability.Descriptor{leafCap("core.openaiApi")}})
	if _, err := r.newDispatcher(context.Background(), durable.ProcessContext{SessionID: "s1", ProcessID: "p1", Revision: 1}, compiledProgram{}); err != nil {
		t.Fatalf("faithful provider rejected at activation: %v", err)
	}
}

// A journal replay cannot reason about is refused before replay: activation
// fails closed rather than serve records the store handed back in a shape the
// tape never writes.
func TestActivationRefusesAMalformedJournal(t *testing.T) {
	r := activationRuntime(fixedProvider{caps: []capability.Descriptor{leafCap("core.openaiApi")}})
	result := sys.Result(nil)
	// A completion with no intent before it — the tape never writes this.
	if err := r.processes["p1"].journal.Append(journaled.Record{Position: 0, Kind: journaled.KindCompletion, Result: &result}); err != nil {
		t.Fatalf("append: %v", err)
	}
	_, err := r.newDispatcher(context.Background(), durable.ProcessContext{SessionID: "s1", ProcessID: "p1", Revision: 1}, compiledProgram{})
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("err = %v, want a journal integrity rejection", err)
	}
}
