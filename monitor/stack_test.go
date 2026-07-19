package monitor

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// stackDriver is the leaf: it records idempotency keys so the test can prove
// the below-replay layers actually receive them.
type stackDriver struct {
	keys []string
}

func (d *stackDriver) Dispatch(ctx context.Context, _ testPID, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	key, _ := sys.IdempotencyKey(ctx)
	d.keys = append(d.keys, key)
	return sys.Result(json.RawMessage(`{"from":"` + syscall.Name + `"}`)), nil
}

func (d *stackDriver) Capabilities() []sys.Capability { return flowCaps }

// The Stack's reason to exist: each layer on its correct side of the replay
// boundary. One test per load-bearing ordering property.
func TestStackEnforcesCanonicalOrder(t *testing.T) {
	journal := newMemJournal()
	header := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Process: "p1"}
	driver := &stackDriver{}

	// Everything the chain publishes is granted, plus the reserved syscalls.
	grants := func(cred testPID) []sys.Capability {
		return append([]sys.Capability(nil), append(flowCaps,
			sys.Capability{Name: sys.SyscallDeclassify},
		)...)
	}
	boot := func(t *testing.T) sys.Dispatcher[testPID] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		chain, err := Stack[string, testPID]{
			Grants: grants,
			Taints: NewTaints[string](), // fresh per boot: a crash loses host memory
		}.ForProcess(tape, driver)
		if err != nil {
			t.Fatalf("for run: %v", err)
		}
		return chain
	}

	chain := boot(t)

	// Validator on top: an ungranted name is denied and never journaled.
	denied := call(t, chain, "p1", "not.granted")
	if denied.Errno() != sys.ErrnoDenied {
		t.Fatalf("ungranted = %#v, want denied", denied)
	}
	if journal.Length() != 0 {
		t.Fatal("a denied call reached the journal")
	}

	// Labeler below replay: labels land in the journaled completion.
	call(t, chain, "p1", "internet.read")
	completion, err := journal.Load(1)
	if err != nil || completion.Result == nil || !slices.Contains(completion.Result.Labels(), "untrusted_web") {
		t.Fatalf("journaled completion = %+v (err %v), want untrusted_web label", completion, err)
	}

	// FlowMonitor above replay: the taint denies the protected capability…
	if result := call(t, chain, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("tainted k8s.delete = %#v, want denied", result)
	}
	recordsBeforeCrash := journal.Length()

	// …and a crash-rebooted host (fresh Taints, fresh tape, same journal)
	// re-derives the same denial from replayed results alone, replaying
	// without re-executing anything.
	driverCalls := len(driver.keys)
	rebooted := boot(t)
	call(t, rebooted, "p1", "internet.read")
	if result := call(t, rebooted, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("post-crash k8s.delete = %#v, want denied (taint not rebuilt)", result)
	}
	if len(driver.keys) != driverCalls {
		t.Fatal("replay re-executed a driver call")
	}
	if journal.Length() != recordsBeforeCrash {
		t.Fatal("replay appended records")
	}
	for _, key := range driver.keys {
		if key == "" {
			t.Fatal("a below-replay layer ran without an idempotency key")
		}
	}
	if err := journaled.Verify(journal); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestStackRequiresItsPieces(t *testing.T) {
	tape, _ := journaled.NewTape(newMemJournal(), journaled.Header{ABI: sys.ABIVersion, Program: "p", Process: "r"})
	if _, err := (Stack[string, testPID]{Taints: NewTaints[string]()}).ForProcess(tape, &recordingDispatcher{}); err == nil {
		t.Fatal("stack without Grants accepted")
	}
	if _, err := (Stack[string, testPID]{Grants: grantsFixture()}).ForProcess(tape, &recordingDispatcher{}); err == nil {
		t.Fatal("stack without Taints accepted")
	}
	if _, err := (Stack[string, testPID]{Grants: grantsFixture(), Taints: NewTaints[string]()}).ForProcess(tape, nil); err == nil {
		t.Fatal("stack without drivers accepted")
	}
}
