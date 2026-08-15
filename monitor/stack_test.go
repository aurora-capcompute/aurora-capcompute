package monitor

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
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

// stackTable is the grant index this chain is assembled around: the same one the
// flow layer reads its policy from and the Validator admits against.
var stackTable = func() *capability.Table {
	table := capability.NewTable()
	for _, family := range []capability.Family{
		single("internet.read", []string{"untrusted_web"}, nil, echo),
		single("k8s.delete", nil, []string{"untrusted_web"}, echo),
		single("mail.send", nil, nil, echo),
	} {
		if err := table.Add(family); err != nil {
			panic(err)
		}
	}
	return table
}()

// The Stack's reason to exist: each layer on its correct side of the replay
// boundary. One test per load-bearing ordering property.
func TestStackEnforcesCanonicalOrder(t *testing.T) {
	journal := newMemJournal()
	header := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Process: "p1"}
	driver := &stackDriver{}

	boot := func(t *testing.T) sys.Dispatcher[testPID] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		chain, err := Stack[string, testPID]{
			Taints: NewTaints[string](), // fresh per boot: a crash loses host memory
		}.ForProcess(tape, stackTable, driver)
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
	if _, err := (Stack[string, testPID]{Taints: NewTaints[string]()}).ForProcess(tape, nil, &recordingDispatcher{}); err == nil {
		t.Fatal("stack without a grant table accepted")
	}
	if _, err := (Stack[string, testPID]{}).ForProcess(tape, stackTable, &recordingDispatcher{}); err == nil {
		t.Fatal("stack without Taints accepted")
	}
	if _, err := (Stack[string, testPID]{Taints: NewTaints[string]()}).ForProcess(tape, stackTable, nil); err == nil {
		t.Fatal("stack without drivers accepted")
	}
}

// A syscall a decorator above the routing dispatcher serves is reserved, not
// indexed: the Validator admits it, but it resolves to no entry. So a layer that
// stops intercepting its own syscall falls through to the leaf and is denied,
// rather than reaching a handler it never had. This is the property that makes
// declaring-where-you-build safe.
func TestReservedSyscallIsAdmittedButNotRoutable(t *testing.T) {
	table := capability.NewTable()
	if err := table.Reserve(capability.Descriptor{Name: "sys.served.above"}); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, admitted := table.Descriptor("sys.served.above"); !admitted {
		t.Fatal("a reserved syscall must be in the grant set")
	}
	// The leaf is the routing dispatcher alone — nothing intercepts above it.
	leaf := capability.NewDispatcher[testPID](table)
	result, err := leaf.Dispatch(context.Background(), testPID{id: "p1"},
		sys.Syscall{Abi: sys.ABIVersion, Name: "sys.served.above"}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want a reserved syscall reaching the leaf to be denied", result.Errno())
	}
}
