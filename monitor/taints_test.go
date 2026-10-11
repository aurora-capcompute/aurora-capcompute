package monitor

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

// echo is the trivial handler: it names the operation it served.
var echo = capability.HandlerFunc(func(_ context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	return sys.Result(json.RawMessage(`{"from":"` + call.Name + `"}`)), nil
})

// single indexes a syscall that is one operation by itself.
func single(name string, labels, forbid []string, handler capability.Handler) capability.Family {
	return capability.Family{Entries: []capability.Entry{{
		Key:     capability.Key{Syscall: name},
		Labels:  labels,
		Forbid:  forbid,
		Handler: handler,
	}}}
}

// flowTable is the policy the whole suite runs against: a source of untrusted
// data, a sink that refuses it, and a sink that does not care.
func flowTable(t *testing.T, handler capability.Handler) *capability.Table {
	t.Helper()
	table := capability.NewTable()
	for _, family := range []capability.Family{
		single("internet.read", []string{"untrusted_web"}, nil, handler),
		single("k8s.delete", nil, []string{"untrusted_web"}, handler),
		single("mail.send", nil, nil, handler),
	} {
		if err := table.Add(family); err != nil {
			t.Fatalf("add family: %v", err)
		}
	}
	return table
}

func call(t *testing.T, d sys.Dispatcher[testCred], pid string, name string) sys.SyscallResult {
	t.Helper()
	result, err := d.Dispatch(context.Background(), testCred{id: pid}, sys.Syscall{Abi: sys.ABIVersion, Name: name}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", name, err)
	}
	return result
}

// stamped is the below-the-tape half over the table's own routing dispatcher:
// the index that resolves the call is the index the labels come from.
func stamped(t *testing.T, table *capability.Table, taints *Taints[testCred]) (*Flow[testCred], sys.Dispatcher[testCred]) {
	t.Helper()
	flow := NewFlow(taints, table)
	return flow, flow.Stamp(capability.NewDispatcher[testCred](table))
}

func TestStampRecordsDerivingCapabilityAndClasses(t *testing.T) {
	table := flowTable(t, echo)
	_, below := stamped(t, table, NewTaints[testCred]())
	result := call(t, below, "p1", "internet.read")

	labels := result.Labels()
	for _, want := range []string{"syscall:internet.read", "untrusted_web"} {
		if !slices.Contains(labels, want) {
			t.Fatalf("labels = %v, want %q present", labels, want)
		}
	}
}

func TestTaintedCallWaitsForApproval(t *testing.T) {
	flow, below := stamped(t, flowTable(t, echo), NewTaints[testCred]())
	tracked := flow.Track(below)

	// Before any taint the protected capability runs.
	if result := call(t, tracked, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("untainted k8s.delete = %#v, want result", result)
	}

	// Observing untrusted data taints the run…
	call(t, tracked, "p1", "internet.read")

	// …so the protected capability now waits for a human, and the prompt says
	// which data it could carry and where that data came from…
	result := call(t, tracked, "p1", "k8s.delete")
	if result.Status() != sys.StatusYield {
		t.Fatalf("tainted k8s.delete = %#v, want a yield for approval", result)
	}
	for _, want := range []string{"untrusted_web", "internet.read"} {
		if !strings.Contains(result.Message(), want) {
			t.Fatalf("prompt %q does not name %q", result.Message(), want)
		}
	}

	// …while unprotected capabilities still run…
	if result := call(t, tracked, "p1", "mail.send"); result.Status() != sys.StatusResult {
		t.Fatalf("mail.send = %#v, want result", result)
	}

	// …and other runs are unaffected.
	if result := call(t, tracked, "p2", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("other run's k8s.delete = %#v, want result", result)
	}
}

// The full chain: Track → replay → Stamp → drivers. Labels must land in the
// journal, and a crash-restarted host must rebuild the run's taint from
// replayed results alone.
func TestFlowTaintSurvivesCrashReplay(t *testing.T) {
	journal := newMemJournal()
	table := flowTable(t, echo)

	newChain := func(t *testing.T) sys.Dispatcher[testCred] {
		t.Helper()
		tape := journaled.NewTape(journal)
		flow, below := stamped(t, table, NewTaints[testCred]())
		return flow.Track(replay.NewDispatcher(tape, below))
	}

	first := newChain(t)
	call(t, first, "p1", "internet.read")

	// Labels reached the journal's completion record.
	completion, err := journal.Load(1)
	if err != nil || completion.Result == nil {
		t.Fatalf("completion record: %+v, err %v", completion, err)
	}
	if !slices.Contains(completion.Result.Labels(), "untrusted_web") {
		t.Fatalf("journaled labels = %v, want untrusted_web", completion.Result.Labels())
	}

	// Crash: a fresh host process (fresh flow state, fresh tape, same journal)
	// replays the run. The replayed result must rebuild the taint…
	crashed := newChain(t)
	replayed := call(t, crashed, "p1", "internet.read")
	if !slices.Contains(replayed.Labels(), "untrusted_web") {
		t.Fatalf("replayed labels = %v, want untrusted_web", replayed.Labels())
	}
	// …so the flow policy still holds after the crash.
	if result := call(t, crashed, "p1", "k8s.delete"); result.Status() != sys.StatusYield {
		t.Fatalf("post-crash k8s.delete = %#v, want a yield for approval", result)
	}
}

// An approval lets one tainted call through and lifts nothing: the run keeps its
// labels, so the next such call asks again, and a crash-replay serves the
// approved call from the journal without asking.
func TestApprovedCallKeepsTheTaint(t *testing.T) {
	journal := newMemJournal()
	table := flowTable(t, echo)
	newChain := func(t *testing.T) (sys.Dispatcher[testCred], *Taints[testCred]) {
		t.Helper()
		taints := NewTaints[testCred]()
		flow, below := stamped(t, table, taints)
		return flow.Track(replay.NewDispatcher(journaled.NewTape(journal), below)), taints
	}
	approved := sys.Authorization{Decision: sys.Approved, Actor: "alice"}
	p1 := testCred{id: "p1"}
	deleteCall := sys.Syscall{Abi: sys.ABIVersion, Name: "k8s.delete"}

	chain, _ := newChain(t)
	call(t, chain, "p1", "internet.read")
	if result := call(t, chain, "p1", "k8s.delete"); result.Status() != sys.StatusYield {
		t.Fatalf("tainted k8s.delete = %#v, want a yield for approval", result)
	}

	// The human approves and the run resumes in a new quantum: the guest runs
	// from the start, internet.read replays, and the parked call comes back
	// with the approval.
	resumed, taints := newChain(t)
	call(t, resumed, "p1", "internet.read")
	result, err := resumed.Dispatch(context.Background(), p1, deleteCall, approved)
	if err != nil || result.Status() != sys.StatusResult {
		t.Fatalf("approved k8s.delete = %#v, %v; want result", result, err)
	}
	if !slices.Contains(taints.Snapshot(p1), "untrusted_web") {
		t.Fatalf("taint after approval = %v: the approval lifted untrusted_web", taints.Snapshot(p1))
	}
	if result := call(t, resumed, "p1", "k8s.delete"); result.Status() != sys.StatusYield {
		t.Fatalf("second k8s.delete = %#v, want a new yield: one approval covers one call", result)
	}

	// Crash-replay: a fresh host serves the approved call from the journal, with
	// no authorization and no new approval.
	crashed, _ := newChain(t)
	call(t, crashed, "p1", "internet.read")
	if result := call(t, crashed, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("replayed k8s.delete = %#v, want the journaled result", result)
	}
	if err := journaled.Verify(journal); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFlowTrackHandsTaintDownstream(t *testing.T) {
	var seen capability.Taint
	probe := capability.HandlerFunc(func(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
		if call.Name == "mail.send" {
			seen = capability.TaintFrom(ctx)
		}
		return sys.Result(nil), nil
	})
	flow, below := stamped(t, flowTable(t, probe), NewTaints[testCred]())
	tracked := flow.Track(below)

	call(t, tracked, "p1", "internet.read")
	call(t, tracked, "p1", "mail.send")
	if sources := seen["untrusted_web"]; !slices.Equal(sources, []string{"internet.read"}) {
		t.Fatalf("downstream taint = %v, want untrusted_web from internet.read", seen)
	}
}

func adtCall(t *testing.T, d sys.Dispatcher[testCred], operation string) sys.SyscallResult {
	t.Helper()
	result, err := d.Dispatch(context.Background(), testCred{id: "p1"}, sys.Syscall{
		Abi:  sys.ABIVersion,
		Name: "core.filesystem",
		Args: json.RawMessage(`{"operation":"` + operation + `"}`),
	}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", operation, err)
	}
	return result
}

// adtTable indexes one syscall with two cases: a read that is a source and a
// write that is a sink.
func adtTable(t *testing.T) *capability.Table {
	t.Helper()
	table := capability.NewTable()
	err := table.Add(capability.Family{
		Entries: []capability.Entry{
			{Key: capability.Key{Syscall: "core.filesystem", Operation: "read"}, Discriminator: "operation",
				Labels: []string{"untrusted_file"}, Handler: echo},
			{Key: capability.Key{Syscall: "core.filesystem", Operation: "write"}, Discriminator: "operation",
				Forbid: []string{"untrusted_file"}, Handler: echo},
		},
	})
	if err != nil {
		t.Fatalf("add family: %v", err)
	}
	return table
}

// Per-operation flow policy: a syscall with several cases carries its labels and
// its sink guard per case, and the monitor resolves the case from the call's
// arguments — the same resolution the routing dispatcher below the journal does.
// This is where filesystem's own sink-guard and label tests moved to when
// enforcement left the driver.
func TestPerOperationFlowPolicy(t *testing.T) {
	table := adtTable(t)
	flow, below := stamped(t, table, NewTaints[testCred]())
	chain := flow.Track(below)

	// A read stamps its own source class and taints the run.
	result := adtCall(t, chain, "read")
	if !slices.Contains(result.Labels(), "untrusted_file") {
		t.Fatalf("labels = %v, want the read's own source class", result.Labels())
	}

	// The write forbids what the read produced, so it waits for a human —
	// while the read, which forbids nothing, still runs.
	if parked := adtCall(t, chain, "write"); parked.Status() != sys.StatusYield {
		t.Fatalf("write = %#v, want a yield for approval", parked)
	}
	if again := adtCall(t, chain, "read"); again.Status() != sys.StatusResult {
		t.Fatalf("read after taint = %v, want it still permitted", again.Status())
	}
}

// An unresolvable case must not be a way past the approval: the routing
// dispatcher cannot tell which case the call is, so it runs none of them.
func TestUnresolvableCaseNeverRuns(t *testing.T) {
	table := adtTable(t)
	flow, below := stamped(t, table, NewTaints[testCred]())
	chain := flow.Track(below)

	adtCall(t, chain, "read") // taints the run with untrusted_file

	result, err := chain.Dispatch(context.Background(), testCred{id: "p1"}, sys.Syscall{
		Abi:  sys.ABIVersion,
		Name: "core.filesystem",
		Args: json.RawMessage(`{"operation":42}`),
	}, sys.Authorization{Decision: sys.Approved})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("result = %#v, want invalid args: a call whose case cannot be read runs nothing", result)
	}
}

// A failed result is still an observation: the call reached a labelled source
// and the failure text may carry what it saw. Stamp labels it like any other
// outcome, which is why a driver need not — and must not — label its own
// failures. openaillm relied on doing that itself until its policy moved onto
// its entries; this is the guarantee it now leans on.
func TestStampLabelsFailuresToo(t *testing.T) {
	failing := capability.HandlerFunc(func(_ context.Context, _ sys.Syscall) (sys.SyscallResult, error) {
		return sys.FailCode(sys.ErrnoTransient, "provider unreachable"), nil
	})
	_, below := stamped(t, flowTable(t, failing), NewTaints[testCred]())

	result := call(t, below, "p1", "internet.read")
	if result.Status() != sys.StatusFailed {
		t.Fatalf("status = %v, want the handler's failure", result.Status())
	}
	if !slices.Contains(result.Labels(), "untrusted_web") {
		t.Fatalf("SECURITY: failed result labels = %v, want the source class — an "+
			"unlabelled error is a channel a forbidding sink would accept", result.Labels())
	}
}
