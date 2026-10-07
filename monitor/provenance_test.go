package monitor

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

// handlerFunc is a leaf operation: the table resolved the call, this performs it.
type handlerFunc func(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error)

func (f handlerFunc) DispatchCall(ctx context.Context, call sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	return f(ctx, call)
}

// echo is the trivial handler: it names the operation it served.
var echo = handlerFunc(func(_ context.Context, call sys.Syscall) (sys.SyscallResult, error) {
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

func TestFlowGuardBlocksTaintedFlow(t *testing.T) {
	flow, below := stamped(t, flowTable(t, echo), NewTaints[testCred]())
	guarded := flow.Guard(below)

	// Before any taint the protected capability is callable.
	if result := call(t, guarded, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("untainted k8s.delete = %#v, want result", result)
	}

	// Observing untrusted data taints the run…
	call(t, guarded, "p1", "internet.read")

	// …so the protected capability is now refused…
	result := call(t, guarded, "p1", "k8s.delete")
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("tainted k8s.delete = %#v, want failed/denied", result)
	}

	// …while unprotected capabilities still work…
	if result := call(t, guarded, "p1", "mail.send"); result.Status() != sys.StatusResult {
		t.Fatalf("mail.send = %#v, want result", result)
	}

	// …and other runs are unaffected.
	if result := call(t, guarded, "p2", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("other run's k8s.delete = %#v, want result", result)
	}
}

func TestFlowGuardDeclassify(t *testing.T) {
	taints := NewTaints[testCred]()
	flow, below := stamped(t, flowTable(t, echo), taints)
	guarded := flow.Guard(below)
	call(t, guarded, "p1", "internet.read")

	if result := call(t, guarded, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("expected denial before declassification, got %#v", result)
	}
	taints.Declassify(testCred{id: "p1"}, "untrusted_web")
	if result := call(t, guarded, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("declassified k8s.delete = %#v, want result", result)
	}
}

// The full chain: Guard → replay → Stamp → drivers. Labels must land in the
// journal, and a crash-restarted host must rebuild the run's taint from
// replayed results alone.
func TestFlowTaintSurvivesCrashReplay(t *testing.T) {
	journal := newMemJournal()
	header := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Process: "p1"}
	table := flowTable(t, echo)

	newChain := func(t *testing.T) sys.Dispatcher[testCred] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		flow, below := stamped(t, table, NewTaints[testCred]())
		return flow.Guard(replay.NewDispatcher(tape, below, nil))
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
	result := call(t, crashed, "p1", "k8s.delete")
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("post-crash k8s.delete = %#v, want failed/denied", result)
	}
}

// The full declassification protocol: taint blocks a protected call; an
// unapproved sys.declassify yields for a human; the approved crossing is
// journaled; a crash-replay re-applies it without asking again.
func TestDeclassifySyscallLifecycle(t *testing.T) {
	journal := newMemJournal()
	header := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Process: "p1"}
	table := flowTable(t, echo)
	newChain := func(t *testing.T) sys.Dispatcher[testCred] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		flow := NewFlow(NewTaints[testCred](), table)
		below := flow.Stamp(NewDeclassifier(capability.NewDispatcher[testCred](table)))
		return flow.Guard(replay.NewDispatcher(tape, below, nil))
	}
	declassify := sys.Syscall{
		Abi:  sys.ABIVersion,
		Name: sys.SyscallDeclassify,
		Args: json.RawMessage(`{"labels":["untrusted_web"],"reason":"reviewed the fetched page"}`),
	}

	chain := newChain(t)
	call(t, chain, "p1", "internet.read")
	if result := call(t, chain, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("expected taint denial, got %#v", result)
	}

	// Unapproved: a human task is created (yield); nothing is lifted.
	result, err := chain.Dispatch(context.Background(), testCred{id: "p1"}, declassify, sys.Authorization{})
	if err != nil {
		t.Fatalf("declassify: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("unapproved declassify = %#v, want yield", result)
	}
	if result := call(t, chain, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("yielded declassify lifted taint early: %#v", result)
	}

	// The approval resolves and the run resumes: the guest re-runs from the
	// start (the yield reset the tape), replays internet.read from the
	// journal, and re-issues the declassify — which meets its own open
	// intent and now carries the resolved Authorization.
	call(t, chain, "p1", "internet.read")
	result, err = chain.Dispatch(context.Background(), testCred{id: "p1"}, declassify,
		sys.Authorization{Decision: sys.Approved, Actor: "alice"})
	if err != nil {
		t.Fatalf("approved declassify: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("approved declassify = %#v", result)
	}
	if result := call(t, chain, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("declassified k8s.delete = %#v, want result", result)
	}

	// Crash-replay: a fresh host replays the journal. The declassification is
	// served from the tape — zero Authorization, no new approval — and the
	// taint removal re-applies in order.
	crashed := newChain(t)
	call(t, crashed, "p1", "internet.read")
	if result := call(t, crashed, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("replayed pre-crossing call escaped denial: %#v", result)
	}
	result, err = crashed.Dispatch(context.Background(), testCred{id: "p1"}, declassify, sys.Authorization{})
	if err != nil {
		t.Fatalf("replayed declassify: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("replayed declassify = %#v, want the journaled result", result)
	}
	if result := call(t, crashed, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("post-replay k8s.delete = %#v, want result", result)
	}
	if err := journaled.Verify(journal); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDeclassifyValidatesRequest(t *testing.T) {
	table := flowTable(t, echo)
	declassifier := NewDeclassifier(capability.NewDispatcher[testCred](table))
	for name, args := range map[string]string{
		"no labels": `{"labels":[],"reason":"r"}`,
		"no reason": `{"labels":["x"],"reason":"  "}`,
		"bad json":  `{`,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := declassifier.Dispatch(context.Background(), testCred{id: "p1"},
				sys.Syscall{Abi: sys.ABIVersion, Name: sys.SyscallDeclassify, Args: json.RawMessage(args)},
				sys.Authorization{Decision: sys.Approved})
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
				t.Fatalf("result = %#v, want failed/invalid_args", result)
			}
		})
	}
}

func TestFlowGuardHandsTaintDownstream(t *testing.T) {
	var seen []string
	probe := handlerFunc(func(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
		if call.Name == "mail.send" {
			seen = capability.Taint(ctx)
		}
		return sys.Result(nil), nil
	})
	flow, below := stamped(t, flowTable(t, probe), NewTaints[testCred]())
	guarded := flow.Guard(below)

	call(t, guarded, "p1", "internet.read")
	call(t, guarded, "p1", "mail.send")
	if !slices.Contains(seen, "untrusted_web") {
		t.Fatalf("downstream taint = %v, want untrusted_web", seen)
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
	chain := flow.Guard(below)

	// A read stamps its own source class and taints the run.
	result := adtCall(t, chain, "read")
	if !slices.Contains(result.Labels(), "untrusted_file") {
		t.Fatalf("labels = %v, want the read's own source class", result.Labels())
	}

	// The write forbids what the read produced, so it is refused — while the
	// read, which forbids nothing, still is not.
	if blocked := adtCall(t, chain, "write"); blocked.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want denied by the write's sink guard", blocked.Errno())
	}
	if again := adtCall(t, chain, "read"); again.Status() != sys.StatusResult {
		t.Fatalf("read after taint = %v, want it still permitted", again.Status())
	}
}

// An unresolvable case must not be a way past the sink guard. No single entry's
// bar is the right one — the table cannot tell which case the call is — so it
// answers with every case's, unioned. Here the write's bar applies to a call
// that named no readable operation, even though the read declares none.
func TestUnresolvableCaseTakesTheStrictestBar(t *testing.T) {
	table := adtTable(t)
	flow, below := stamped(t, table, NewTaints[testCred]())
	chain := flow.Guard(below)

	adtCall(t, chain, "read") // taints the run with untrusted_file

	result, err := chain.Dispatch(context.Background(), testCred{id: "p1"}, sys.Syscall{
		Abi:  sys.ABIVersion,
		Name: "core.filesystem",
		Args: json.RawMessage(`{"operation":42}`),
	}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want the strictest case's bar to deny a call whose case cannot be read", result.Errno())
	}
}

// A failed result is still an observation: the call reached a labelled source
// and the failure text may carry what it saw. Stamp labels it like any other
// outcome, which is why a driver need not — and must not — label its own
// failures. openaillm relied on doing that itself until its policy moved onto
// its entries; this is the guarantee it now leans on.
func TestStampLabelsFailuresToo(t *testing.T) {
	failing := handlerFunc(func(_ context.Context, _ sys.Syscall) (sys.SyscallResult, error) {
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
