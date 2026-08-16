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

func call(t *testing.T, d sys.Dispatcher[testPID], pid string, name string) sys.SyscallResult {
	t.Helper()
	result, err := d.Dispatch(context.Background(), testPID{id: pid}, sys.Syscall{Abi: sys.ABIVersion, Name: name}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", name, err)
	}
	return result
}

// stamped is the below-the-tape half over the table's own routing dispatcher:
// the index that resolves the call is the index the labels come from.
func stamped(t *testing.T, table *capability.Table, taints *Taints[string]) (*Flow[string, testPID], sys.Dispatcher[testPID]) {
	t.Helper()
	flow := NewFlow[string, testPID](taints, table)
	return flow, flow.Stamp(capability.NewDispatcher[testPID](table))
}

func TestStampRecordsDerivingCapabilityAndClasses(t *testing.T) {
	table := flowTable(t, echo)
	_, below := stamped(t, table, NewTaints[string]())
	result := call(t, below, "p1", "internet.read")

	labels := result.Labels()
	for _, want := range []string{"syscall:internet.read", "untrusted_web"} {
		if !slices.Contains(labels, want) {
			t.Fatalf("labels = %v, want %q present", labels, want)
		}
	}
}

func TestFlowGuardBlocksTaintedFlow(t *testing.T) {
	flow, below := stamped(t, flowTable(t, echo), NewTaints[string]())
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
	taints := NewTaints[string]()
	flow, below := stamped(t, flowTable(t, echo), taints)
	guarded := flow.Guard(below)
	call(t, guarded, "p1", "internet.read")

	if result := call(t, guarded, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("expected denial before declassification, got %#v", result)
	}
	taints.Declassify("p1", "untrusted_web")
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

	newChain := func(t *testing.T) sys.Dispatcher[testPID] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		flow, below := stamped(t, table, NewTaints[string]())
		return flow.Guard(replay.NewDispatcher[testPID](tape, below))
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
	newChain := func(t *testing.T) sys.Dispatcher[testPID] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		flow := NewFlow[string, testPID](NewTaints[string](), table)
		below := flow.Stamp(NewDeclassifier[testPID](capability.NewDispatcher[testPID](table)))
		return flow.Guard(replay.NewDispatcher[testPID](tape, below))
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
	result, err := chain.Dispatch(context.Background(), testPID{id: "p1"}, declassify, sys.Authorization{})
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
	result, err = chain.Dispatch(context.Background(), testPID{id: "p1"}, declassify,
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
	result, err = crashed.Dispatch(context.Background(), testPID{id: "p1"}, declassify, sys.Authorization{})
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
	declassifier := NewDeclassifier[testPID](capability.NewDispatcher[testPID](table))
	for name, args := range map[string]string{
		"no labels": `{"labels":[],"reason":"r"}`,
		"no reason": `{"labels":["x"],"reason":"  "}`,
		"bad json":  `{`,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := declassifier.Dispatch(context.Background(), testPID{id: "p1"},
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
	flow, below := stamped(t, flowTable(t, probe), NewTaints[string]())
	guarded := flow.Guard(below)

	call(t, guarded, "p1", "internet.read")
	call(t, guarded, "p1", "mail.send")
	if !slices.Contains(seen, "untrusted_web") {
		t.Fatalf("downstream taint = %v, want untrusted_web", seen)
	}
}

func adtCall(t *testing.T, d sys.Dispatcher[testPID], operation string) sys.SyscallResult {
	t.Helper()
	result, err := d.Dispatch(context.Background(), testPID{id: "p1"}, sys.Syscall{
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
// write that is a sink, plus a family-wide bar the write cannot escape.
func adtTable(t *testing.T, familyForbid []string) *capability.Table {
	t.Helper()
	table := capability.NewTable()
	err := table.Add(capability.Family{
		Discriminator: "operation",
		Forbid:        familyForbid,
		Entries: []capability.Entry{
			{Key: capability.Key{Syscall: "core.filesystem", Operation: "read"}, Labels: []string{"untrusted_file"}, Handler: echo},
			{Key: capability.Key{Syscall: "core.filesystem", Operation: "write"}, Forbid: []string{"untrusted_file"}, Handler: echo},
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
	table := adtTable(t, nil)
	flow, below := stamped(t, table, NewTaints[string]())
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

// A family-wide bar applies to every case, including one that declares no bar of
// its own: the table folds it in at indexing time, so there is no case a call can
// name to reach the family with less policy than the family declared.
func TestFamilyForbidCannotBeEscapedByCase(t *testing.T) {
	table := adtTable(t, []string{"untrusted_file"})
	flow, below := stamped(t, table, NewTaints[string]())
	chain := flow.Guard(below)

	adtCall(t, chain, "read") // taints the run with untrusted_file
	// "read" declares no Forbid of its own, but the family does.
	if blocked := adtCall(t, chain, "read"); blocked.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want the family-wide bar to apply to the read case", blocked.Errno())
	}
}

// An unresolvable case must not be a way past the sink guard: the discriminator
// is unreadable, so no entry applies, and the family's own bar is what answers.
func TestUnresolvableCaseFallsBackToFamilyBar(t *testing.T) {
	table := adtTable(t, []string{"untrusted_file"})
	flow, below := stamped(t, table, NewTaints[string]())
	chain := flow.Guard(below)

	adtCall(t, chain, "read") // taints the run

	result, err := chain.Dispatch(context.Background(), testPID{id: "p1"}, sys.Syscall{
		Abi:  sys.ABIVersion,
		Name: "core.filesystem",
		Args: json.RawMessage(`{"operation":42}`),
	}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %v, want the family bar to deny a call whose case cannot be read", result.Errno())
	}
}

// The permitted set is the index minus what the run's taint bars, and it must
// track Guard exactly: anything it still lists must actually dispatch, and
// anything it drops must actually be denied. Deriving it rather than caching it
// is what makes that hold.
func TestPermittedSetTracksTheGuard(t *testing.T) {
	table := adtTable(t, nil)
	flow, below := stamped(t, table, NewTaints[string]())
	chain := flow.Guard(below)

	permitted := flow.Permitted("p1")
	if len(permitted) != 2 {
		t.Fatalf("permitted = %v, want both cases reachable before any taint", permitted)
	}

	adtCall(t, chain, "read") // taints the run with untrusted_file

	permitted = flow.Permitted("p1")
	if len(permitted) != 1 || permitted[0].Operation != "read" {
		t.Fatalf("permitted = %v, want the write dropped and the read kept", permitted)
	}
	// What the set claims is what the guard does, in both directions.
	if blocked := adtCall(t, chain, "write"); blocked.Errno() != sys.ErrnoDenied {
		t.Fatalf("write = %v, want denied — the permitted set dropped it", blocked.Errno())
	}
	if allowed := adtCall(t, chain, "read"); allowed.Status() != sys.StatusResult {
		t.Fatalf("read = %v, want served — the permitted set kept it", allowed.Status())
	}

	// A declassification grows the set back.
	flow.taints.Declassify("p1", "untrusted_file")
	if permitted = flow.Permitted("p1"); len(permitted) != 2 {
		t.Fatalf("permitted after declassify = %v, want both cases reachable again", permitted)
	}
}

// A flow layer with no index would answer every sink guard with "no policy" —
// the one wrong answer a reference monitor can give. It refuses to exist.
func TestFlowRefusesToBeBuiltWithoutAnIndex(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a flow layer with no grant table was built instead of panicking")
		}
	}()
	NewFlow[string, testPID](NewTaints[string](), nil)
}
