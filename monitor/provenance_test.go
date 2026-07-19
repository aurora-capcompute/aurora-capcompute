package monitor

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

var flowCaps = []sys.Capability{
	{Name: "internet.read", Labels: []string{"untrusted_web"}},
	{Name: "k8s.delete", Forbid: []string{"untrusted_web"}},
	{Name: "mail.send"},
}

type flowDriver struct{}

func (flowDriver) Dispatch(_ context.Context, _ testPID, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	return sys.Result(json.RawMessage(`{"from":"` + syscall.Name + `"}`)), nil
}

func (flowDriver) Capabilities() []sys.Capability { return flowCaps }

func call(t *testing.T, d sys.Dispatcher[testPID], pid string, name string) sys.SyscallResult {
	t.Helper()
	result, err := d.Dispatch(context.Background(), testPID{id: pid}, sys.Syscall{Abi: sys.ABIVersion, Name: name}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch %s: %v", name, err)
	}
	return result
}

func TestLabelerStampsDerivingCapabilityAndClasses(t *testing.T) {
	labeler := NewLabeler[testPID](flowDriver{})
	result := call(t, labeler, "p1", "internet.read")

	labels := result.Labels()
	for _, want := range []string{"syscall:internet.read", "untrusted_web"} {
		if !slices.Contains(labels, want) {
			t.Fatalf("labels = %v, want %q present", labels, want)
		}
	}
}

func TestFlowMonitorBlocksTaintedFlow(t *testing.T) {
	monitor := NewFlowMonitor(NewTaints[string](), NewLabeler[testPID](flowDriver{}))

	// Before any taint the protected capability is callable.
	if result := call(t, monitor, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("untainted k8s.delete = %#v, want result", result)
	}

	// Observing untrusted data taints the run…
	call(t, monitor, "p1", "internet.read")

	// …so the protected capability is now refused…
	result := call(t, monitor, "p1", "k8s.delete")
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("tainted k8s.delete = %#v, want failed/denied", result)
	}

	// …while unprotected capabilities still work…
	if result := call(t, monitor, "p1", "mail.send"); result.Status() != sys.StatusResult {
		t.Fatalf("mail.send = %#v, want result", result)
	}

	// …and other runs are unaffected.
	if result := call(t, monitor, "p2", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("other run's k8s.delete = %#v, want result", result)
	}
}

func TestFlowMonitorDeclassify(t *testing.T) {
	taints := NewTaints[string]()
	monitor := NewFlowMonitor(taints, NewLabeler[testPID](flowDriver{}))
	call(t, monitor, "p1", "internet.read")

	if result := call(t, monitor, "p1", "k8s.delete"); result.Errno() != sys.ErrnoDenied {
		t.Fatalf("expected denial before declassification, got %#v", result)
	}
	taints.Declassify("p1", "untrusted_web")
	if result := call(t, monitor, "p1", "k8s.delete"); result.Status() != sys.StatusResult {
		t.Fatalf("declassified k8s.delete = %#v, want result", result)
	}
}

// The full chain: FlowMonitor → replay → Labeler → driver. Labels must land in
// the journal, and a crash-restarted host must rebuild the run's taint from
// replayed results alone.
func TestFlowTaintSurvivesCrashReplay(t *testing.T) {
	journal := newMemJournal()
	header := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Process: "p1"}

	newChain := func(t *testing.T) *FlowMonitor[string, testPID] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return NewFlowMonitor(NewTaints[string](), replay.NewDispatcher[testPID](tape, NewLabeler[testPID](flowDriver{})))
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

	// Crash: a fresh host process (fresh monitor, fresh tape, same journal)
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
	newChain := func(t *testing.T) *FlowMonitor[string, testPID] {
		t.Helper()
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return NewFlowMonitor(NewTaints[string](),
			replay.NewDispatcher[testPID](tape,
				NewLabeler[testPID](NewDeclassifier[testPID](flowDriver{}))))
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
	declassifier := NewDeclassifier[testPID](flowDriver{})
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

func TestFlowMonitorHandsTaintDownstream(t *testing.T) {
	var seen []string
	probe := nextFuncDispatcher(func(ctx context.Context, syscall sys.Syscall) (sys.SyscallResult, error) {
		if syscall.Name == "mail.send" {
			seen = sys.Taint(ctx)
		}
		return sys.Result(nil), nil
	})
	monitor := NewFlowMonitor(NewTaints[string](), NewLabeler[testPID](probe))

	call(t, monitor, "p1", "internet.read")
	call(t, monitor, "p1", "mail.send")
	if !slices.Contains(seen, "untrusted_web") {
		t.Fatalf("downstream taint = %v, want untrusted_web", seen)
	}
}

type nextFuncDispatcher func(ctx context.Context, syscall sys.Syscall) (sys.SyscallResult, error)

func (f nextFuncDispatcher) Dispatch(ctx context.Context, _ testPID, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	return f(ctx, syscall)
}
func (nextFuncDispatcher) Capabilities() []sys.Capability { return flowCaps }
