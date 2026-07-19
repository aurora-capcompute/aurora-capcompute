package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

// C1: a completed child's taint must ride its spawn result so the parent's
// FlowMonitor observes what the child observed — a parent cannot launder a
// forbidden source by delegating the read to a child and reading it back.
func TestSpawnAnswerStampsChildLabels(t *testing.T) {
	result, err := spawnAnswer("done", "untrusted_web", "secret")
	if err != nil {
		t.Fatalf("spawnAnswer: %v", err)
	}
	got := map[string]bool{}
	for _, l := range result.Labels() {
		got[l] = true
	}
	if len(got) != 2 || !got["untrusted_web"] || !got["secret"] {
		t.Fatalf("spawn result labels = %v, want the child's taint stamped", result.Labels())
	}
}

// C1: the child's terminal snapshot carries its taint out of waitForCompletion,
// which is where the spawn result gets it — on the completed path AND on every
// failed/rolled-back path. The spawn call sites stamp these labels on their
// error returns too, so a child cannot launder an observed source to the parent
// through a (guest-controlled) failure or abort reason.
func TestChildTerminalCarriesLabels(t *testing.T) {
	answer, labels, done, err := childTerminal(ProcessSnapshot{
		Status: ProcessCompleted, Answer: "a", Labels: []string{"untrusted_web"},
	})
	if !done || err != nil || answer != "a" {
		t.Fatalf("childTerminal = %q, %v, %v, %v", answer, labels, done, err)
	}
	if len(labels) != 1 || labels[0] != "untrusted_web" {
		t.Fatalf("labels = %v, want the snapshot's taint", labels)
	}

	// The error terminals must carry the taint too — these are the states the
	// spawn error branches propagate. ProcessCompensated is the sharpest: its
	// error text embeds the guest's rollback reason, which can carry read data.
	for _, status := range []ProcessStatus{ProcessFailed, ProcessStopped, ProcessInterrupted, ProcessCompensated} {
		_, labels, done, err := childTerminal(ProcessSnapshot{
			Status: status, Answer: "leak", Labels: []string{"secret"},
		})
		if !done || err == nil {
			t.Fatalf("childTerminal(%s) = done %v, err %v, want a terminal error", status, done, err)
		}
		if len(labels) != 1 || labels[0] != "secret" {
			t.Fatalf("childTerminal(%s) labels = %v, want the child's taint carried on the error", status, labels)
		}
	}
}

// H1: a deferred compensation is held to the reference monitor at registration,
// because the rollback path that fires it at abort time re-runs neither the
// Validator nor the FlowMonitor. So: an ungranted inverse is refused, a
// schema-violating inverse is refused, and a run that has observed a forbidden
// label may not register that sink as an undo (the abort-time flow bypass).
func TestLifecycleCompensateHeldToReferenceMonitor(t *testing.T) {
	next := nopNext{caps: []sys.Capability{{
		Name:        "k8s.delete",
		InputSchema: json.RawMessage(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}},"additionalProperties":false}`),
		Forbid:      []string{"untrusted_web"},
	}}}
	l := newLifecycleDispatcher(next, "msg", nil, nil, Manifest{}, 1, nil)
	compensate := func(ctx context.Context, args string) sys.SyscallResult {
		t.Helper()
		result, err := l.Dispatch(ctx, ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: callSysCompensate, Args: json.RawMessage(args)},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return result
	}

	if r := compensate(context.Background(), `{"name":"k8s.delete","args":{"name":"pod-1"}}`); r.Status() != sys.StatusResult {
		t.Fatalf("a clean compensation should register: got %v", r.Status())
	}
	if r := compensate(context.Background(), `{"name":"k8s.forge","args":{}}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("ungranted inverse = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
	if r := compensate(context.Background(), `{"name":"k8s.delete","args":{"oops":true}}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("schema-violating inverse = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
	tainted := sys.WithTaint(context.Background(), []string{"untrusted_web"})
	if r := compensate(tainted, `{"name":"k8s.delete","args":{"name":"pod-1"}}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoDenied {
		t.Fatalf("compensation in a tainted run = %v/%v, want failed/denied (abort-time flow bypass blocked)", r.Status(), r.Errno())
	}
}

// L6: the guest's sys.input payload must carry role/content only — the taint
// labels seed the FlowMonitor host-side and must never be serialized to the
// (untrusted) guest, so the property is host-enforced, not a guest struct shape.
func TestSysInputOmitsHistoryLabelsFromGuestPayload(t *testing.T) {
	history := []HistoryMessage{
		{Role: "user", Content: "q"},
		{Role: "assistant", Content: "a", Labels: []string{"untrusted_web", "credential:ONYX@abc"}},
	}
	l := newLifecycleDispatcher(nopNext{}, "task", nil, history, Manifest{}, 1, nil)
	result, err := l.Dispatch(context.Background(), ProcessContext{},
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysInput}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	for _, needle := range []string{"labels", "untrusted_web", "credential:ONYX@abc"} {
		if bytes.Contains(result.Result(), []byte(needle)) {
			t.Fatalf("SECURITY: %q reached the guest sys.input payload: %s", needle, result.Result())
		}
	}
	// The taint still seeds the run host-side: the result carries the labels for
	// the FlowMonitor even though the guest payload does not.
	if len(result.Labels()) == 0 {
		t.Fatal("sys.input result must carry the history taint for the FlowMonitor")
	}
}

// L3: only sys.spawn carries programs; a sys.timer grant with a stray programs
// field is rejected (an un-recursed, un-validated child manifest must not ride
// along).
func TestValidateManifestRejectsTimerWithPrograms(t *testing.T) {
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: TimerSyscall, Programs: []Manifest{{Program: "x"}}}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("expected sys.timer with programs to be rejected")
	}
}

// L4: cloneManifest deep-copies the History/ShareCapabilities pointers, so a
// caller that retains the input manifest cannot mutate a stored clone.
func TestCloneManifestDeepCopiesPointers(t *testing.T) {
	yes := true
	original := Manifest{History: &yes, ShareCapabilities: &yes}
	clone := cloneManifest(original)
	*original.History = false
	*original.ShareCapabilities = false
	if !clone.sharesHistory() || !clone.sharesCapabilities() {
		t.Fatal("mutating the original manifest's pointers changed the clone's settings")
	}
}

// Declassify is grantable, opt-in per program: a bare grant validates; one that
// carries settings or programs is refused.
func TestValidateManifestDeclassifyGrant(t *testing.T) {
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Program:  "root",
		Syscalls: []Syscall{{Syscall: DeclassifySyscall}},
	}, &testDispatchers{}); err != nil {
		t.Fatalf("a bare sys.declassify grant should validate: %v", err)
	}
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: DeclassifySyscall, Config: json.RawMessage(`{"x":1}`)}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("sys.declassify with settings should be rejected")
	}
	if _, err := ValidateManifest(Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Syscall: DeclassifySyscall, Programs: []Manifest{{Program: "x"}}}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("sys.declassify with programs should be rejected")
	}
}

// The lifecycle admits sys.declassify to the grant set ONLY when the manifest
// grants it — so the Validator accepts the call opt-in — and advertises it
// (not hidden) so the model can discover and request it. The kernel Declassifier
// still gates every crossing on human approval, so this only makes the governed
// path reachable; it does not let the guest self-lift.
func TestLifecyclePublishesDeclassifyWhenGranted(t *testing.T) {
	granted := newLifecycleDispatcher(nopNext{}, "msg", nil, nil,
		Manifest{Syscalls: []Syscall{{Syscall: DeclassifySyscall}}}, 1, nil)
	cap, ok := sys.FindCapability(granted.Capabilities(), DeclassifySyscall)
	if !ok {
		t.Fatal("a manifest granting sys.declassify must advertise it in the grant set")
	}
	if cap.Hidden {
		t.Fatal("sys.declassify should be visible so the model can request it")
	}
	if len(cap.InputSchema) == 0 {
		t.Fatal("sys.declassify must carry an input schema for the Validator")
	}
	ungranted := newLifecycleDispatcher(nopNext{}, "msg", nil, nil, Manifest{}, 1, nil)
	if _, ok := sys.FindCapability(ungranted.Capabilities(), DeclassifySyscall); ok {
		t.Fatal("sys.declassify must not appear unless the manifest grants it (opt-in)")
	}
}

// Decision #3: a non-idempotent capability's open intent is failed (surfaced
// for review) rather than silently retried on crash-resume; everything else
// retries; an empty set disables the policy (framework default).
func TestOpenIntentPolicy(t *testing.T) {
	if openIntentPolicy(nil) != nil {
		t.Fatal("empty set should yield nil (retry everything)")
	}
	if openIntentPolicy([]string{"", "  "}) != nil {
		t.Fatal("only-blank names should yield nil")
	}
	policy := openIntentPolicy([]string{"payments.charge"})
	if policy == nil {
		t.Fatal("a non-empty set should yield a policy")
	}
	if got := policy(sys.Syscall{Name: "payments.charge"}); got != replay.FailOpenIntent {
		t.Fatalf("non-idempotent syscall = %v, want FailOpenIntent (no silent at-least-once)", got)
	}
	if got := policy(sys.Syscall{Name: "core.read"}); got != replay.RetryOpenIntent {
		t.Fatalf("ordinary syscall = %v, want RetryOpenIntent", got)
	}
}

// A guest-supplied duration_seconds large enough to overflow int64 nanoseconds
// must be rejected — not accepted via a wrapped-negative Duration slipping past
// the max-duration bound.
func TestTimerRejectsOverflowingDuration(t *testing.T) {
	td := &timerDispatcher{next: nopNext{}, maxDuration: defaultMaxTimer}
	dispatch := func(seconds int64) sys.SyscallResult {
		t.Helper()
		r, err := td.Dispatch(context.Background(), ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: TimerSyscall,
				Args: json.RawMessage(fmt.Sprintf(`{"duration_seconds":%d}`, seconds))},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return r
	}
	if r := dispatch(1 << 62); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("overflowing duration = %v/%v, want failed/invalid_args (bound must not be bypassed)", r.Status(), r.Errno())
	}
	if r := dispatch(int64(defaultMaxTimer/time.Second) + 1); r.Status() != sys.StatusFailed {
		t.Fatalf("over-max duration = %v, want failed", r.Status())
	}
	if r := dispatch(60); r.Status() != sys.StatusYield {
		t.Fatalf("a valid 60s timer = %v, want yield", r.Status())
	}
}
