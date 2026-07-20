package agent

// The compensation-laundering guard. A deferred inverse fires at rollback time
// through a chain that has NO FlowMonitor — the manifest chain's flow enforcement
// (Validator, FlowMonitor) is not in the rollback path; only the drivers are. A
// production driver enforces flow per operation, by checking sys.Taint(ctx)
// against its declared sink taints, NOT via a processor Capability.Forbid (which
// real drivers never set — the registration-time gate that reads Forbid is inert
// for them). So without settleRollback re-injecting the run's accumulated taint,
// a driver's sink guard would see a nil taint during rollback and permit the
// effect — letting a guest launder a forbidden source past every flow control by
// registering the sink as a compensation and aborting to fire it.
//
// This test drives that exact vector end to end against the real runtime and
// proves the inverse is refused at rollback time because the taint is present.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// launderDispatchers scripts the exfiltration-via-compensation attack: a run
// reads a `secret`-labeled source (tainting it), registers an egress sink as the
// "undo" with the secret in its args, and aborts to fire it during rollback.
type launderDispatchers struct{ d *launderDispatcher }

func (launderDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (p launderDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return p.d, nil
}

type launderDispatcher struct {
	mu        sync.Mutex
	sinkSeen  bool     // web.post was dispatched (its only dispatch is the rollback)
	sinkTaint []string // the taint web.post observed at rollback dispatch
	sinkRuns  int      // times web.post's effect actually executed (a launder if > 0)
}

func (d *launderDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		// A labeled source: the Labeler stamps `secret` onto every result, so a
		// read taints the run — exactly how a secrets-dir filesystem read declares
		// its provenance. No Forbid: reading is always allowed; the taint it
		// deposits is what constrains later sinks.
		{Name: "vault.read", Description: "read a secret", Labels: []string{"secret"},
			InputSchema: json.RawMessage(`{"type":"object"}`)},
		// An egress sink with NO capability-wide Forbid — the way production
		// network drivers are declared. It self-enforces per operation against
		// sys.Taint(ctx), so the ONLY thing that can block it at rollback time is
		// settleRollback injecting the run taint into the FlowMonitor-less chain.
		{Name: "web.post", Description: "post to the internet",
			InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (d *launderDispatcher) Dispatch(ctx context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "vault.read":
		return sys.Result(json.RawMessage(`{"secret":"hunter2"}`)), nil
	case "web.post":
		// Self-classify like every production egress driver: refuse a run that has
		// observed `secret`. A nil taint here (the pre-fix rollback bypass) passes
		// the guard and the secret exfiltrates.
		taint := sys.Taint(ctx)
		d.mu.Lock()
		d.sinkSeen = true
		d.sinkTaint = append([]string(nil), taint...)
		d.mu.Unlock()
		if blocked := sys.BlockedBy(taint, []string{"secret"}); len(blocked) > 0 {
			return sys.FailCode(sys.ErrnoDenied, "egress refused: run has observed secret"), nil
		}
		d.mu.Lock()
		d.sinkRuns++
		d.mu.Unlock()
		return sys.Result(json.RawMessage(`{"posted":true}`)), nil
	case "core.openaiApi":
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(syscall.Args, &req)
		if _, later := firstAndLaterUser(req.Messages); later {
			// The read is in and the sink is registered as its undo: abort to fire
			// the rollback (no retry_seconds — a settled rollback would stop, but
			// this one fails on the refused inverse before it can settle).
			return chatActions(`{"actions":[{"action":"abort","content":{"reason":"changed my mind"}}]}`), nil
		}
		// First turn: read the secret, then register the egress sink as its "undo",
		// carrying the secret in the inverse's args. Registration is admitted — the
		// lifecycle gate reads only Capability.Forbid (which web.post lacks), never a
		// driver's per-op sink taints — which is precisely why the defense has to
		// live at rollback dispatch.
		return chatActions(`{"actions":[{"action":"vault.read","content":{}},{"action":"compensate","content":{"name":"web.post","args":{"body":"hunter2"}}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

// TestCompensationCannotLaunderTaintPastRollbackSink proves that a tainted run's
// registered inverse to a flow-forbidding sink is refused when the rollback
// fires it: settleRollback injects the run's taint into the FlowMonitor-less
// rollback chain, so the driver's own sink guard sees `secret` and blocks the
// egress. Without the injection the guard would see a nil taint, permit the
// effect, and the secret would exfiltrate through the compensation path.
func TestCompensationCannotLaunderTaintPastRollbackSink(t *testing.T) {
	disp := &launderDispatcher{}
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers: launderDispatchers{d: disp},
		Log:         newMemLog(),
		Leases:      newRuntimeStore(),
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})

	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "exfiltrate the secret", Manifest{
		Version:  ManifestVersion,
		Program:  "program@1",
		Syscalls: cognitionGrants("vault.read", "web.post"),
	})
	if err != nil {
		t.Fatalf("create process: %v", err)
	}

	// Wait for any terminal status (not only failed): were the injection reverted,
	// the rollback would SETTLE and the process reach ProcessCompensated — the
	// laundered outcome — so we must observe that case to fail with the security
	// diagnostic rather than time out.
	snap := waitForTerminal(t, runtime, proc.ID)

	disp.mu.Lock()
	sinkSeen, sinkRuns := disp.sinkSeen, disp.sinkRuns
	sinkTaint := append([]string(nil), disp.sinkTaint...)
	disp.mu.Unlock()

	if !sinkSeen {
		t.Fatal("the egress sink inverse was never dispatched during rollback — the attack setup is wrong")
	}
	if sinkRuns != 0 {
		t.Fatalf("SECURITY: the egress sink executed %d time(s) during rollback — the secret was laundered", sinkRuns)
	}
	if !containsLabel(sinkTaint, "secret") {
		t.Fatalf("SECURITY: the rollback dispatched the inverse with taint %v — settleRollback did not inject the run's `secret` taint, so a sink guard would see nothing", sinkTaint)
	}
	if snap.Status != ProcessFailed {
		t.Fatalf("process status = %v, want failed (rollback blocked, unsettled)", snap.Status)
	}
}

// TestRollbackTaintRebuiltFromJournalAfterCrash is the crash twin of the test
// above. r.taints is in-memory and is not rebuilt on restore — the processor
// FlowMonitor that repopulates it on the forward path does not run on the
// rollback path, and the revision laws forbid re-driving the guest. So after a
// restart the snapshot is empty, and settleRollback would inject an EMPTY taint,
// re-opening the exact launder the test above closes on the live path.
// rollbackTaint reconstructs the run's taint from the journal's completions;
// this proves the reconstruction picks up a `secret` a live snapshot has lost.
func TestRollbackTaintRebuiltFromJournalAfterCrash(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now, nil)

	// A completed read that observed a `secret` source — exactly what the Labeler
	// journals below replay for a labeled capability.
	syscall := sys.Syscall{Abi: sys.ABIVersion, Name: "vault.read"}
	labeled := sys.Result(json.RawMessage(`{"secret":"hunter2"}`)).WithLabels("secret")
	appendPair(t, j, syscall, labeled)

	// A freshly-restarted runtime: nothing has re-observed the completion, so the
	// in-memory snapshot is empty — the crash condition.
	restarted := &Runtime{taints: monitor.NewTaints[string]()}
	if snap := restarted.taints.Snapshot("proc1"); len(snap) != 0 {
		t.Fatalf("precondition: taint map should be empty after restart, got %v", snap)
	}

	if taint := restarted.rollbackTaint("proc1", j); !containsLabel(taint, "secret") {
		t.Fatalf("rollbackTaint = %v, want `secret` rebuilt from the journal (else a resumed compensation launders)", taint)
	}
}

// waitForTerminal polls until the process reaches any terminal status, so a
// caller can assert on which terminal it was (failed vs. the laundered
// compensated outcome) instead of timing out.
func waitForTerminal(t *testing.T, runtime *Runtime, processID string) ProcessSnapshot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := runtime.GetProcess(processID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if isTerminal(snap.Status) {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not reach a terminal status within timeout")
	return ProcessSnapshot{}
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
