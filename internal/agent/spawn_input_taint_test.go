package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// C2 — the downward mirror of C1: a delegated child's input is composed by its
// parent from whatever the parent had observed, so the parent's taint must
// enter the child with it. Without the seed, a tainted parent launders by
// embedding observed data in the input of a fresh, untainted child whose
// manifest grants the guarded sink.

// The lifecycle stamps the input's provenance (a child's parent-taint snapshot)
// on the sys.input result, unioned with the history labels, so the child's
// FlowMonitor observes what the parent had observed.
func TestSysInputStampsInputLabels(t *testing.T) {
	history := []HistoryMessage{{Role: "assistant", Content: "prior", Labels: []string{"untrusted_web"}}}
	l := newLifecycleDispatcher(nopNext{}, "summarize: <data the parent read>", []string{"onyx_data"},
		history, Manifest{}, 1, nil)

	result, err := l.Dispatch(context.Background(), ProcessContext{},
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysInput}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch sys.input: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("sys.input = %v, want a result", result.Status())
	}
	for _, want := range []string{"onyx_data", "untrusted_web"} {
		if !slices.Contains(result.Labels(), want) {
			t.Fatalf("sys.input labels = %v, want both the input's and the history's taint (%s)", result.Labels(), want)
		}
	}
	// The labels seed the FlowMonitor host-side and must never be serialized to
	// the (untrusted) guest payload — same guarantee as the history labels.
	if strings.Contains(string(result.Result()), "onyx_data") {
		t.Fatalf("SECURITY: input labels reached the guest payload: %s", result.Result())
	}
}

// The input seed persists: storedProcessLocked carries it out and a restart
// re-serves sys.input with the same taint — the parent→child flow policy
// survives a crash exactly like the cross-run one.
func TestStoredProcessCarriesInputLabels(t *testing.T) {
	r := &Runtime{}
	stored := r.storedProcessLocked(&processState{
		id: "proc_1", sessionID: "ses_1", inputLabels: []string{"onyx_data"},
	})
	if len(stored.InputLabels) != 1 || stored.InputLabels[0] != "onyx_data" {
		t.Fatalf("StoredProcess.InputLabels = %v, want the input seed persisted", stored.InputLabels)
	}
}

// spawnTaintDispatchers scripts the laundering attempt: the parent reads a
// labeled source (onyx.search, granted to the parent only), then delegates a
// subtask whose input it composed; the child immediately finishes — it reads
// nothing but its own input. The provider advertises per-manifest, so the
// reconciliation guard sees exactly the granted set for parent and child.
type spawnTaintDispatchers struct{}

func (spawnTaintDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (spawnTaintDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, manifest Manifest) (sys.Dispatcher[ProcessContext], error) {
	return spawnTaintDispatcher{manifest: manifest}, nil
}

type spawnTaintDispatcher struct{ manifest Manifest }

func (d spawnTaintDispatcher) Capabilities() []sys.Capability {
	caps := []sys.Capability{llmCapability()}
	if _, ok := d.manifest.grant("onyx.search"); ok {
		caps = append(caps, sys.Capability{Name: "onyx.search", Description: "search the trusted KB"})
	}
	return caps
}

func (d spawnTaintDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "onyx.search":
		// The labeled source: its result taints the (parent) run.
		return sys.Result(json.RawMessage(`"kb says 42"`)).WithLabels("onyx_data"), nil
	case "core.openaiApi":
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(syscall.Args, &req)
	var first string
	users := 0
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		if users == 0 {
			first = m.Content
		}
		users++
	}
	switch {
	case strings.Contains(first, "do subtask"):
		// The child: finishes on its first turn, having read only its input.
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"child-done"}}]}`), nil
	case users <= 1:
		// Parent turn 1: read the labeled source.
		return chatActions(`{"actions":[{"action":"onyx.search","content":{"q":"answer"}}]}`), nil
	case users == 2:
		// Parent turn 2 (source observed, run now tainted): delegate.
		return chatActions(`{"actions":[{"action":"sys.spawn","content":{"program":"program@1","input":"do subtask with what I read"}}]}`), nil
	default:
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"parent-done"}}]}`), nil
	}
}

// End to end through the real runtime: the parent taints itself on a labeled
// source and spawns a child that does nothing but read its input and finish.
// The child's manifest grants no labeled source, so the only way onyx_data can
// appear on the child is the parent-taint seed riding its sys.input — the
// downward laundering path is closed, and the seed survives a restart.
func TestSpawnSeedsChildWithParentTaint(t *testing.T) {
	store := newRuntimeStore()
	newRT := func() *Runtime {
		t.Helper()
		runtime, err := NewRuntime(context.Background(), Config{
			Programs: staticPrograms{
				defaultID: "program@1",
				sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
			},
			Dispatchers: spawnTaintDispatchers{},
			Log:         store.log,
			Leases:      store,
			TaskSecret:  []byte("stable-secret"),
			IDSource:    sequentialIDs(),
		})
		if err != nil {
			t.Fatalf("new runtime: %v", err)
		}
		return runtime
	}
	closeRT := func(runtime *Runtime) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	}
	runtime := newRT()

	session, err := runtime.CreateSession("", nil)
	if err != nil {
		closeRT(runtime)
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "parent task", Manifest{
		Version: ManifestVersion,
		Program: "program@1",
		Syscalls: []Syscall{
			{Syscall: SpawnSyscall, Programs: []Manifest{{Program: "program@1", Syscalls: cognitionGrants()}}},
			{Syscall: "core.openaiApi", Hidden: true},
			{Syscall: "onyx.search"},
		},
	})
	if err != nil {
		closeRT(runtime)
		t.Fatalf("create run: %v", err)
	}
	if first := waitForStatus(t, runtime, proc.ID, ProcessCompleted); first.Answer != "parent-done" {
		closeRT(runtime)
		t.Fatalf("parent answer = %q, want parent-done", first.Answer)
	}
	childID := onlyChildProcess(t, runtime, proc.ID)

	// The child's accumulated taint carries the parent's label it never read
	// itself — the seed worked.
	child, err := runtime.GetProcess(childID)
	if err != nil {
		closeRT(runtime)
		t.Fatalf("get child: %v", err)
	}
	if !slices.Contains(child.Labels, "onyx_data") {
		closeRT(runtime)
		t.Fatalf("child labels = %v, want the parent's onyx_data taint seeded through its input", child.Labels)
	}

	// The seed is visible at the exact journaled entry that carried it: the
	// child's sys.input outcome — so replay re-observes it deterministically.
	entries, err := runtime.Journal(childID)
	if err != nil || len(entries) == 0 {
		closeRT(runtime)
		t.Fatalf("child journal: %v (%d entries)", err, len(entries))
	}
	if entries[0].Syscall.Name != callSysInput || !slices.Contains(entries[0].Outcome.Labels, "onyx_data") {
		closeRT(runtime)
		t.Fatalf("child journal[0] = %s %v, want sys.input stamped with onyx_data", entries[0].Syscall.Name, entries[0].Outcome.Labels)
	}
	closeRT(runtime)

	// Restart from the same store: the restored child still carries the input
	// seed, so a revision restart would re-serve sys.input with the same taint.
	restarted := newRT()
	defer closeRT(restarted)
	restarted.mu.Lock()
	restored := restarted.processes[childID]
	var restoredSeed []string
	if restored != nil {
		restoredSeed = append([]string(nil), restored.inputLabels...)
	}
	restarted.mu.Unlock()
	if restored == nil || !slices.Contains(restoredSeed, "onyx_data") {
		t.Fatalf("restored child inputLabels = %v, want the persisted parent-taint seed", restoredSeed)
	}
}
