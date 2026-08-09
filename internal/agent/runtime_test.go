package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

type runtimeDispatchers struct {
	mu        sync.Mutex
	manifests []manifest.Manifest
}

func (*runtimeDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (p *runtimeDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, manifest manifest.Manifest) (sys.Dispatcher[ProcessContext], error) {
	p.mu.Lock()
	p.manifests = append(p.manifests, manifest.Clone())
	p.mu.Unlock()
	return finalDispatcher{}, nil
}

// llmCapability publishes the fake cognition tool the way a real assembly
// does: dispatchable, hidden from the discoverable menu, and — because the
// processor's Validator enforces complete mediation — granted explicitly.
func llmCapability() sys.Capability {
	return sys.Capability{Name: "core.openaiApi", Description: "LLM chat", Hidden: true}
}

type finalDispatcher struct{}

func (finalDispatcher) Capabilities() []sys.Capability { return []sys.Capability{llmCapability()} }

func (finalDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != "core.openaiApi" {
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
	return sys.Result(json.RawMessage(
		`{"choices":[{"message":{"content":"{\"actions\":[{\"action\":\"final\",\"content\":{\"answer\":\"done\"}}]}"}}]}`,
	)), nil
}

type runtimeStore struct {
	log    *memLog
	mu     sync.Mutex
	leases map[string]string
}

func newRuntimeStore() *runtimeStore {
	return &runtimeStore{log: newMemLog(), leases: make(map[string]string)}
}

func (s *runtimeStore) Acquire(_ context.Context, tenant, kind, resource, holder string, _ time.Time, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenant + "/" + kind + "/" + resource
	if current := s.leases[key]; current != "" && current != holder {
		return false, nil
	}
	s.leases[key] = holder
	return true, nil
}

func (s *runtimeStore) Release(_ context.Context, tenant, kind, resource, holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenant + "/" + kind + "/" + resource
	if s.leases[key] == holder {
		delete(s.leases, key)
	}
	return nil
}

// seed appends proc.state events so the runtime folds them on restore.
// Session state is derived from the runs; no separate session event is needed.
func (s *runtimeStore) seed(runs ...durable.Process) {
	now := time.Now().UTC()
	for _, r := range runs {
		ev, _ := durable.ProcessStateEvent(now, r)
		_, _ = s.log.Append(context.Background(), eventlog.Scope{TenantID: r.TenantID, SessionID: r.SessionID}, ev)
	}
}

// minRev2Index returns the lowest journal record position that has a
// revision-2 record, or -1 if none.
func (s *runtimeStore) minRev2Index(processID string) int {
	streams, _ := s.log.Streams(context.Background(), "local")
	min := -1
	for _, scope := range streams {
		events, _ := s.log.Read(context.Background(), scope, 0)
		for _, ev := range events {
			if ev.Kind != evSyscall || ev.Proc != processID || ev.Rev != 2 {
				continue
			}
			var sd syscallRecordData
			if json.Unmarshal(ev.Data, &sd) == nil {
				if min < 0 || sd.Record.Position < min {
					min = sd.Record.Position
				}
			}
		}
	}
	return min
}

func TestNewRuntimeRequiresImplementationDependencies(t *testing.T) {
	store := newRuntimeStore()
	dispatchers := &runtimeDispatchers{}
	base := Config{
		Dispatchers: dispatchers, Log: store.log,
		Leases: store, TaskSecret: []byte("secret"),
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "dispatcher provider", mutate: func(config *Config) { config.Dispatchers = nil }},
		{name: "event log", mutate: func(config *Config) { config.Log = nil }},
		{name: "leases", mutate: func(config *Config) { config.Leases = nil }},
		{name: "task secret", mutate: func(config *Config) { config.TaskSecret = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := NewRuntime(context.Background(), config); err == nil {
				t.Fatal("expected missing dependency error")
			}
		})
	}
}

// journalNames projects a run's journal into its syscall names.
func journalNames(t *testing.T, runtime *Runtime, processID string) []string {
	t.Helper()
	entries, err := runtime.Journal(processID)
	if err != nil {
		t.Fatalf("load journal: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Syscall.Name)
	}
	return names
}

func TestRuntimePassesManifestToDispatcherProvider(t *testing.T) {
	dispatchers := &runtimeDispatchers{}
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: dispatchers,
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "finish", manifest.Manifest{
		Version: manifest.Version,
		Program: "program@1",
		Syscalls: []manifest.Syscall{
			{Syscall: "core.custom", Config: json.RawMessage(`{"value":2}`)},
			{Syscall: "core.openaiApi", Hidden: true},
		},
	}, 0)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	// The program brackets its one turn in a sys.begin/sys.commit savepoint, so
	// the journal narrative is input → begin → chat → commit → finish.
	names := journalNames(t, runtime, proc.ID)
	want := []string{callSysInput, sys.SyscallBegin, "core.openaiApi", sys.SyscallCommit, callSysOutput}
	if len(names) != len(want) {
		t.Fatalf("journal = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("journal = %v, want %v", names, want)
		}
	}

	dispatchers.mu.Lock()
	defer dispatchers.mu.Unlock()
	if len(dispatchers.manifests) != 1 ||
		string(dispatchers.manifests[0].Syscalls[0].Config) != `{"value":2}` {
		t.Fatalf("dispatcher manifests = %+v", dispatchers.manifests)
	}
}

// TestRuntimeProgramLifecycle boots with no program (so program runs fail), then
// hot-registers one via AddProgram and drives a run through it, then removes it —
// covering the control plane's live Program CRD add/remove path.
func TestRuntimeProgramLifecycle(t *testing.T) {
	wasm := buildProgram(t)
	dispatchers := &runtimeDispatchers{}
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: dispatchers,
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	if len(runtime.Programs()) != 0 {
		t.Fatalf("expected no programs at boot, got %v", runtime.Programs())
	}
	emptyTh, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session (no programs): %v", err)
	}
	if _, err := runtime.CreateProcess(emptyTh.ID, "task", manifest.Manifest{Version: manifest.Version}, 0); err == nil {
		t.Fatal("creating a run with no registered program should fail")
	}

	// Hot-register the program.
	addTestProgram(t, runtime, "program@1", wasm)
	got := runtime.Programs()
	if len(got) != 1 || got[0].ID != "program@1" {
		t.Fatalf("programs after register = %v", got)
	}
	registered := got[0].Digest

	// A run now dispatches through the freshly registered program.
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "finish", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants(),
	}, 0)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)

	// Registering over a taken id withdraws the old program and installs the new
	// one. Identical bytes land on the identical identity; different bytes are a
	// different program under the same name.
	if err := runtime.AddProgram(context.Background(), testProgram("program@1", wasm)); err != nil {
		t.Fatalf("re-add the identical program: %v", err)
	}
	if got := runtime.Programs(); len(got) != 1 || got[0].Digest != registered {
		t.Fatalf("re-adding identical bytes changed the identity: %v", got)
	}
	changed := testProgram("program@1", buildEchoProgram(t))
	if err := runtime.AddProgram(context.Background(), changed); err != nil {
		t.Fatalf("add over a taken id: %v", err)
	}
	if got := runtime.Programs(); len(got) != 1 || got[0].Digest == registered {
		t.Fatalf("add over a taken id did not replace the program: %v", got)
	}
	if err := runtime.RemoveProgram(context.Background(), "program@1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(runtime.Programs()) != 0 {
		t.Fatalf("expected empty registry after removal, got %v", runtime.Programs())
	}
	if err := runtime.RemoveProgram(context.Background(), "program@1"); !errors.Is(err, errs.NotFound) {
		t.Fatalf("removing an unregistered program = %v, want errs.NotFound", err)
	}
	if err := runtime.AddProgram(context.Background(), changed); err != nil {
		t.Fatalf("add after removal: %v", err)
	}
}

// TestRemoveProgramEjectsLiveProcesses: withdrawing a program settles the
// processes running against it. A process parked on its approval is live — not
// terminal — so removal stops and ejects it rather than leaving it waiting on
// code the app has withdrawn, and it can neither be resumed nor retried
// afterwards while a different program holds its name.
func TestRemoveProgramEjectsLiveProcesses(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: approvalDispatchers{},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "do the guarded thing", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("tool.y"),
	}, 0)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	// Parked on its approval: live, and holding a pending task.
	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)

	if err := runtime.RemoveProgram(context.Background(), "program@1"); err != nil {
		t.Fatalf("remove program: %v", err)
	}
	ejected := waitForStatus(t, runtime, proc.ID, durable.ProcessStopped)
	if ejected.Status != durable.ProcessStopped {
		t.Fatalf("process after program removal = %s, want stopped", ejected.Status)
	}
	// It stays auditable — its journal is still readable.
	if _, err := runtime.Journal(proc.ID); err != nil {
		t.Fatalf("journal of an ejected process: %v", err)
	}
	// And it stays bound to the identity it was created from: a different program
	// under the same name leaves it stranded.
	changed := testProgram("program@1", buildEchoProgram(t))
	if err := runtime.AddProgram(context.Background(), changed); err != nil {
		t.Fatalf("add replacement: %v", err)
	}
	if _, err := runtime.Retry(proc.ID, RetryRestart); !errors.Is(err, errs.Conflict) {
		t.Fatalf("retry under a replaced program = %v, want errs.Conflict", err)
	}
}

// TestProcessImmutablyBoundToProgramBytes: a process is an audit target — its
// journal, effects, and conclusions attest to the exact program bytes it was
// created from. When the registered program's content changes under the same
// name, the process can neither resume nor restart; the new bytes serve new
// processes, bound by their own manifest.
func TestProcessImmutablyBoundToProgramBytes(t *testing.T) {
	disp := &effectsDispatcher{}
	runtime := newEffectsRuntime(t, disp)
	proc := startEffectsProcess(t, runtime)
	waitForStatus(t, runtime, proc.ID, durable.ProcessFailed)

	// Replace program@1: same name, different content digest. A replacement is a
	// remove followed by an add — the id is never overwritten in place.
	if err := runtime.RemoveProgram(context.Background(), "program@1"); err != nil {
		t.Fatalf("remove program: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildEchoProgram(t))

	for _, mode := range []RetryMode{RetryResume, RetryRestart} {
		_, err := runtime.Retry(proc.ID, mode)
		if err == nil || !errors.Is(err, errs.Conflict) {
			t.Fatalf("retry %q under changed bytes = %v, want errs.Conflict", mode, err)
		}
		if !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("retry %q error = %q, want the immutability law named", mode, err)
		}
	}

	// The new bytes run in a new process.
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	fresh, err := runtime.CreateProcess(session.ID, "hello from the new program", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("billing.charge", "billing.refund", "shipping.book", "inventory.sync"),
	}, 0)
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	final := waitForStatus(t, runtime, fresh.ID, durable.ProcessCompleted)
	if final.Answer != "hello from the new program" {
		t.Fatalf("answer = %q, want the echo program's answer", final.Answer)
	}
}

// TestProcessStrandedBySchemaChange: the declared schemas are part of a program's
// contract, so editing one — even with the wasm byte-for-byte unchanged — is a
// program change. A process created under the old schema is stranded: it can
// neither resume nor restart, exactly as it would be under a bytes change.
func TestProcessStrandedBySchemaChange(t *testing.T) {
	disp := &effectsDispatcher{}
	runtime := newEffectsRuntime(t, disp)
	proc := startEffectsProcess(t, runtime)
	waitForStatus(t, runtime, proc.ID, durable.ProcessFailed)

	// Re-register program@1 with the SAME wasm but a different output schema.
	edited := testProgram("program@1", buildProgram(t))
	edited.Output = json.RawMessage(`{"type":"object"}`)
	if err := runtime.RemoveProgram(context.Background(), "program@1"); err != nil {
		t.Fatalf("remove program: %v", err)
	}
	if err := runtime.AddProgram(context.Background(), edited); err != nil {
		t.Fatalf("add edited program: %v", err)
	}

	for _, mode := range []RetryMode{RetryResume, RetryRestart} {
		_, err := runtime.Retry(proc.ID, mode)
		if err == nil || !errors.Is(err, errs.Conflict) {
			t.Fatalf("retry %q under changed schema = %v, want errs.Conflict", mode, err)
		}
		if !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("retry %q error = %q, want the immutability law named", mode, err)
		}
	}
}

// TestProcessSurvivesDescriptionChange: the description is outside a program's
// identity, so re-registering the same code and schemas with reworded prose does
// not strand a process — it can still be retried.
func TestProcessSurvivesDescriptionChange(t *testing.T) {
	disp := &effectsDispatcher{}
	runtime := newEffectsRuntime(t, disp)
	proc := startEffectsProcess(t, runtime)
	waitForStatus(t, runtime, proc.ID, durable.ProcessFailed)

	reworded := testProgram("program@1", buildProgram(t))
	reworded.Description = "program@1, described afresh"
	if err := runtime.RemoveProgram(context.Background(), "program@1"); err != nil {
		t.Fatalf("remove program: %v", err)
	}
	if err := runtime.AddProgram(context.Background(), reworded); err != nil {
		t.Fatalf("add reworded program: %v", err)
	}
	if _, err := runtime.Retry(proc.ID, RetryRestart); err != nil {
		t.Fatalf("retry after a description change = %v, want it allowed", err)
	}
}

func TestAddProgramRejectsInvalidWasm(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: &runtimeDispatchers{},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})
	if err := runtime.AddProgram(context.Background(), testProgram("program@1", []byte("not wasm"))); err == nil {
		t.Fatal("expected program compile error")
	}
	if len(runtime.Programs()) != 0 {
		t.Fatalf("a program that failed to compile was registered: %v", runtime.Programs())
	}
}

func waitForStatus(t *testing.T, runtime *Runtime, processID string, want durable.ProcessStatus) ProcessSnapshot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		proc, err := runtime.GetProcess(processID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		if proc.Status == want {
			return proc
		}
		if proc.Status == durable.ProcessFailed {
			t.Fatalf("run failed: %s", proc.Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run did not reach %s", want)
	return ProcessSnapshot{}
}

func chatActions(actions string) sys.SyscallResult {
	payload, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": actions}}},
	})
	return sys.Result(payload)
}

func sequentialIDs() func(string) (string, error) {
	var next atomic.Int32
	return func(prefix string) (string, error) {
		return fmt.Sprintf("%s%d", prefix, next.Add(1)), nil
	}
}

var (
	programOnce  sync.Once
	programWasm  []byte
	programError error
)

// buildProgram compiles the Rust agent program from the sibling aurora-brains checkout
// workspace to wasm32-wasip1 — the same artifact a real assembly deploys.
// Tests that need a guest skip when the Rust toolchain is unavailable.
func buildProgram(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found")
	}
	programOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "cargo", "build",
			"--release",
			"--target", "wasm32-wasip1",
			"-p", "agent",
		)
		cmd.Dir = "../../../aurora-brains"
		if out, err := cmd.CombinedOutput(); err != nil {
			programError = fmt.Errorf("build program: %v\n%s", err, out)
			return
		}
		wasmPath := filepath.Join(cmd.Dir, "target", "wasm32-wasip1", "release", "agent.wasm")
		raw, err := os.ReadFile(wasmPath)
		if err != nil {
			programError = fmt.Errorf("read program: %v", err)
			return
		}
		programWasm = raw
	})
	if programError != nil {
		t.Skipf("agent program unavailable: %v", programError)
	}
	return programWasm
}

var (
	echoOnce  sync.Once
	echoWasm  []byte
	echoError error
)

// buildEchoProgram compiles the Rust echo program — different bytes for the
// same registered name, the probe for the process↔program immutability law.
func buildEchoProgram(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not found")
	}
	echoOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "cargo", "build",
			"--release",
			"--target", "wasm32-wasip1",
			"-p", "echo",
		)
		cmd.Dir = "../../../aurora-brains"
		if out, err := cmd.CombinedOutput(); err != nil {
			echoError = fmt.Errorf("build echo program: %v\n%s", err, out)
			return
		}
		wasmPath := filepath.Join(cmd.Dir, "target", "wasm32-wasip1", "release", "echo.wasm")
		raw, err := os.ReadFile(wasmPath)
		if err != nil {
			echoError = fmt.Errorf("read echo program: %v", err)
			return
		}
		echoWasm = raw
	})
	if echoError != nil {
		t.Skipf("echo program unavailable: %v", echoError)
	}
	return echoWasm
}

// firstAndLaterUser returns the first user message (the run's input) and whether
// any subsequent user message exists (a tool observation the guest appends as a
// user-role message). Mock programs distinguish child from parent by their input
// rather than by scanning every user message, whose content includes the echoed
// delegation args.
func firstAndLaterUser(messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) (first string, later bool) {
	seen := false
	for _, m := range messages {
		if m.Role != "user" {
			continue
		}
		if !seen {
			first = m.Content
			seen = true
		} else {
			later = true
		}
	}
	return first, later
}

// approvalDispatchers drives a run whose first turn calls tool.y, a capability
// that requires human approval: the driver yields until the dispatch carries
// an approved Authorization (the task layer's injection seam).
type approvalDispatchers struct{}

func (approvalDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (approvalDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ manifest.Manifest) (sys.Dispatcher[ProcessContext], error) {
	return approvalToolDispatcher{}, nil
}

type approvalToolDispatcher struct{}

func (approvalToolDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{Name: "tool.y", Description: "guarded tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (approvalToolDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "tool.y":
		if auth.Decision != sys.Approved {
			return sys.Yield("Approve tool.y"), nil
		}
		return sys.Result(json.RawMessage(`{"granted":true}`)), nil
	case "core.openaiApi":
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(syscall.Args, &req)
		if _, laterUser := firstAndLaterUser(req.Messages); laterUser {
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"approved-done"}}]}`), nil
		}
		return chatActions(`{"actions":[{"action":"tool.y","content":{}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

// TestRuntimeApprovalCycle drives the whole human-in-the-loop machinery end to
// end: a guarded syscall yields, the run parks as waiting_for_task with a
// durable task whose identity is the open journal intent, resolving the task
// auto-resumes the proc, replay re-drives the open intent with the stored
// resolution as its Authorization, and the run completes. A second identical
// journal position is never re-executed — the completion replays from tape.
func TestRuntimeApprovalCycle(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: approvalDispatchers{},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "do the guarded thing", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("tool.y"),
	}, 0)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)
	tasks, err := runtime.Tasks(proc.ID)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("tasks = %+v, err=%v", tasks, err)
	}
	pending := tasks[0]
	if pending.Syscall.Name != "tool.y" || pending.State != "pending" {
		t.Fatalf("pending task = %+v", pending)
	}
	if pending.Summary != "Approve tool.y" {
		t.Fatalf("task summary = %q", pending.Summary)
	}

	if _, err := runtime.ResolveTask(pending.ID, pending.ResolutionToken, task.Resolution{
		Decision: task.StateApproved,
		Actor:    "tester",
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	completed := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	if completed.Answer != "approved-done" {
		t.Fatalf("answer = %q, want approved-done", completed.Answer)
	}
	// The approved execution was journaled once and marked executed.
	tasks, _ = runtime.Tasks(proc.ID)
	if len(tasks) != 1 || tasks[0].State != "executed" {
		t.Fatalf("final task state = %+v", tasks)
	}
}

// failThenSucceedDispatchers drives a run that does a tool call, then on its
// second turn requests an unavailable capability (failing the proc) on the first
// attempt and finishes on the second. The shared counter persists across the
// run's attempts.
type failThenSucceedDispatchers struct {
	mu    sync.Mutex
	turn2 int
}

func (*failThenSucceedDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (d *failThenSucceedDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ manifest.Manifest) (sys.Dispatcher[ProcessContext], error) {
	return &failThenSucceedDispatcher{parent: d}, nil
}

type failThenSucceedDispatcher struct{ parent *failThenSucceedDispatchers }

func (d *failThenSucceedDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{
			Name:        "tool.x",
			Description: "test tool",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		},
	}
}

func (d *failThenSucceedDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "tool.x":
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	case "core.openaiApi":
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(syscall.Args, &req)
		// A tool observation is appended as a user-role message, so the second
		// turn is signalled by a user message beyond the run's initial input.
		_, laterUser := firstAndLaterUser(req.Messages)
		if !laterUser {
			return chatActions(`{"actions":[{"action":"tool.x","content":{}}]}`), nil
		}
		d.parent.mu.Lock()
		d.parent.turn2++
		n := d.parent.turn2
		d.parent.mu.Unlock()
		if n == 1 {
			// First attempt: request a capability that was not granted; the program
			// rejects it and the run fails after several recorded steps.
			return chatActions(`{"actions":[{"action":"missing.tool","content":{}}]}`), nil
		}
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"recovered"}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

// waitForProcessFailed polls until the run reaches durable.ProcessFailed, fataling if it
// reaches any other terminal state first.
func waitForProcessFailed(t *testing.T, runtime *Runtime, processID string) ProcessSnapshot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := runtime.GetProcess(processID)
		if err != nil {
			t.Fatalf("get run: %v", err)
		}
		switch snap.Status {
		case durable.ProcessFailed:
			return snap
		case durable.ProcessCompleted, durable.ProcessStopped:
			t.Fatalf("run reached %s, expected durable.ProcessFailed", snap.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not reach durable.ProcessFailed within timeout")
	return ProcessSnapshot{}
}

func TestRuntimeHardRetryForksFromBeginning(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: &failThenSucceedDispatchers{},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "task", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("tool.x"),
	}, 0)
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	failed := waitForProcessFailed(t, runtime, proc.ID)
	if failed.Error == "" {
		t.Fatal("expected a failure error")
	}

	// Hard retry always forks from the beginning (sys.input step, no shared prefix).
	if _, err := runtime.Retry(proc.ID, RetryRestart); err != nil {
		t.Fatalf("retry: %v", err)
	}
	recovered := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	if recovered.Answer != "recovered" {
		t.Fatalf("answer = %q, want recovered", recovered.Answer)
	}
	// The session graph exposes a flat entry list where each entry carries its
	// revision. Revision 2 must start at record 0 (hard restart, no shared prefix).
	graph, err := runtime.SessionGraph(session.ID)
	if err != nil {
		t.Fatalf("session graph: %v", err)
	}
	if len(graph.Processes) != 1 {
		t.Fatalf("graph runs = %d, want 1", len(graph.Processes))
	}
	gr := graph.Processes[0]
	if gr.CurrentRevision != 2 {
		t.Fatalf("current revision = %d, want 2", gr.CurrentRevision)
	}
	forkIdx := store.minRev2Index(gr.ProcessID)
	if forkIdx != 0 {
		t.Fatalf("fork index = %d, want 0 (hard retry always restarts from the beginning)", forkIdx)
	}
	// Both revisions should have entries (old revision is preserved in the log; new process
	// re-ran everything from scratch).
	var rev1Count, rev2Count int
	for _, e := range gr.Entries {
		switch e.Revision {
		case 1:
			rev1Count++
		case 2:
			rev2Count++
		}
	}
	if rev1Count == 0 {
		t.Fatal("expected revision-1 entries in graph (first run preserved in log)")
	}
	if rev2Count == 0 {
		t.Fatal("expected revision-2 entries in graph (hard retry re-ran from the beginning)")
	}
}

// effectsDispatchers drives a guest that takes an effect and then calls a
// capability it was never granted — failing with the turn's savepoint section
// still open. That is the shape the program-immutability tests need: a process
// parked in a terminal Failed state with a real journal behind it.
type effectsDispatchers struct{ d *effectsDispatcher }

func (effectsDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	return settings, nil
}

func (p effectsDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ manifest.Manifest) (sys.Dispatcher[ProcessContext], error) {
	return p.d, nil
}

type effectsDispatcher struct {
	mu      sync.Mutex
	charges int
}

func (d *effectsDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{Name: "billing.charge", Description: "charge a card", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (d *effectsDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "billing.charge":
		d.mu.Lock()
		d.charges++
		d.mu.Unlock()
		return sys.Result(json.RawMessage(`{"charge_id":"c1"}`)), nil
	case "core.openaiApi":
		return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"kaboom.unavailable","content":{}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

func newEffectsRuntime(t *testing.T, disp *effectsDispatcher) *Runtime {
	t.Helper()
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: effectsDispatchers{d: disp},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("stable-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	return runtime
}

func startEffectsProcess(t *testing.T, runtime *Runtime) ProcessSnapshot {
	t.Helper()
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "place the order", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("billing.charge"),
	}, 0)
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	return proc
}
