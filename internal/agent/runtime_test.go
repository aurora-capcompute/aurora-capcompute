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

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

type runtimeDispatchers struct {
	mu        sync.Mutex
	manifests []Manifest
}

func (*runtimeDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (p *runtimeDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, manifest Manifest) (sys.Dispatcher[ProcessContext], error) {
	p.mu.Lock()
	p.manifests = append(p.manifests, cloneManifest(manifest))
	p.mu.Unlock()
	return finalDispatcher{}, nil
}

// llmCapability publishes the fake cognition tool the way a real assembly
// does: dispatchable, hidden from the discoverable menu, and — because the
// kernel's Validator enforces complete mediation — granted explicitly.
func llmCapability() sys.Capability {
	return sys.Capability{Name: "openai.chat", Description: "LLM chat", Hidden: true}
}

type finalDispatcher struct{}

func (finalDispatcher) Capabilities() []sys.Capability { return []sys.Capability{llmCapability()} }

func (finalDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != "openai.chat" {
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
func (s *runtimeStore) seed(runs ...StoredProcess) {
	now := time.Now().UTC()
	for _, r := range runs {
		ev, _ := processStateEvent(now, r)
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
	programs := staticPrograms{defaultID: "program@1", sources: []ProgramSource{{ID: "program@1", Wasm: []byte("wasm")}}}
	base := Config{
		Programs: programs, Dispatchers: dispatchers, Log: store.log,
		Leases: store, ProcessTable: newMemProcessTable(), TaskSecret: []byte("secret"),
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "dispatcher provider", mutate: func(config *Config) { config.Dispatchers = nil }},
		{name: "event log", mutate: func(config *Config) { config.Log = nil }},
		{name: "leases", mutate: func(config *Config) { config.Leases = nil }},
		{name: "process table", mutate: func(config *Config) { config.ProcessTable = nil }},
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
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  dispatchers,
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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
	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "finish", Manifest{
		Version: ManifestVersion,
		Syscalls: []Syscall{{
			Name: "custom.call", Type: "core.custom", Settings: json.RawMessage(`{"value":2}`),
		}},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	// The program brackets its one turn in a sys.begin/sys.commit savepoint, so
	// the journal narrative is input → begin → chat → commit → finish.
	names := journalNames(t, runtime, proc.ID)
	want := []string{callSysInput, sys.SyscallBegin, "openai.chat", sys.SyscallCommit, callSysOutput}
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
		string(dispatchers.manifests[0].Syscalls[0].Settings) != `{"value":2}` {
		t.Fatalf("dispatcher manifests = %+v", dispatchers.manifests)
	}
}

// TestRuntimeSetProgramsLifecycle boots with no program (so program runs fail), then
// hot-registers a program via SetPrograms and drives a run through it, then removes
// it — covering the control plane's live Program CRD add/remove path.
func TestRuntimeSetProgramsLifecycle(t *testing.T) {
	wasm := buildProgram(t)
	dispatchers := &runtimeDispatchers{}
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs:     nil, // boot with zero programs
		Dispatchers:  dispatchers,
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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
	emptyTh, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session (no programs): %v", err)
	}
	if _, err := runtime.CreateProcess(emptyTh.ID, "task", Manifest{Version: ManifestVersion}); err == nil {
		t.Fatal("creating a run with no registered program should fail")
	}

	// Hot-register the program.
	if err := runtime.SetPrograms(context.Background(), []ProgramSource{{ID: "program@1", Wasm: wasm}}); err != nil {
		t.Fatalf("set programs: %v", err)
	}
	if got := runtime.Programs(); len(got) != 1 || got[0].ID != "program@1" {
		t.Fatalf("programs after register = %v", got)
	}

	// A run now dispatches through the freshly registered program.
	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "finish", Manifest{
		Version:  ManifestVersion,
		Syscalls: []Syscall{{Name: "custom.call", Type: "core.custom", Settings: json.RawMessage(`{"value":1}`)}},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	waitForStatus(t, runtime, proc.ID, ProcessCompleted)

	// Re-applying the same set is a no-op; removing it leaves an empty registry.
	if err := runtime.SetPrograms(context.Background(), []ProgramSource{{ID: "program@1", Wasm: wasm}}); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(runtime.Programs()) != 1 {
		t.Fatalf("re-apply changed registry: %v", runtime.Programs())
	}
	if err := runtime.SetPrograms(context.Background(), nil); err != nil {
		t.Fatalf("clear programs: %v", err)
	}
	if len(runtime.Programs()) != 0 {
		t.Fatalf("expected empty registry after removal, got %v", runtime.Programs())
	}
}

func TestNewRuntimeRejectsInvalidProgramWasm(t *testing.T) {
	store := newRuntimeStore()
	_, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: []byte("not wasm")}},
		},
		Dispatchers:  &runtimeDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
	})
	if err == nil {
		t.Fatal("expected program compile error")
	}
}

func waitForStatus(t *testing.T, runtime *Runtime, processID string, want ProcessStatus) ProcessSnapshot {
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
		if proc.Status == ProcessFailed {
			t.Fatalf("run failed: %s", proc.Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run did not reach %s", want)
	return ProcessSnapshot{}
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

// buildProgram compiles the Rust agent program from the sibling aurora-brains
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
			"-p", "agent-brain",
		)
		cmd.Dir = "../../../aurora-brains"
		if out, err := cmd.CombinedOutput(); err != nil {
			programError = fmt.Errorf("build program: %v\n%s", err, out)
			return
		}
		wasmPath := filepath.Join(cmd.Dir, "target", "wasm32-wasip1", "release", "agent_brain.wasm")
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

// cascadeDispatchers drives a parent program to delegate to a "child" once and
// then finish. The openai.chat fake decides what to emit by inspecting the
// conversation: the child's own turn (whose user message is the delegated task)
// finishes immediately; the parent's first turn delegates; its second turn (which
// now carries a tool observation) finishes.
type cascadeDispatchers struct{}

func (cascadeDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (cascadeDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return cascadeDispatcher{}, nil
}

type cascadeDispatcher struct{}

func (cascadeDispatcher) Capabilities() []sys.Capability { return []sys.Capability{llmCapability()} }

func chatActions(actions string) sys.SyscallResult {
	payload, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"message": map[string]any{"content": actions}}},
	})
	return sys.Result(payload)
}

func (cascadeDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != "openai.chat" {
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(syscall.Args, &req)
	firstUser, laterUser := firstAndLaterUser(req.Messages)
	switch {
	case strings.Contains(firstUser, "do subtask"):
		// This is the child program (its run input is the delegation message).
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"child-done"}}]}`), nil
	case laterUser:
		// The parent already delegated and is now observing the child's result.
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"parent-done"}}]}`), nil
	default:
		return chatActions(`{"actions":[{"action":"child","content":{"message":"do subtask"}}]}`), nil
	}
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

func onlyChildProcess(t *testing.T, r *Runtime, parentID string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	parent := r.processes[parentID]
	if parent == nil || len(parent.childProcessIDs) != 1 {
		t.Fatalf("parent %q childProcessIDs = %v, want exactly one", parentID, parentChildIDs(parent))
	}
	return parent.childProcessIDs[0]
}

func parentChildIDs(proc *processState) []string {
	if proc == nil {
		return nil
	}
	return proc.childProcessIDs
}

func runField(t *testing.T, r *Runtime, id string) (parentProcessID string, attempt int) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[id]
	if proc == nil {
		t.Fatalf("run %q not found", id)
	}
	return proc.parentProcessID, proc.attempt
}

func TestRuntimeCascadeResumeReusesChildRun(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  cascadeDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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

	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "parent task", Manifest{
		Version:  ManifestVersion,
		Program:  "program@1",
		Syscalls: []Syscall{{Name: "child", Type: SpawnType, Settings: json.RawMessage(`{"program":"program@1"}`)}},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	first := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if first.Answer != "parent-done" {
		t.Fatalf("parent answer = %q, want parent-done", first.Answer)
	}

	// Addressability: the parent recorded exactly one child, and that child links
	// back to the parent.
	childID := onlyChildProcess(t, runtime, proc.ID)
	childParent, childAttempt := runField(t, runtime, childID)
	if childParent != proc.ID {
		t.Fatalf("child.parentProcessID = %q, want %q", childParent, proc.ID)
	}

	// Call-graph projection: the parent run projects to a tree with the child
	// beneath it, linked back to the parent.
	graph, err := runtime.CallGraph(proc.ID)
	if err != nil {
		t.Fatalf("call graph: %v", err)
	}
	if graph.ProcessID != proc.ID || len(graph.Children) != 1 || graph.Children[0].ProcessID != childID {
		t.Fatalf("call graph = %+v, want root %s with single child %s", graph, proc.ID, childID)
	}
	if graph.Children[0].ParentProcessID != proc.ID {
		t.Fatalf("child node ParentProcessID = %q, want %q", graph.Children[0].ParentProcessID, proc.ID)
	}

	// Deep cascade resume: restarting the parent must reuse and retry the same
	// child run rather than spawning a fresh one.
	if _, err := runtime.Retry(proc.ID, RetryRestart); err != nil {
		t.Fatalf("retry parent: %v", err)
	}
	waitForStatus(t, runtime, proc.ID, ProcessCompleted)

	reusedChildID := onlyChildProcess(t, runtime, proc.ID)
	if reusedChildID != childID {
		t.Fatalf("cascade spawned a new child %q, want reuse of %q", reusedChildID, childID)
	}
	if _, attempt := runField(t, runtime, childID); attempt <= childAttempt {
		t.Fatalf("child attempt = %d, want > %d (child should have been retried)", attempt, childAttempt)
	}
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

func (approvalDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
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
	case "openai.chat":
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
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  approvalDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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

	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "do the guarded thing", Manifest{
		Version:  ManifestVersion,
		Program:  "program@1",
		Syscalls: []Syscall{{Name: "tool.y", Type: "core.custom"}},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	waitForStatus(t, runtime, proc.ID, ProcessWaitingTask)
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

	completed := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if completed.Answer != "approved-done" {
		t.Fatalf("answer = %q, want approved-done", completed.Answer)
	}
	// The approved execution was journaled once and marked executed.
	tasks, _ = runtime.Tasks(proc.ID)
	if len(tasks) != 1 || tasks[0].State != "executed" {
		t.Fatalf("final task state = %+v", tasks)
	}
}

// failingChildDispatchers makes a parent delegate once to a child whose program
// then requests an unavailable capability, failing the child proc.
type failingChildDispatchers struct{}

func (failingChildDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (failingChildDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return failingChildDispatcher{}, nil
}

type failingChildDispatcher struct{}

func (failingChildDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{llmCapability()}
}

func (failingChildDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != "openai.chat" {
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(syscall.Args, &req)
	for _, m := range req.Messages {
		if m.Role == "user" && strings.Contains(m.Content, "do subtask") {
			// The child requests a capability it was not granted; the program
			// rejects it and the child run fails.
			return chatActions(`{"actions":[{"action":"missing.tool","content":{}}]}`), nil
		}
	}
	return chatActions(`{"actions":[{"action":"child","content":{"message":"do subtask"}}]}`), nil
}

func TestRuntimeChildFailurePropagatesToParent(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  failingChildDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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

	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "parent task", Manifest{
		Version: ManifestVersion,
		Program: "program@1",
		Syscalls: []Syscall{{
			Name: "child", Type: SpawnType,
			Settings: json.RawMessage(`{"program":"program@1","on_failure":"propagate"}`),
		}},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	// With OnFailurePropagate, the failed child fails the parent run rather than
	// surfacing as a recoverable observation.
	failed := waitForProcessFailed(t, runtime, proc.ID)
	if !strings.Contains(failed.Error, "child") {
		t.Fatalf("parent error = %q, want it to mention the failed child", failed.Error)
	}
	// The failure came from a real delegated child proc, not from the parent
	// program merely failing to see the delegation tool.
	childID := onlyChildProcess(t, runtime, proc.ID)
	child, err := runtime.GetProcess(childID)
	if err != nil {
		t.Fatalf("get child: %v", err)
	}
	if child.Status != ProcessFailed {
		t.Fatalf("child status = %s, want failed", child.Status)
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

func (d *failThenSucceedDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
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
	case "openai.chat":
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

// waitForProcessFailed polls until the run reaches ProcessFailed, fataling if it
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
		case ProcessFailed:
			return snap
		case ProcessCompleted, ProcessStopped:
			t.Fatalf("run reached %s, expected ProcessFailed", snap.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not reach ProcessFailed within timeout")
	return ProcessSnapshot{}
}

// cascadeResumeDispatchers drives a parent that delegates to a child with
// multiple steps. The child calls tool.x then on its second LLM turn fails on
// attempt 1 and succeeds on attempt 2. With OnFailurePropagate the parent also
// fails on attempt 1. On parent resume-retry the cascade must resume (not
// restart) the child so only entries from the failing step onward get a new
// revision.
type cascadeResumeDispatchers struct {
	mu         sync.Mutex
	childTurn2 int
}

func (*cascadeResumeDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (d *cascadeResumeDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return &cascadeResumeDispatcherImpl{parent: d}, nil
}

type cascadeResumeDispatcherImpl struct{ parent *cascadeResumeDispatchers }

func (d *cascadeResumeDispatcherImpl) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{
			Name:        "tool.x",
			Description: "test tool",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		},
	}
}

func (d *cascadeResumeDispatcherImpl) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "tool.x":
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	case "openai.chat":
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(syscall.Args, &req)
		firstUser, laterUser := firstAndLaterUser(req.Messages)
		isChild := strings.Contains(firstUser, "do subtask")
		if isChild {
			if !laterUser {
				// Child first turn: call tool.x
				return chatActions(`{"actions":[{"action":"tool.x","content":{}}]}`), nil
			}
			// Child second turn: fail on first live dispatch, succeed on second.
			d.parent.mu.Lock()
			d.parent.childTurn2++
			n := d.parent.childTurn2
			d.parent.mu.Unlock()
			if n == 1 {
				return chatActions(`{"actions":[{"action":"missing.tool","content":{}}]}`), nil
			}
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"child-done"}}]}`), nil
		}
		// Parent: delegate on first turn, finish once it has the child's result.
		if laterUser {
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"parent-done"}}]}`), nil
		}
		return chatActions(`{"actions":[{"action":"child","content":{"message":"do subtask"}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

func TestRuntimeCascadeResumeUsesResumeModeForFailedChild(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  &cascadeResumeDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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

	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "parent task", Manifest{
		Version: ManifestVersion,
		Program: "program@1",
		Syscalls: []Syscall{{
			Name:     "child",
			Type:     SpawnType,
			Settings: json.RawMessage(`{"program":"program@1","on_failure":"propagate"}`),
			Syscalls: []Syscall{{Name: "tool.x", Type: "core.custom"}},
		}},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	// Attempt 1: child fails → parent fails via OnFailurePropagate.
	waitForProcessFailed(t, runtime, proc.ID)
	childID := onlyChildProcess(t, runtime, proc.ID)

	// Resume parent: the cascade must propagate RetryResume to the child so the
	// child replays its shared prefix rather than restarting from scratch.
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry parent: %v", err)
	}
	completed := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if completed.Answer != "parent-done" {
		t.Fatalf("parent answer = %q, want parent-done", completed.Answer)
	}

	// The child's revision-2 records must begin at a position > 0: the shared
	// prefix (all steps before the failing turn) should carry the old revision.
	childForkIdx := store.minRev2Index(childID)
	if childForkIdx < 0 {
		t.Fatal("child has no revision-2 records (child was not retried via cascade)")
	}
	if childForkIdx == 0 {
		t.Fatalf("child fork index = 0, want > 0: cascade resume should preserve the child's shared prefix, not restart from scratch")
	}
}

func TestRuntimeHardRetryForksFromBeginning(t *testing.T) {
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  &failThenSucceedDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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

	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "task", Manifest{
		Version:  ManifestVersion,
		Program:  "program@1",
		Syscalls: []Syscall{{Name: "tool.x", Type: "core.custom"}},
	})
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
	recovered := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
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

// compensationDispatchers drives the guest-registered rollback story: the model
// charges and registers billing.refund with the charge's concrete result as
// args, then aborts. The runtime must execute the registration on abort and
// apply the abort's retry policy. On a retried attempt (the brain announces
// "attempt N" in its system prompt) the model finishes instead.
type compensationDispatchers struct{ d *compensationDispatcher }

func (compensationDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (p compensationDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return p.d, nil
}

type compensationDispatcher struct {
	// abortContent is the JSON content of the model's abort action.
	abortContent string
	// failRefundsOnce makes the first billing.refund dispatch fail semantically.
	failRefundsOnce bool
	// guardRefunds makes billing.refund yield until dispatched with an approved
	// Authorization — the sign-off-gated undo.
	guardRefunds bool
	// failMidTurn scripts the first turn as charge + registered refund + a call
	// to an ungranted capability, so the guest fails with the turn's section
	// open — after the effect and its registration.
	failMidTurn bool
	// rechargeAfterRollback (with failMidTurn) scripts the post-rollback
	// attempt to re-issue the byte-identical charge and then conclude — the
	// probe for attempt-scoped idempotency keys.
	rechargeAfterRollback bool
	// parkMidTurn scripts the first turn as charge + registered refund +
	// shipping.book, which yields for approval — parking the process with the
	// turn's section open.
	parkMidTurn bool
	// gapInfraFailure scripts the worst register-after window: charge, then
	// inventory.sync (whose driver dies once with an infrastructure error —
	// killing the guest BEFORE it reaches the compensate), then the refund
	// registration. The later turn aborts, so the registered refund must run.
	gapInfraFailure bool
	inventoryFailed bool
	// dedupe makes charge/refund exactly-once on the idempotency key, the way
	// a real effectful driver is (ROADMAP #18).
	dedupe bool

	mu         sync.Mutex
	seen       map[string]sys.SyscallResult
	charges    int
	refunds    int
	refundArgs string
}

// effect applies one charge/refund exactly-once when dedupe is on: a re-seen
// idempotency key replays the recorded result instead of re-executing.
func (d *compensationDispatcher) effect(ctx context.Context, name string, run func() sys.SyscallResult) (sys.SyscallResult, error) {
	key, _ := sys.IdempotencyKey(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dedupe && key != "" {
		if recorded, ok := d.seen[name+"/"+key]; ok {
			return recorded, nil
		}
	}
	result := run()
	if d.dedupe && key != "" && result.Status() == sys.StatusResult {
		if d.seen == nil {
			d.seen = make(map[string]sys.SyscallResult)
		}
		d.seen[name+"/"+key] = result
	}
	return result, nil
}

func (d *compensationDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{Name: "billing.charge", Description: "charge a card", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "billing.refund", Description: "refund a charge", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "shipping.book", Description: "book a shipment", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "inventory.sync", Description: "sync inventory", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (d *compensationDispatcher) Dispatch(ctx context.Context, _ ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "billing.charge":
		return d.effect(ctx, "charge", func() sys.SyscallResult {
			d.charges++
			return sys.Result(json.RawMessage(`{"charge_id":"c1"}`))
		})
	case "billing.refund":
		return d.effect(ctx, "refund", func() sys.SyscallResult {
			if d.guardRefunds && auth.Decision != sys.Approved {
				return sys.Yield("Approve the refund")
			}
			if d.failRefundsOnce {
				d.failRefundsOnce = false
				return sys.FailCode(sys.ErrnoInternal, "card network down")
			}
			d.refunds++
			d.refundArgs = string(syscall.Args)
			return sys.Result(json.RawMessage(`{"refunded":true}`))
		})
	case "shipping.book":
		if auth.Decision != sys.Approved {
			return sys.Yield("Approve the shipment"), nil
		}
		return sys.Result(json.RawMessage(`{"booked":true}`)), nil
	case "inventory.sync":
		// One infrastructure death (an error, not a failed result: the quantum
		// dies, the intent stays open), then success on the re-driven intent.
		d.mu.Lock()
		if !d.inventoryFailed {
			d.inventoryFailed = true
			d.mu.Unlock()
			return sys.SyscallResult{}, errors.New("inventory hiccup")
		}
		d.mu.Unlock()
		return sys.Result(json.RawMessage(`{"synced":true}`)), nil
	case "openai.chat":
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(syscall.Args, &req)
		for _, m := range req.Messages {
			if m.Role == "system" && strings.Contains(m.Content, "attempt 2") {
				return chatActions(`{"actions":[{"action":"final","content":{"answer":"recovered-after-rollback"}}]}`), nil
			}
		}
		if d.failMidTurn {
			// The failure story, self-contained. Recovery keys on external
			// state, not the attempt number: a section refork replays the
			// original sys.input (attempt and all), so what a fresh attempt
			// observes differently is the rolled-back world — the refund
			// exists, the model concludes.
			d.mu.Lock()
			refunded := d.refunds > 0
			d.mu.Unlock()
			if !refunded {
				return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"compensate","content":{"name":"billing.refund","args":{"charge_id":"c1"}}},{"action":"kaboom.unavailable","content":{}}]}`), nil
			}
			if d.rechargeAfterRollback {
				// The fresh attempt re-issues the byte-identical charge — it
				// must land as a NEW effect (the rolled-back attempt's key
				// space is dead) — then concludes on its observation.
				if _, later := firstAndLaterUser(req.Messages); later {
					return chatActions(`{"actions":[{"action":"final","content":{"answer":"recharged"}}]}`), nil
				}
				return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}}]}`), nil
			}
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"recovered-after-rollback"}}]}`), nil
		}
		if _, later := firstAndLaterUser(req.Messages); later {
			// The charge observation is in: give up and roll back.
			return chatActions(`{"actions":[{"action":"abort","content":` + d.abortContent + `}]}`), nil
		}
		// First turn: charge, and register the refund with the charge's id —
		// then either park mid-section on a yielding call, or feed the
		// observations back for the abort story.
		if d.parkMidTurn {
			return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"compensate","content":{"name":"billing.refund","args":{"charge_id":"c1"}}},{"action":"shipping.book","content":{"speed":"express"}}]}`), nil
		}
		if d.gapInfraFailure {
			return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"inventory.sync","content":{}},{"action":"compensate","content":{"name":"billing.refund","args":{"charge_id":"c1"}}}]}`), nil
		}
		return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"compensate","content":{"name":"billing.refund","args":{"charge_id":"c1"}}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

func newCompensationRuntime(t *testing.T, disp *compensationDispatcher) *Runtime {
	t.Helper()
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  compensationDispatchers{d: disp},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
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
	return runtime
}

func startCompensationProcess(t *testing.T, runtime *Runtime) ProcessSnapshot {
	t.Helper()
	session, err := runtime.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "place the order", Manifest{
		Version: ManifestVersion,
		Program: "program@1",
		Syscalls: []Syscall{
			{Name: "billing.charge", Type: "core.custom"},
			{Name: "billing.refund", Type: "core.custom"},
		},
	})
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	return proc
}

// TestAbortRollsBackAndStops: sys.abort with no retry executes the registered
// compensation with the guest's exact args and finishes as compensated.
func TestAbortRollsBackAndStops(t *testing.T) {
	disp := &compensationDispatcher{abortContent: `{"reason":"could not confirm the order"}`}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	final := waitForStatus(t, runtime, proc.ID, ProcessCompensated)

	disp.mu.Lock()
	charges, refunds, refundArgs := disp.charges, disp.refunds, disp.refundArgs
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want 1 and 1", charges, refunds)
	}
	if !strings.Contains(refundArgs, `"charge_id":"c1"`) {
		t.Fatalf("refund args = %s, want the guest-registered charge id", refundArgs)
	}
	if !strings.Contains(final.Answer, "could not confirm the order") ||
		!strings.Contains(final.Answer, "billing.refund") {
		t.Fatalf("rollback report = %q", final.Answer)
	}

	// The journal narrates the whole transaction: the registration, the abort,
	// and the executed compensation (rendered with its Compensates link).
	entries, err := runtime.Journal(proc.ID)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	var sawRegistration, sawCompensation bool
	for _, entry := range entries {
		if entry.Syscall.Name == callSysCompensate {
			sawRegistration = true
		}
		if entry.Syscall.Name == "billing.refund" && entry.Compensates != nil {
			sawCompensation = true
		}
	}
	if !sawRegistration || !sawCompensation {
		t.Fatalf("journal lacks the rollback story: registration=%v compensation=%v", sawRegistration, sawCompensation)
	}
}

// TestAbortRetriesImmediately: retry_seconds=0 rolls back and re-runs the task
// at once as a new attempt; the model recovers on attempt 2.
func TestAbortRetriesImmediately(t *testing.T) {
	disp := &compensationDispatcher{abortContent: `{"reason":"provider hiccup","retry_seconds":0}`}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	final := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if final.Answer != "recovered-after-rollback" {
		t.Fatalf("answer = %q", final.Answer)
	}
	if final.Attempt != 2 {
		t.Fatalf("attempt = %d, want 2 (one rolled-back attempt, one fresh)", final.Attempt)
	}
	disp.mu.Lock()
	charges, refunds := disp.charges, disp.refunds
	disp.mu.Unlock()
	if charges != 1 || refunds != 1 {
		t.Fatalf("charges = %d, refunds = %d, want 1 and 1 (attempt 2 finished without charging)", charges, refunds)
	}
}

// TestAbortParksOnDurableRetryTimer: a positive retry delay parks the process
// on a host-authored pending timer.set task; resolving it (as the timer
// service would) re-runs the task to completion.
func TestAbortParksOnDurableRetryTimer(t *testing.T) {
	disp := &compensationDispatcher{abortContent: `{"reason":"provider busy","retry_seconds":3600}`}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, ProcessWaitingTask)
	disp.mu.Lock()
	refunds := disp.refunds
	disp.mu.Unlock()
	if refunds != 1 {
		t.Fatalf("refunds before retry = %d, want 1 (rollback runs before the park)", refunds)
	}

	tasks, err := runtime.Tasks(proc.ID)
	if err != nil {
		t.Fatalf("tasks: %v", err)
	}
	var retry *TaskSnapshot
	for i := range tasks {
		if tasks[i].State == task.StatePending && tasks[i].Syscall.Name == "timer.set" {
			retry = &tasks[i]
		}
	}
	if retry == nil {
		t.Fatalf("no pending retry timer task: %+v", tasks)
	}
	var timerArgs struct {
		DurationSeconds int64 `json:"duration_seconds"`
	}
	if err := json.Unmarshal(retry.Syscall.Args, &timerArgs); err != nil || timerArgs.DurationSeconds != 3600 {
		t.Fatalf("retry timer args = %s (err %v), want duration_seconds 3600", retry.Syscall.Args, err)
	}

	// Fire the timer the way the distribution's timer service does.
	if _, err := runtime.ResolveTask(retry.ID, retry.ResolutionToken, task.Resolution{
		Decision: task.StateCompleted, Data: json.RawMessage(`{"status":"fired"}`), Actor: "timer",
	}); err != nil {
		t.Fatalf("resolve retry timer: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, ProcessCompleted)
	if final.Answer != "recovered-after-rollback" || final.Attempt != 2 {
		t.Fatalf("answer = %q attempt = %d, want recovery on attempt 2", final.Answer, final.Attempt)
	}
}

// TestFailedCompensationFailsThenResumes: a compensation that fails
// semantically stops the rollback and fails the process with the report
// (decision: the system needs a human); a later manual resume re-runs the
// remaining compensations and settles the abort.
func TestFailedCompensationFailsThenResumes(t *testing.T) {
	disp := &compensationDispatcher{
		abortContent:    `{"reason":"could not confirm the order"}`,
		failRefundsOnce: true,
	}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	failed := waitForStatus(t, runtime, proc.ID, ProcessFailed)
	if !strings.Contains(failed.Error, "billing.refund") || !strings.Contains(failed.Error, "card network down") {
		t.Fatalf("failure = %q, want the failed compensation named", failed.Error)
	}
	if !strings.Contains(failed.Answer, "outstanding: billing.refund") {
		t.Fatalf("rollback report = %q, want the outstanding undo listed", failed.Answer)
	}

	// The card network recovers; a manual resume continues the rollback.
	if _, err := runtime.Retry(proc.ID, RetryResume); err != nil {
		t.Fatalf("retry: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, ProcessCompensated)
	disp.mu.Lock()
	refunds := disp.refunds
	disp.mu.Unlock()
	if refunds != 1 {
		t.Fatalf("refunds = %d, want exactly 1 successful", refunds)
	}
	if !strings.Contains(final.Answer, "billing.refund") {
		t.Fatalf("final report = %q", final.Answer)
	}
}

// TestRollbackParksForApproval: an undo that needs sign-off yields into a
// durable task mid-rollback; the rollback parks, approval executes the inverse
// with the stored authorization, and settlement resumes to compensated — the
// human as terminal compensator inside the rollback.
func TestRollbackParksForApproval(t *testing.T) {
	disp := &compensationDispatcher{
		abortContent: `{"reason":"could not confirm the order"}`,
		guardRefunds: true,
	}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, ProcessWaitingTask)
	tasks, err := runtime.Tasks(proc.ID)
	if err != nil {
		t.Fatalf("tasks: %v", err)
	}
	var approval *TaskSnapshot
	for i := range tasks {
		if tasks[i].State == task.StatePending && tasks[i].Syscall.Name == "billing.refund" {
			approval = &tasks[i]
		}
	}
	if approval == nil {
		t.Fatalf("no pending refund approval task: %+v", tasks)
	}
	if approval.Summary != "Approve the refund" {
		t.Fatalf("task summary = %q", approval.Summary)
	}

	if _, err := runtime.ResolveTask(approval.ID, approval.ResolutionToken, task.Resolution{
		Decision: task.StateApproved, Actor: "human",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	final := waitForStatus(t, runtime, proc.ID, ProcessCompensated)

	disp.mu.Lock()
	refunds := disp.refunds
	disp.mu.Unlock()
	if refunds != 1 {
		t.Fatalf("refunds = %d, want 1 (executed once, after approval)", refunds)
	}
	if !strings.Contains(final.Answer, "billing.refund") {
		t.Fatalf("rollback report = %q", final.Answer)
	}
}

// TestRollbackDeniedApprovalFails: denying the undo's sign-off stops the
// rollback — the terminal compensator said no — and the process fails with the
// report naming the outstanding undo.
func TestRollbackDeniedApprovalFails(t *testing.T) {
	disp := &compensationDispatcher{
		abortContent: `{"reason":"could not confirm the order"}`,
		guardRefunds: true,
	}
	runtime := newCompensationRuntime(t, disp)
	proc := startCompensationProcess(t, runtime)

	waitForStatus(t, runtime, proc.ID, ProcessWaitingTask)
	tasks, err := runtime.Tasks(proc.ID)
	if err != nil || len(tasks) == 0 {
		t.Fatalf("tasks = %+v, err=%v", tasks, err)
	}
	pending := tasks[len(tasks)-1]
	if _, err := runtime.ResolveTask(pending.ID, pending.ResolutionToken, task.Resolution{
		Decision: task.StateDenied, Actor: "human", Reason: "keep the charge",
	}); err != nil {
		t.Fatalf("deny: %v", err)
	}
	failed := waitForStatus(t, runtime, proc.ID, ProcessFailed)
	if !strings.Contains(failed.Error, "billing.refund") {
		t.Fatalf("failure = %q, want the denied undo named", failed.Error)
	}
	if !strings.Contains(failed.Answer, "outstanding: billing.refund") {
		t.Fatalf("report = %q", failed.Answer)
	}
	disp.mu.Lock()
	refunds := disp.refunds
	disp.mu.Unlock()
	if refunds != 0 {
		t.Fatalf("refunds = %d, want 0 (the human said no)", refunds)
	}
}
