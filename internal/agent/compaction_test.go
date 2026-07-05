package agent

// Journal lifecycle (ROADMAP #16) tests. The law under test: a compacted
// stream folds to the same projection; only terminal processes' journals are
// traded away. Live views must be bit-identical across a compaction (they are
// served from memory, never re-read from the log), and a fresh runtime folded
// from the compacted stream must reproduce the same session — summary,
// history, process snapshots, tasks — with retained journals intact and a
// parked process still able to resume to completion.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

// seedCompactableSession hand-crafts one session's stream the way a real life
// would have written it: a completed process (state transitions + a finished
// journal) and a parked waiting_for_task process (state transitions + a
// journal ending in an open intent + its pending task). Returns the pending
// task's id.
func seedCompactableSession(t *testing.T, store *runtimeStore, scope eventlog.Scope) string {
	t.Helper()
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	now := func() time.Time { return base }
	manifest := Manifest{Version: ManifestVersion, Program: "program@1"}

	done := StoredProcess{
		TenantID: scope.TenantID, ID: "proc_done", SessionID: scope.SessionID, Revision: 1,
		Message: "hello there", Status: ProcessRunning, Attempt: 1,
		CreatedAt: base, UpdatedAt: base, StartedAt: &base,
		Manifest: manifest, ProgramDigest: "digest-1",
	}
	ev, err := processStateEvent(base, done)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, store.log, scope, ev)

	doneJournal := newLogJournal(store.log, scope, done.ID, 1, newProcessHistory(), 0, now, nil)
	appendPair(t, doneJournal,
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysInput}, sys.Result(json.RawMessage(`{}`)))
	appendPair(t, doneJournal,
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysOutput, Args: json.RawMessage(`{"answer":"done-answer"}`)},
		sys.Result(json.RawMessage(`{"ok":true}`)))

	doneAt := base.Add(2 * time.Second)
	done.Status, done.Answer = ProcessCompleted, "done-answer"
	done.UpdatedAt, done.CompletedAt = doneAt, &doneAt
	ev, err = processStateEvent(doneAt, done)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, store.log, scope, ev)

	waitStart := base.Add(3 * time.Second)
	wait := StoredProcess{
		TenantID: scope.TenantID, ID: "proc_wait", SessionID: scope.SessionID, Revision: 1,
		Message: "do the guarded thing", Status: ProcessRunning, Attempt: 1,
		CreatedAt: waitStart, UpdatedAt: waitStart, StartedAt: &waitStart,
		Manifest: manifest, ProgramDigest: "digest-1",
	}
	ev, err = processStateEvent(waitStart, wait)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, store.log, scope, ev)

	waitJournal := newLogJournal(store.log, scope, wait.ID, 1, newProcessHistory(), 0, now, nil)
	appendPair(t, waitJournal,
		sys.Syscall{Abi: sys.ABIVersion, Name: callSysInput}, sys.Result(json.RawMessage(`{}`)))
	guarded := sys.Syscall{Abi: sys.ABIVersion, Name: "tool.y", Args: json.RawMessage(`{}`)}
	appendIntent(t, waitJournal, guarded) // the open intent: the park

	token := task.Token([]byte("stable-secret"), scope.TenantID, "task_1")
	sum := sha256.Sum256([]byte(token))
	record := task.Record{
		Scope: task.Scope{
			TenantID: scope.TenantID, SessionID: scope.SessionID,
			ProcessID: wait.ID, Revision: 1,
		},
		ID: "task_1", JournalPosition: 2, CallHash: task.HashCall(guarded),
		Syscall: guarded.Copy(), Summary: "Approve tool.y",
		State: task.StatePending, TokenHash: sum[:], CreatedAt: waitStart,
	}
	taskEv, err := taskCreatedEvent(waitStart, record)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, store.log, scope, taskEv)

	parkedAt := waitStart.Add(time.Second)
	wait.Status, wait.UpdatedAt = ProcessWaitingTask, parkedAt
	ev, err = processStateEvent(parkedAt, wait)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, store.log, scope, ev)
	return record.ID
}

func newCompactionRuntime(t *testing.T, store *runtimeStore) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs:     nil, // restore-only: no execution in the unit test
		Dispatchers:  &runtimeDispatchers{},
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
		_ = runtime.Close(ctx)
	})
	return runtime
}

// sessionView bundles everything the public API says about a session, for
// before/after comparison.
type sessionView struct {
	Session  SessionSnapshot
	Journals map[string][]JournalEntry
	Tasks    map[string][]TaskSnapshot
}

func captureSessionView(t *testing.T, runtime *Runtime, sessionID string) sessionView {
	t.Helper()
	session, err := runtime.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	view := sessionView{
		Session:  session,
		Journals: map[string][]JournalEntry{},
		Tasks:    map[string][]TaskSnapshot{},
	}
	for _, proc := range session.Processes {
		entries, err := runtime.Journal(proc.ID)
		if err != nil {
			t.Fatalf("journal %s: %v", proc.ID, err)
		}
		view.Journals[proc.ID] = entries
		tasks, err := runtime.Tasks(proc.ID)
		if err != nil {
			t.Fatalf("tasks %s: %v", proc.ID, err)
		}
		view.Tasks[proc.ID] = tasks
	}
	return view
}

// mustEqualJSON compares two values by their canonical JSON — the projection
// types carry time.Time, whose in-memory representations legitimately differ
// across a JSON round-trip while denoting the same instant.
func mustEqualJSON(t *testing.T, label string, want, got any) {
	t.Helper()
	wantJSON, err := json.MarshalIndent(want, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("%s diverged:\nwant %s\ngot  %s", label, wantJSON, gotJSON)
	}
}

// TestCompactSessionPreservesProjection is the unit law: for a session holding
// a completed and a parked process, everything the API serves is identical
// before and after CompactSession; the parked process's journal events are
// retained in original order while the completed process's are dropped; and
// the compacted stream folds to the same projection the original did.
func TestCompactSessionPreservesProjection(t *testing.T) {
	ctx := context.Background()
	store := newRuntimeStore()
	scope := eventlog.Scope{TenantID: "local", SessionID: "ses_1"}
	taskID := seedCompactableSession(t, store, scope)
	runtime := newCompactionRuntime(t, store)

	original, err := store.log.Read(ctx, scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	foldBefore, err := Fold(original)
	if err != nil {
		t.Fatal(err)
	}
	before := captureSessionView(t, runtime, scope.SessionID)
	if before.Session.History[1].Content != "done-answer" {
		t.Fatalf("seeded history = %+v, want the completed process's answer", before.Session.History)
	}
	if len(before.Journals["proc_done"]) == 0 || len(before.Journals["proc_wait"]) == 0 {
		t.Fatalf("seeded journals empty: %+v", before.Journals)
	}

	if err := runtime.CompactSession(scope.SessionID); err != nil {
		t.Fatalf("compact: %v", err)
	}

	// Live views are untouched: journals are served from memory, not the log.
	after := captureSessionView(t, runtime, scope.SessionID)
	mustEqualJSON(t, "live session view across compaction", before, after)

	// The stream physically shrank and was rewritten as
	// [session.snapshot + retained journal events], renumbered from 1.
	compacted, err := store.log.Read(ctx, scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(compacted) >= len(original) {
		t.Fatalf("stream did not shrink: %d -> %d", len(original), len(compacted))
	}
	if compacted[0].Kind != evSessionSnapshot || compacted[0].Seq != 1 {
		t.Fatalf("compacted stream must start with %s at seq 1, got %s@%d",
			evSessionSnapshot, compacted[0].Kind, compacted[0].Seq)
	}
	var retainedKinds []string
	for i, ev := range compacted {
		if ev.Seq != uint64(i)+1 {
			t.Fatalf("seq not contiguous from 1: %+v", compacted)
		}
		if i == 0 {
			continue
		}
		if ev.Kind != evJournalHeader && ev.Kind != evSyscall {
			t.Fatalf("compacted tail holds a non-journal event: %s", ev.Kind)
		}
		if ev.Proc != "proc_wait" {
			t.Fatalf("journal event for %s survived; only the parked process's journal is retained", ev.Proc)
		}
		retainedKinds = append(retainedKinds, ev.Kind)
	}
	// The parked journal in original relative order: header, then the three
	// records (input intent, input completion, open tool.y intent).
	want := []string{evJournalHeader, evSyscall, evSyscall, evSyscall}
	if !reflect.DeepEqual(retainedKinds, want) {
		t.Fatalf("retained tail = %v, want %v", retainedKinds, want)
	}

	// The law itself: the compacted stream folds to the same projection.
	foldAfter, err := Fold(compacted)
	if err != nil {
		t.Fatal(err)
	}
	mustEqualJSON(t, "session fold", foldBefore.Session, foldAfter.Session)
	mustEqualJSON(t, "process fold", foldBefore.Processes, foldAfter.Processes)
	mustEqualJSON(t, "task fold", foldBefore.Tasks, foldAfter.Tasks)
	if got := foldAfter.Tasks[taskID].TokenHash; len(got) == 0 ||
		!reflect.DeepEqual(got, foldBefore.Tasks[taskID].TokenHash) {
		t.Fatalf("token hash lost by the snapshot: %v vs %v", foldBefore.Tasks[taskID].TokenHash, got)
	}

	// Restore over the compacted stream: same session, same history, same
	// parked journal and task; the completed process's journal is the
	// documented trade — gone (length 0), its state and answer kept.
	restored := newCompactionRuntime(t, store)
	view := captureSessionView(t, restored, scope.SessionID)
	expected := before
	expected.Session.Processes = append([]ProcessSnapshot(nil), before.Session.Processes...)
	for i := range expected.Session.Processes {
		if expected.Session.Processes[i].ID == "proc_done" {
			expected.Session.Processes[i].JournalLength = 0
		}
	}
	expected.Journals = map[string][]JournalEntry{
		"proc_done": {},
		"proc_wait": before.Journals["proc_wait"],
	}
	mustEqualJSON(t, "restored session view", expected, view)
	if len(view.Tasks["proc_wait"]) != 1 || view.Tasks["proc_wait"][0].ID != taskID ||
		view.Tasks["proc_wait"][0].State != task.StatePending {
		t.Fatalf("restored tasks = %+v, want pending %s", view.Tasks["proc_wait"], taskID)
	}
}

// TestCompactSessionRefusesBusyAndMissing pins the guard rails: compaction
// refuses a session with an executing quantum (its journal appends bypass the
// runtime mutex) and an unknown session.
func TestCompactSessionRefusesBusyAndMissing(t *testing.T) {
	store := newRuntimeStore()
	scope := eventlog.Scope{TenantID: "local", SessionID: "ses_1"}
	seedCompactableSession(t, store, scope)
	runtime := newCompactionRuntime(t, store)

	if err := runtime.CompactSession("ses_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session err = %v, want ErrNotFound", err)
	}
	runtime.mu.Lock()
	runtime.processes["proc_wait"].status = ProcessRunning
	runtime.mu.Unlock()
	err := runtime.CompactSession(scope.SessionID)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "proc_wait") {
		t.Fatalf("busy session err = %v, want ErrConflict naming the running process", err)
	}
	runtime.mu.Lock()
	runtime.processes["proc_wait"].status = ProcessWaitingTask
	runtime.mu.Unlock()
	if err := runtime.CompactSession(scope.SessionID); err != nil {
		t.Fatalf("compact after quiescing: %v", err)
	}
}

// TestCompactSessionsSkipsNoop: the sweep compacts a compactable session once,
// then leaves the already-compacted stream byte-identical (retention would
// keep everything, so the rewrite is skipped — no new snapshot is minted).
func TestCompactSessionsSkipsNoop(t *testing.T) {
	ctx := context.Background()
	store := newRuntimeStore()
	scope := eventlog.Scope{TenantID: "local", SessionID: "ses_1"}
	seedCompactableSession(t, store, scope)
	runtime := newCompactionRuntime(t, store)

	if err := runtime.CompactSessions(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	first, err := store.log.Read(ctx, scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || first[0].Kind != evSessionSnapshot {
		t.Fatalf("first sweep did not compact: %+v", first)
	}
	if err := runtime.CompactSessions(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	second, err := store.log.Read(ctx, scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	mustEqualJSON(t, "already-compacted stream after a no-op sweep", first, second)

	// A busy session is skipped, not an error, so the sweep never fights live work.
	runtime.mu.Lock()
	runtime.processes["proc_wait"].status = ProcessRunning
	runtime.mu.Unlock()
	if err := runtime.CompactSessions(ctx); err != nil {
		t.Fatalf("sweep over a busy session must skip, got %v", err)
	}
}

// mixedApprovalDispatchers drives two flavors of process through the real wasm
// guest: a message mentioning "guarded" calls tool.y (which yields for
// approval, parking the process); anything else finishes immediately.
type mixedApprovalDispatchers struct{}

func (mixedApprovalDispatchers) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (mixedApprovalDispatchers) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return mixedApprovalDispatcher{}, nil
}

type mixedApprovalDispatcher struct{}

func (mixedApprovalDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{Name: "tool.y", Description: "guarded tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (mixedApprovalDispatcher) Dispatch(_ context.Context, _ ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
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
		// The guarded process sees the completed process's turn as history, so
		// the decision keys on the *latest* guarded user message: nothing after
		// it → call the guarded tool; an observation after it → finish.
		sawGuarded, afterGuarded := false, false
		for _, m := range req.Messages {
			if m.Role != "user" {
				continue
			}
			if strings.Contains(m.Content, "guarded") {
				sawGuarded, afterGuarded = true, false
			} else if sawGuarded {
				afterGuarded = true
			}
		}
		switch {
		case !sawGuarded:
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"plain-done"}}]}`), nil
		case afterGuarded:
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"approved-done"}}]}`), nil
		default:
			return chatActions(`{"actions":[{"action":"tool.y","content":{}}]}`), nil
		}
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

// TestCompactSessionRestoreResumesParked is the end-to-end law, driven through
// the real wasm guest: run a process to completion and park a second one on an
// approval; compact; a fresh runtime folded from the compacted stream serves
// the same session (the completed process's journal traded away, everything
// else identical) and the parked process still resumes to completion when its
// task resolves — replaying the retained journal it parked on.
func TestCompactSessionRestoreResumesParked(t *testing.T) {
	store := newRuntimeStore()
	config := Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  mixedApprovalDispatchers{},
		Log:          store.log,
		Leases:       store,
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
	}
	first, err := NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}

	session, err := first.CreateSession(nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	manifest := Manifest{
		Version: ManifestVersion,
		Program: "program@1",
		Tools:   []Tool{{Name: "tool.y", Type: "core.custom"}},
	}
	completedProc, err := first.CreateProcess(session.ID, "plain task first", manifest)
	if err != nil {
		t.Fatalf("create completed process: %v", err)
	}
	if got := waitForStatus(t, first, completedProc.ID, ProcessCompleted); got.Answer != "plain-done" {
		t.Fatalf("first answer = %q, want plain-done", got.Answer)
	}
	parkedProc, err := first.CreateProcess(session.ID, "do the guarded thing", manifest)
	if err != nil {
		t.Fatalf("create parked process: %v", err)
	}
	waitForStatus(t, first, parkedProc.ID, ProcessWaitingTask)

	before := captureSessionView(t, first, session.ID)
	original, err := store.log.Read(context.Background(), eventlog.Scope{TenantID: "local", SessionID: session.ID}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The control: what a restart over the UNCOMPACTED stream reproduces. The
	// compacted restart below must match it exactly, journal trade aside —
	// compaction must not change what restore produces.
	controlStore := newRuntimeStore()
	if _, err := controlStore.log.Append(context.Background(),
		eventlog.Scope{TenantID: "local", SessionID: session.ID}, original...); err != nil {
		t.Fatal(err)
	}
	controlConfig := config
	controlConfig.Log = controlStore.log
	controlConfig.Leases = controlStore
	control, err := NewRuntime(context.Background(), controlConfig)
	if err != nil {
		t.Fatalf("control restore: %v", err)
	}
	baseline := captureSessionView(t, control, session.ID)
	controlCtx, cancelControl := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelControl()
	if err := control.Close(controlCtx); err != nil {
		t.Fatalf("close control runtime: %v", err)
	}

	if err := first.CompactSession(session.ID); err != nil {
		t.Fatalf("compact: %v", err)
	}
	mustEqualJSON(t, "live view across compaction",
		before, captureSessionView(t, first, session.ID))
	compacted, err := store.log.Read(context.Background(), eventlog.Scope{TenantID: "local", SessionID: session.ID}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(compacted) >= len(original) || compacted[0].Kind != evSessionSnapshot {
		t.Fatalf("compaction did not rewrite the stream: %d -> %d events, head %s",
			len(original), len(compacted), compacted[0].Kind)
	}
	for _, ev := range compacted[1:] {
		if ev.Proc == completedProc.ID {
			t.Fatalf("completed process's journal survived compaction: %s@%d", ev.Kind, ev.Seq)
		}
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := first.Close(closeCtx); err != nil {
		t.Fatalf("close first runtime: %v", err)
	}

	// The restart: a fresh runtime folds the compacted stream.
	second, err := NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("restore over compacted store: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = second.Close(ctx)
	})
	restored := captureSessionView(t, second, session.ID)
	expected := baseline
	expected.Session.Processes = append([]ProcessSnapshot(nil), baseline.Session.Processes...)
	for i := range expected.Session.Processes {
		if expected.Session.Processes[i].ID == completedProc.ID {
			expected.Session.Processes[i].JournalLength = 0 // the documented trade
		}
	}
	expected.Journals = map[string][]JournalEntry{
		completedProc.ID: {},
		parkedProc.ID:    baseline.Journals[parkedProc.ID],
	}
	mustEqualJSON(t, "restored session view (vs uncompacted-restore control)", expected, restored)

	// The parked process still resumes: resolve its approval and it completes.
	tasks := restored.Tasks[parkedProc.ID]
	if len(tasks) != 1 || tasks[0].State != task.StatePending {
		t.Fatalf("restored tasks = %+v, want one pending approval", tasks)
	}
	if _, err := second.ResolveTask(tasks[0].ID, tasks[0].ResolutionToken, task.Resolution{
		Decision: task.StateApproved, Actor: "tester",
	}); err != nil {
		t.Fatalf("resolve after restore: %v", err)
	}
	final := waitForStatus(t, second, parkedProc.ID, ProcessCompleted)
	if final.Answer != "approved-done" {
		t.Fatalf("answer = %q, want approved-done", final.Answer)
	}
	history, err := second.GetSession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.History) != 4 || history.History[3].Content != "approved-done" {
		t.Fatalf("final history = %+v, want both turns", history.History)
	}
}

// TestFoldSeedsFromSnapshot: a snapshot seeds the projection and later events
// override it per id — the append-resumes-after-compaction shape.
func TestFoldSeedsFromSnapshot(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	manifest := Manifest{Version: ManifestVersion, Program: "program@1"}
	snapProc := StoredProcess{
		TenantID: "t", ID: "run1", SessionID: "th1", Revision: 1,
		Message: "hi", Status: ProcessWaitingTask, Attempt: 1,
		CreatedAt: base, UpdatedAt: base, Manifest: manifest,
	}
	record := task.Record{
		Scope: task.Scope{TenantID: "t", SessionID: "th1", ProcessID: "run1", Revision: 1},
		ID:    "task1", State: task.StatePending, TokenHash: []byte{9, 9}, CreatedAt: base,
	}
	snapshot, err := sessionSnapshotEvent(base, []StoredProcess{snapProc}, []task.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	later := snapProc
	later.Status, later.Answer, later.UpdatedAt = ProcessCompleted, "late", base.Add(time.Minute)
	laterEv, err := processStateEvent(later.UpdatedAt, later)
	if err != nil {
		t.Fatal(err)
	}

	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th1"}
	mustAppend(t, log, scope, snapshot, laterEv)
	events, _ := log.Read(context.Background(), scope, 0)
	proj, err := Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	got := proj.Processes["run1"]
	if got.Status != ProcessCompleted || got.Answer != "late" {
		t.Fatalf("later event must override the snapshot seed, got %+v", got)
	}
	if task1 := proj.Tasks["task1"]; task1.State != task.StatePending || len(task1.TokenHash) != 2 {
		t.Fatalf("snapshot task not seeded with its token hash: %+v", task1)
	}
	if proj.Session.ID != "th1" || proj.Session.ActiveProcessID != "" {
		t.Fatalf("derived session = %+v", proj.Session)
	}
}
