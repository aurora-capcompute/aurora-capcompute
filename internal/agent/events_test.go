package agent

import (
	"context"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

// appendAll encodes and appends events to a stream, failing the test on error.
func mustAppend(t *testing.T, log *memLog, scope eventlog.Scope, events ...eventlog.Event) {
	t.Helper()
	if _, err := log.Append(context.Background(), scope, events...); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func TestFoldReconstructsLatestRunAndSessionState(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th1"}
	now := time.Unix(0, 0).UTC()

	// Run goes running → completed; session state is derived from runs.
	r1, _ := processStateEvent(now, StoredProcess{
		TenantID: "t", ID: "proc1", SessionID: "th1", Revision: 1,
		Message: "hello", Status: ProcessRunning,
		CreatedAt: now, UpdatedAt: now,
		Tags: map[string]string{"binding_ref": "ops"},
	})
	r2, _ := processStateEvent(now.Add(time.Second), StoredProcess{
		TenantID: "t", ID: "proc1", SessionID: "th1", Revision: 1,
		Message: "hello", Status: ProcessCompleted, Answer: "done",
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
		Tags: map[string]string{"binding_ref": "ops"},
	})
	mustAppend(t, log, scope, r1, r2)

	events, _ := log.Read(context.Background(), scope, 0)
	proj, err := Fold(events)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	// Completed run is terminal: no active run on the session.
	if proj.Session.ActiveProcessID != "" {
		t.Fatalf("session active proc = %q, want cleared (completed run is not active)", proj.Session.ActiveProcessID)
	}
	// Session identity and tags are derived from the proc.
	if proj.Session.ID != "th1" || proj.Session.Tags["binding_ref"] != "ops" {
		t.Fatalf("session = %+v, want id=th1 binding_ref=ops", proj.Session)
	}
	proc := proj.Processes["proc1"]
	if proc.Status != ProcessCompleted || proc.Answer != "done" {
		t.Fatalf("run folded to %+v, want completed/done", proc)
	}
}

func TestFoldTaskLifecycle(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th1"}
	now := time.Unix(0, 0).UTC()
	rec := task.Record{
		Scope:     task.Scope{TenantID: "t", SessionID: "th1", ProcessID: "proc1", Revision: 1},
		ID:        "task1",
		State:     task.StatePending,
		TokenHash: []byte{1, 2, 3},
		CreatedAt: now,
	}
	created, _ := taskCreatedEvent(now, rec)

	resolved := rec
	resolved.State = task.StateApproved
	resolvedEv, _ := taskResolvedEvent(now.Add(time.Second), resolved)

	executed, _ := taskExecutedEvent(now.Add(2*time.Second), "proc1", 1, "task1")
	mustAppend(t, log, scope, created, resolvedEv, executed)

	events, _ := log.Read(context.Background(), scope, 0)
	proj, err := Fold(events)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	got := proj.Tasks["task1"]
	if got.State != task.StateExecuted {
		t.Fatalf("task state = %q, want executed", got.State)
	}
	// TokenHash must survive the round-trip even though task.Record omits it from JSON.
	if len(got.TokenHash) != 3 || got.TokenHash[0] != 1 {
		t.Fatalf("token hash not preserved: %v", got.TokenHash)
	}
	list := proj.TaskList()
	if len(list) != 1 || list[0].ID != "task1" {
		t.Fatalf("task list = %+v", list)
	}
}
