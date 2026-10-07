package durable

import (
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

func TestFoldReconstructsLatestRunAndSessionState(t *testing.T) {
	now := time.Unix(0, 0).UTC()

	// Run goes running → completed; session state is derived from runs.
	r1, _ := ProcessStateEvent(now, Process{
		ID: "proc1", SessionID: "th1", Revision: 1,
		Input: "hello", Status: ProcessRunning,
		CreatedAt: now, UpdatedAt: now,
		Tags: map[string]string{"binding_ref": "ops"},
	})
	r2, _ := ProcessStateEvent(now.Add(time.Second), Process{
		ID: "proc1", SessionID: "th1", Revision: 1,
		Input: "hello", Status: ProcessCompleted, Answer: "done",
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
		Tags: map[string]string{"binding_ref": "ops"},
	})
	proj, err := Fold([]eventlog.Event{r1, r2})
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
	now := time.Unix(0, 0).UTC()
	rec := TaskRecord{
		Scope:     ProcessContext{SessionID: "th1", ProcessID: "proc1", Revision: 1},
		ID:        "task1",
		State:     TaskPending,
		TokenHash: []byte{1, 2, 3},
		CreatedAt: now,
	}
	created, _ := TaskCreatedEvent(now, rec)

	resolved := rec
	resolved.State = TaskApproved
	resolvedEv, _ := TaskResolvedEvent(now.Add(time.Second), resolved)

	executed, _ := TaskExecutedEvent(now.Add(2*time.Second), "proc1", 1, "task1")
	proj, err := Fold([]eventlog.Event{created, resolvedEv, executed})
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	got := proj.Tasks["task1"]
	if got.State != TaskExecuted {
		t.Fatalf("task state = %q, want executed", got.State)
	}
	// TokenHash must survive the round-trip even though TaskRecord omits it from JSON.
	if len(got.TokenHash) != 3 || got.TokenHash[0] != 1 {
		t.Fatalf("token hash not preserved: %v", got.TokenHash)
	}
	list := proj.TaskList()
	if len(list) != 1 || list[0].ID != "task1" {
		t.Fatalf("task list = %+v", list)
	}
}
