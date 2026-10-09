package durable

import (
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

func TestFoldReconstructsLatestRunAndSessionState(t *testing.T) {
	now := time.Unix(0, 0).UTC()

	// The session's identity comes from its session.state event; the run goes
	// running → completed, and the rest of the session is derived from it.
	session, _ := SessionStateEvent(now, Session{
		ID: "th1", CreatedAt: now, UpdatedAt: now, Tags: map[string]string{"origin": "ops"},
	})
	r1, _ := ProcessStateEvent(now, Process{
		ID: "proc1", SessionID: "th1", Revision: 1,
		Input: "hello", Status: ProcessRunning,
		CreatedAt: now, UpdatedAt: now,
	})
	r2, _ := ProcessStateEvent(now.Add(time.Second), Process{
		ID: "proc1", SessionID: "th1", Revision: 1,
		Input: "hello", Status: ProcessCompleted, Answer: "done",
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
	})
	proj, err := Fold([]eventlog.Event{session, r1, r2})
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	// Completed run is terminal: no active run on the session.
	if proj.Session.ActiveProcessID != "" {
		t.Fatalf("session active proc = %q, want cleared (completed run is not active)", proj.Session.ActiveProcessID)
	}
	if proj.Session.ID != "th1" || proj.Session.Tags["origin"] != "ops" ||
		!proj.Session.UpdatedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("session = %+v, want th1, its tags, the run's last update", proj.Session)
	}
	if len(proj.Processes) != 1 {
		t.Fatalf("processes = %+v, want one", proj.Processes)
	}
	proc := proj.Processes[0]
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

	proj, err := Fold([]eventlog.Event{created, resolvedEv})
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	if len(proj.Tasks) != 1 || proj.Tasks[0].ID != "task1" {
		t.Fatalf("tasks = %+v, want task1", proj.Tasks)
	}
	got := proj.Tasks[0]
	if got.State != TaskApproved {
		t.Fatalf("task state = %q, want approved", got.State)
	}
	// TokenHash must survive the round-trip even though TaskRecord omits it from JSON.
	if len(got.TokenHash) != 3 || got.TokenHash[0] != 1 {
		t.Fatalf("token hash not preserved: %v", got.TokenHash)
	}
}
