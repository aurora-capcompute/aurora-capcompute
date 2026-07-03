package agent

import (
	"context"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

// appendAll encodes and appends events to a stream, failing the test on error.
func mustAppend(t *testing.T, log *memLog, scope eventlog.Scope, events ...eventlog.Event) {
	t.Helper()
	if _, err := log.Append(context.Background(), scope, events...); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func TestFoldReconstructsLatestRunAndThreadState(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", ThreadID: "th1"}
	now := time.Unix(0, 0).UTC()

	// Run goes running → completed; thread state is derived from runs.
	r1, _ := runStateEvent(now, StoredRun{
		TenantID: "t", ID: "run1", ThreadID: "th1", Revision: 1,
		Message: "hello", Status: RunRunning,
		CreatedAt: now, UpdatedAt: now,
		Tags: map[string]string{"binding_ref": "ops"},
	})
	r2, _ := runStateEvent(now.Add(time.Second), StoredRun{
		TenantID: "t", ID: "run1", ThreadID: "th1", Revision: 1,
		Message: "hello", Status: RunCompleted, Answer: "done",
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
		Tags: map[string]string{"binding_ref": "ops"},
	})
	mustAppend(t, log, scope, r1, r2)

	events, _ := log.Read(context.Background(), scope, 0)
	proj, err := Fold(events)
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	// Completed run is terminal: no active run on the thread.
	if proj.Thread.ActiveRunID != "" {
		t.Fatalf("thread active run = %q, want cleared (completed run is not active)", proj.Thread.ActiveRunID)
	}
	// Thread identity and tags are derived from the run.
	if proj.Thread.ID != "th1" || proj.Thread.Tags["binding_ref"] != "ops" {
		t.Fatalf("thread = %+v, want id=th1 binding_ref=ops", proj.Thread)
	}
	run := proj.Runs["run1"]
	if run.Status != RunCompleted || run.Answer != "done" {
		t.Fatalf("run folded to %+v, want completed/done", run)
	}
}

func TestFoldTaskLifecycle(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", ThreadID: "th1"}
	now := time.Unix(0, 0).UTC()
	rec := task.Record{
		Scope:     task.Scope{TenantID: "t", ThreadID: "th1", RunID: "run1", Revision: 1},
		ID:        "task1",
		State:     task.StatePending,
		TokenHash: []byte{1, 2, 3},
		CreatedAt: now,
	}
	created, _ := taskCreatedEvent(now, rec)

	resolved := rec
	resolved.State = task.StateApproved
	resolvedEv, _ := taskResolvedEvent(now.Add(time.Second), resolved)

	executed, _ := taskExecutedEvent(now.Add(2*time.Second), "run1", 1, "task1")
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
