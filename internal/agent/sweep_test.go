package agent

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/capcompute/sys"
)

// timerDispatchers drives a run whose first turn sets a one-minute timer and
// whose next turn finishes.
type timerDispatchers struct{}

func (timerDispatchers) ValidateConfig(string, json.RawMessage) error { return nil }

func (timerDispatchers) NewDispatcher(context.Context, durable.ProcessContext, manifest.Manifest) (*capability.Table, error) {
	return tableOf(timerLLM{}, llmCapability()), nil
}

type timerLLM struct{}

func (timerLLM) Dispatch(_ context.Context, _ durable.ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(syscall.Args, &req)
	if _, laterUser := firstAndLaterUser(req.Messages); laterUser {
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"woke up"}}]}`), nil
	}
	return chatActions(`{"actions":[{"action":"sys.timer","content":{"duration_seconds":60,"label":"nap"}}]}`), nil
}

// A timer is a task whose deadline is its fire time: the runtime's sweep fires
// it once the clock passes that time, and the parked process resumes with the
// fired result.
func TestTimerFiresFromTheSweep(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: timerDispatchers{},
		Log:         newMemLog(),
		TaskSecret:  []byte("stable-secret"),
		Now:         clock,
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, runtime, "program@1", buildProgram(t))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "take a nap", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants(manifest.TimerSyscall),
	}, 0)
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)

	runtime.sweepTasks()
	if tasks := processLog(t, runtime, proc.ID).Tasks; len(tasks) != 1 || tasks[0].State != durable.TaskPending {
		t.Fatalf("timer fired before its time: %+v", tasks)
	}

	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	runtime.sweepTasks()

	done := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	if done.Answer != "woke up" {
		t.Fatalf("answer = %q", done.Answer)
	}
	tasks := processLog(t, runtime, proc.ID).Tasks
	if len(tasks) != 1 || tasks[0].State != durable.TaskCompleted || tasks[0].Resolution.Actor != "timer" {
		t.Fatalf("timer task = %+v", tasks)
	}
	if got := string(tasks[0].Resolution.Data); got != `{"label":"nap","status":"fired"}` {
		t.Fatalf("fired result = %s", got)
	}
}

// A resolution is recorded even when the parked process cannot resume yet —
// here a restarted host has not loaded the program. The sweep wakes the process
// once the program is back, with no second resolution.
func TestSweepWakesAProcessWhoseWakeFailed(t *testing.T) {
	store := newRuntimeStore()
	config := Config{
		Dispatchers: approvalDispatchers{},
		Log:         store.log,
		TaskSecret:  []byte("stable-secret"),
	}
	first, err := NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	addTestProgram(t, first, "program@1", buildProgram(t))
	session, err := first.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := first.CreateProcess(session.ID, "do the guarded thing", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("tool.y"),
	}, 0)
	if err != nil {
		t.Fatalf("create process: %v", err)
	}
	waitForStatus(t, first, proc.ID, durable.ProcessWaitingTask)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := first.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("restart runtime: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = second.Close(ctx)
	})
	tasks := processLog(t, second, proc.ID).Tasks
	if len(tasks) != 1 {
		t.Fatalf("tasks = %+v", tasks)
	}
	if _, err := second.ResolveTask(tasks[0].ID, tasks[0].ResolutionToken, durable.TaskResolution{
		Decision: durable.TaskApproved,
		Actor:    "tester",
	}); err != nil {
		t.Fatalf("resolve before the program is loaded: %v", err)
	}
	if got, _ := second.GetProcess(proc.ID); got.Status != durable.ProcessWaitingTask {
		t.Fatalf("process resumed with no program loaded: %s", got.Status)
	}

	addTestProgram(t, second, "program@1", buildProgram(t))
	done := waitForStatus(t, second, proc.ID, durable.ProcessCompleted)
	if done.Answer != "approved-done" {
		t.Fatalf("answer = %q", done.Answer)
	}
}
