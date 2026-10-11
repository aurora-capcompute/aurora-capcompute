package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/capcompute/sys"
)

// flowDispatchers serve a labeled source, a sink that forbids its label, and an
// LLM that reads the source, sends what it read, and then finishes.
type flowDispatchers struct{}

func (flowDispatchers) ValidateConfig(string, json.RawMessage) error { return nil }

func (flowDispatchers) NewDispatcher(context.Context, durable.ProcessContext, manifest.Manifest) (*capability.Table, error) {
	table := tableOf(flowLLM{}, llmCapability())
	err := table.Add(capability.Family{Entries: []capability.Entry{{
		Key:     capability.Key{Syscall: "tool.read"},
		Input:   json.RawMessage(`{"type":"object"}`),
		Labels:  []string{"secret"},
		Handler: dispatchAsHandler{flowLLM{}},
	}}})
	if err != nil {
		return nil, err
	}
	err = table.Add(capability.Family{Entries: []capability.Entry{{
		Key:     capability.Key{Syscall: "tool.send"},
		Input:   json.RawMessage(`{"type":"object"}`),
		Forbid:  []string{"secret"},
		Handler: dispatchAsHandler{flowLLM{}},
	}}})
	return table, err
}

type flowLLM struct{}

func (flowLLM) Dispatch(_ context.Context, _ durable.ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case "tool.read":
		return sys.Result(json.RawMessage(`{"page":"the launch date"}`)), nil
	case "tool.send":
		return sys.Result(json.RawMessage(`{"receipt":"delivered-42"}`)), nil
	}
	conversation := string(syscall.Args)
	switch {
	case strings.Contains(conversation, "delivered-42"):
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"published"}}]}`), nil
	case strings.Contains(conversation, "the launch date"):
		return chatActions(`{"actions":[{"action":"tool.send","content":{"text":"the launch date"}}]}`), nil
	default:
		return chatActions(`{"actions":[{"action":"tool.read","content":{}}]}`), nil
	}
}

// A call that could carry labeled data out of the run parks the process on a
// durable task, like any approval. The task names the data and the call that
// produced it. Approving it runs that one call, and the run keeps its label.
func TestTaintedCallParksOnATaskAndKeepsTheLabel(t *testing.T) {
	runtime, err := NewRuntime(context.Background(), Config{
		Programs:    []ProgramData{testProgram("program@1", buildProgram(t))},
		Dispatchers: flowDispatchers{},
		Log:         newMemLog(),
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
	session, err := runtime.CreateSession("", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	proc, err := runtime.CreateProcess(session.ID, "publish the date", manifest.Manifest{
		Version:  manifest.Version,
		Program:  "program@1",
		Syscalls: cognitionGrants("tool.read", "tool.send"),
	})
	if err != nil {
		t.Fatalf("create process: %v", err)
	}

	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)
	tasks := processLog(t, runtime, proc.ID).Tasks
	if len(tasks) != 1 || tasks[0].Syscall.Name != "tool.send" {
		t.Fatalf("tasks = %+v, want one tool.send task", tasks)
	}
	for _, want := range []string{"labeled secret", "secret came from:\n- tool.read"} {
		if !strings.Contains(tasks[0].Summary, want) {
			t.Fatalf("task summary %q does not show %q", tasks[0].Summary, want)
		}
	}
	if _, err := runtime.ResolveTask(tasks[0].ID, tasks[0].ResolutionToken, durable.TaskResolution{
		Decision: durable.TaskApproved,
		Actor:    "tester",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	done := waitForStatus(t, runtime, proc.ID, durable.ProcessCompleted)
	if done.Answer != "published" {
		t.Fatalf("answer = %q", done.Answer)
	}
	if !slices.Contains(done.Labels, "secret") {
		t.Fatalf("labels = %v: the approval lifted secret from the run", done.Labels)
	}
}
