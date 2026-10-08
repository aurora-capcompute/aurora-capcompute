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

// declassifyDispatchers serve one labelled source and an LLM that reads it,
// asks to lift its label, and then finishes.
type declassifyDispatchers struct{}

func (declassifyDispatchers) ValidateConfig(string, json.RawMessage) error { return nil }

func (declassifyDispatchers) NewDispatcher(context.Context, durable.ProcessContext, manifest.Manifest) (*capability.Table, error) {
	table := tableOf(declassifyLLM{}, llmCapability())
	err := table.Add(capability.Family{Entries: []capability.Entry{{
		Key:     capability.Key{Syscall: "tool.read"},
		Input:   json.RawMessage(`{"type":"object"}`),
		Labels:  []string{"secret"},
		Handler: dispatchAsHandler{declassifyLLM{}},
	}}})
	return table, err
}

type declassifyLLM struct{}

func (declassifyLLM) Dispatch(_ context.Context, _ durable.ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == "tool.read" {
		return sys.Result(json.RawMessage(`{"page":"the launch date"}`)), nil
	}
	conversation := string(syscall.Args)
	switch {
	case strings.Contains(conversation, "declassified"):
		return chatActions(`{"actions":[{"action":"final","content":{"answer":"published"}}]}`), nil
	case strings.Contains(conversation, "the launch date"):
		return chatActions(`{"actions":[{"action":"sys.declassify","content":{"labels":["secret"],"reason":"the date is public now"}}]}`), nil
	default:
		return chatActions(`{"actions":[{"action":"tool.read","content":{}}]}`), nil
	}
}

// A declassification is a human decision like any approval: the guest's
// request parks the process on a durable task, approving the task lifts the
// label from the run's taint, and the process carries on.
func TestDeclassifyParksOnATaskAndLiftsTheLabel(t *testing.T) {
	runtime, err := NewRuntime(context.Background(), Config{
		Programs:    []ProgramData{testProgram("program@1", buildProgram(t))},
		Dispatchers: declassifyDispatchers{},
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
		Syscalls: cognitionGrants("tool.read", manifest.DeclassifySyscall),
	})
	if err != nil {
		t.Fatalf("create process: %v", err)
	}

	waitForStatus(t, runtime, proc.ID, durable.ProcessWaitingTask)
	tasks := processLog(t, runtime, proc.ID).Tasks
	if len(tasks) != 1 || tasks[0].Syscall.Name != manifest.DeclassifySyscall {
		t.Fatalf("tasks = %+v, want one sys.declassify task", tasks)
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
	if slices.Contains(done.Labels, "secret") {
		t.Fatalf("labels = %v: the approved declassification did not lift secret", done.Labels)
	}
}
