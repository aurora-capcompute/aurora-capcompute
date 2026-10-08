package capability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

func approvalTable(t *testing.T) *Dispatcher[string] {
	t.Helper()
	guarded := entry("core.internet", "method", "POST")
	guarded.Description = "post to the API"
	guarded.RequireApproval = true
	table := NewTable()
	if err := table.Add(Family{Entries: []Entry{guarded}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	return NewDispatcher[string](table)
}

// A human approves the exact call: the prompt names the operation and carries
// the arguments it would run with.
func TestApprovalPromptShowsTheArguments(t *testing.T) {
	call := sys.Syscall{Name: "core.internet", Args: json.RawMessage(`{"method":"POST",
		"url":"https://api.example.com/charge","body":"{\"amount\":100}"}`)}
	result, err := approvalTable(t).Dispatch(context.Background(), "p1", call, sys.Authorization{})
	if err != nil || result.Status() != sys.StatusYield {
		t.Fatalf("dispatch = %#v, %v; want a yield for approval", result, err)
	}
	prompt := result.Message()
	for _, want := range []string{"core.internet/POST", "post to the API", `"url":"https://api.example.com/charge"`, `amount`} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt %q does not show %q", prompt, want)
		}
	}
}

// Arguments past the cap are cut, and the prompt says so instead of passing a
// partial call off as the whole one.
func TestApprovalPromptMarksCutArguments(t *testing.T) {
	big, _ := json.Marshal(map[string]string{"method": "POST", "url": "https://api.example.com", "body": strings.Repeat("x", 3*approvalPromptArgsLimit)})
	result, _ := approvalTable(t).Dispatch(context.Background(), "p1", sys.Syscall{Name: "core.internet", Args: big}, sys.Authorization{})
	prompt := result.Message()
	if len(prompt) > approvalPromptArgsLimit+200 || !strings.Contains(prompt, "more bytes; the task's syscall holds them all") {
		t.Fatalf("prompt is %d bytes and lacks the cut marker: %.120q…", len(prompt), prompt)
	}
}

// An entry whose arguments do not show what will run renders the call itself.
func TestApprovalPromptUsesTheEntrysRendering(t *testing.T) {
	guarded := entry("core.command", "operation", "list")
	guarded.RequireApproval = true
	guarded.Prompt = func(sys.Syscall) string { return `run: ["/bin/ls","/srv"]` }
	table := NewTable()
	if err := table.Add(Family{Entries: []Entry{guarded}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	call := sys.Syscall{Name: "core.command", Args: json.RawMessage(`{"operation":"list"}`)}
	result, _ := NewDispatcher[string](table).Dispatch(context.Background(), "p1", call, sys.Authorization{})
	if prompt := result.Message(); !strings.Contains(prompt, `run: ["/bin/ls","/srv"]`) || strings.Contains(prompt, "args:") {
		t.Fatalf("prompt = %q, want the entry's rendering in place of the arguments", prompt)
	}
}
