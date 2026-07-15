package agent

import (
	"context"
	"slices"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

// nopNext is a minimal downstream dispatcher for the lifecycle dispatcher, which
// serves sys.input itself and only reads next's capability menu.
type nopNext struct{ caps []sys.Capability }

func (n nopNext) Dispatch(context.Context, ProcessContext, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Result(nil), nil
}
func (n nopNext) Capabilities() []sys.Capability { return n.caps }

// historyLabels unions the provenance across history entries — the taint the
// run-to-run loopback carries.
func TestHistoryLabelsUnionsEntries(t *testing.T) {
	got := historyLabels([]HistoryMessage{
		{Role: "assistant", Content: "a1", Labels: []string{"onyx_data", "syscall:core.httpTemplate"}},
		{Role: "user", Content: "q2"},
		{Role: "assistant", Content: "a2", Labels: []string{"secret"}},
	})
	for _, want := range []string{"onyx_data", "syscall:core.httpTemplate", "secret"} {
		if !slices.Contains(got, want) {
			t.Fatalf("historyLabels missing %q: %v", want, got)
		}
	}
}

// The crux: sys.input returns the session history stamped with that history's
// labels, so the flow monitor (which observes every result's labels) taints the
// reading run. Without this, a prior run's provenance launders across turns.
func TestSysInputStampsHistoryLabels(t *testing.T) {
	history := []HistoryMessage{
		{Role: "user", Content: "what is Hwaas"},
		{Role: "assistant", Content: "HwaaS is …", Labels: []string{"onyx_data"}},
	}
	l := newLifecycleDispatcher(nopNext{}, "next task", nil, history, Manifest{}, 1, nil)

	result, err := l.Dispatch(context.Background(), ProcessContext{},
		sys.Syscall{Name: callSysInput}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch sys.input: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("sys.input status = %v, want a result", result.Status())
	}
	if !slices.Contains(result.Labels(), "onyx_data") {
		t.Fatalf("sys.input result labels = %v, want the history's onyx_data taint", result.Labels())
	}
}

// History with no labels stamps nothing — a fresh session doesn't spuriously
// taint the run.
func TestSysInputUnlabeledHistoryTaintsNothing(t *testing.T) {
	l := newLifecycleDispatcher(nopNext{}, "task", nil,
		[]HistoryMessage{{Role: "assistant", Content: "clean"}}, Manifest{}, 1, nil)
	result, err := l.Dispatch(context.Background(), ProcessContext{},
		sys.Syscall{Name: callSysInput}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(result.Labels()) != 0 {
		t.Fatalf("sys.input labels = %v, want none for unlabeled history", result.Labels())
	}
}

// A root manifest with history:false hides the session history and, with it, the
// cross-run taint — each run starts fresh.
func TestRootHistoryFalseHidesHistory(t *testing.T) {
	no := false
	yes := true
	cases := map[string]struct {
		flag *bool
		hide bool
	}{
		"unset shares":    {nil, false},
		"true shares":     {&yes, false},
		"false is hidden": {&no, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := Manifest{History: tc.flag}
			hide := m.History != nil && !*m.History
			if hide != tc.hide {
				t.Fatalf("hideHistory = %v, want %v", hide, tc.hide)
			}
		})
	}
}
