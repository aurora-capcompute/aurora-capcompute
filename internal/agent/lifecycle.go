package agent

// The lifecycle layer serves the agent protocol: sys.input (the process's
// input, history and tool menu), sys.output (its answer) and sys.abort. The
// calls go through the journal, so the journal tells a run's whole story:
// sys.input, then the capability calls, then sys.output or sys.abort.
//
// sys.abort is the guest's own way to abandon its revision, so it belongs on
// the journal. The host's abandonments (a failure, a stop, a restart) are
// process state, never journal records.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/capcompute/sys"
)

type lifecycleDispatcher struct {
	next           sys.Dispatcher[durable.ProcessContext]
	table          *capability.Table
	input          string
	history        []HistoryMessage
	skills         []manifest.Skill
	attempt        int
	validateAnswer func(string) error
}

// agentInput is what sys.input returns to the guest.
type agentInput struct {
	Input string `json:"input"`
	// History is the session history as the guest sees it: role and content.
	// The provenance labels stay on the host: they seed the run's taint (see
	// historyLabels), and a guest must never read them.
	History      []guestHistoryMessage   `json:"history,omitempty"`
	Capabilities []capability.Descriptor `json:"capabilities,omitempty"`
	Skills       []manifest.Skill        `json:"skills,omitempty"`
	// Attempt is which run of this process this is (1 = first). A retried
	// process sees a higher attempt, so a program can change its approach.
	Attempt int `json:"attempt,omitempty"`
}

type guestHistoryMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// finishArgs are sys.output's arguments.
type finishArgs struct {
	Answer string `json:"answer"`
}

// abortArgs are sys.abort's arguments.
type abortArgs struct {
	Reason string `json:"reason"`
}

// newLifecycleDispatcher builds the layer and admits its syscalls into the
// table. validateAnswer checks an answer against the program's output schema.
func newLifecycleDispatcher(
	next sys.Dispatcher[durable.ProcessContext],
	input string,
	history []HistoryMessage,
	spec manifest.Manifest,
	attempt int,
	validateAnswer func(string) error,
	table *capability.Table,
) (*lifecycleDispatcher, error) {
	for _, descriptor := range []capability.Descriptor{
		{Name: sys.SyscallInput, Description: "fetch this process's input, prior history, and the visible capability menu", Hidden: true},
		{Name: sys.SyscallOutput, Description: "record this process's final answer on the journal", Hidden: true},
		{Name: sys.SyscallAbort, Description: "abandon the open section and re-run it from its sys.begin", Hidden: true},
	} {
		if err := table.Reserve(descriptor); err != nil {
			return nil, err
		}
	}
	return &lifecycleDispatcher{
		next:           next,
		table:          table,
		input:          input,
		history:        history,
		skills:         spec.Skills,
		attempt:        attempt,
		validateAnswer: validateAnswer,
	}, nil
}

func (l *lifecycleDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallInput:
		payload, _ := json.Marshal(agentInput{
			Input:        l.input,
			History:      guestHistory(l.history),
			Capabilities: visibleCapabilities(l.table.Descriptors()),
			Skills:       l.skills,
			Attempt:      l.attempt,
		})
		// The history carries what earlier runs observed. Stamping its labels on
		// the input taints this run with them, so reading an earlier answer
		// cannot launder its provenance.
		return sys.Result(payload).WithLabels(historyLabels(l.history)...), nil
	case sys.SyscallOutput:
		// The journal records the answer, and the host reads it back from there
		// (answerFromJournal). An answer the output schema rejects is a failed
		// result: the guest can correct it and publish again.
		var args finishArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.output: %v", err)), nil
		}
		if err := l.validateAnswer(args.Answer); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	case sys.SyscallAbort:
		// The journal records the abort and its reason, and the host reads them
		// back (guestAbort). Empty args are a bare "give up".
		if len(syscall.Args) > 0 {
			var args abortArgs
			if err := json.Unmarshal(syscall.Args, &args); err != nil {
				return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.abort: %v", err)), nil
			}
		}
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	default:
		return l.next.Dispatch(ctx, cred, syscall, auth)
	}
}

// historyLabels is every label the session history carries.
func historyLabels(history []HistoryMessage) []string {
	var labels []string
	for _, message := range history {
		labels = append(labels, message.Labels...)
	}
	return labels
}

// guestHistory is the session history without its labels.
func guestHistory(history []HistoryMessage) []guestHistoryMessage {
	out := make([]guestHistoryMessage, len(history))
	for i, m := range history {
		out[i] = guestHistoryMessage{Role: m.Role, Content: m.Content}
	}
	return out
}

// visibleCapabilities is the guest's tool menu: every descriptor not hidden.
func visibleCapabilities(caps []capability.Descriptor) []capability.Descriptor {
	visible := make([]capability.Descriptor, 0, len(caps))
	for _, c := range caps {
		if !c.Hidden {
			visible = append(visible, c)
		}
	}
	return visible
}
