package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	manifestpkg "github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Agent lifecycle syscalls. The guest fetches its input and reports its answer
// through these calls so both are recorded on the replay journal — making the
// per-process tape the full narrative: sys.input → capability calls → sys.output.
const (
	callSysInput  = sys.SyscallInput
	callSysOutput = sys.SyscallOutput
	// callSysLog is the side-effect-free progress report, served by the
	// progress dispatcher below the task layer.
	callSysLog = sys.SyscallLog
	// callSysAbort abandons the open savepoint section instead of finishing: the
	// runtime forks the journal at the section's sys.begin and re-runs it. This
	// call is the guest's own way to abandon its revision — the only one that
	// belongs on the journal; the host's own abandonments (a failure, a stop, a
	// restart) are management state on the process, never journal records.
	callSysAbort = sys.SyscallAbort
)

type finishArgs struct {
	Answer string `json:"answer"`
}

type abortArgs struct {
	Reason string `json:"reason"`
}

type lifecycleDispatcher struct {
	next           sys.Dispatcher[durable.ProcessContext]
	table          *capability.Table
	input          string
	history        []HistoryMessage
	manifest       manifestpkg.Manifest
	attempt        int
	validateAnswer func(string) error
}

func newLifecycleDispatcher(
	next sys.Dispatcher[durable.ProcessContext],
	input string,
	history []HistoryMessage,
	manifest manifestpkg.Manifest,
	attempt int,
	validateAnswer func(string) error,
	table *capability.Table,
) (*lifecycleDispatcher, error) {
	// The agent protocol, declared by the layer that serves it.
	for _, descriptor := range []capability.Descriptor{
		{Name: sys.SyscallInput, Description: "fetch this process's input, prior history, and the visible capability menu", Hidden: true},
		{Name: sys.SyscallOutput, Description: "record this process's final answer on the journal", Hidden: true},
		{Name: sys.SyscallAbort, Description: "abandon the open section and re-run it from its sys.begin", Hidden: true},
	} {
		if err := table.Reserve(descriptor); err != nil {
			return nil, err
		}
	}
	// sys.declassify is served by the Declassifier below the flow guard (which
	// performs the actual taint lift on the approved result). It must be in the
	// grant set HERE so the Validator admits the call — but only when the
	// manifest granted it: declassification is opt-in per program. It is
	// advertised (not hidden) so the model can discover and request it; every
	// crossing still yields for human approval, so the guest can propose a lift
	// but never perform one itself.
	if _, ok := manifest.FindSyscall(manifestpkg.DeclassifySyscall); ok {
		err := table.Reserve(capability.Descriptor{
			Name:        manifestpkg.DeclassifySyscall,
			Description: "Request to lift labels from this run's taint. Use it when flow policy refuses a call: give the labels that the refusal names, and the reason. A human must approve each request. The journal keeps the reason.",
			InputSchema: monitor.DeclassifyInputSchema,
		})
		if err != nil {
			return nil, err
		}
	}
	return &lifecycleDispatcher{
		next:           next,
		table:          table,
		input:          input,
		history:        history,
		manifest:       manifest,
		attempt:        attempt,
		validateAnswer: validateAnswer,
	}, nil
}

func (l *lifecycleDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallInput:
		payload, err := json.Marshal(agentInput{
			Input:        l.input,
			History:      guestHistory(l.history),
			Capabilities: visibleCapabilities(l.table.Descriptors()),
			Attempt:      l.attempt,
		})
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		// The input is this run's loopback from the session history that came
		// before it. Stamp its provenance so the flow monitor taints this run with
		// what its predecessors observed — closing the cross-run laundering path.
		return sys.Result(payload).WithLabels(historyLabels(l.history)...), nil
	case sys.SyscallOutput:
		// The answer travels in syscall.Args and is recorded on the journal; the
		// host reads it back from there. Validate it against the program's
		// declared output schema before acknowledging: a rejected answer is a
		// failed result the guest can react to (correct the answer, publish
		// again), journaled like any other failed observation — nothing is
		// recorded as the terminal answer until it satisfies the interface.
		if l.validateAnswer != nil {
			var args finishArgs
			if err := json.Unmarshal(syscall.Args, &args); err != nil {
				return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.output: %v", err)), nil
			}
			if err := l.validateAnswer(args.Answer); err != nil {
				return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
			}
		}
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	case sys.SyscallAbort:
		// The reason travels in syscall.Args and is journaled as the terminal
		// call; the runtime reads it back and re-runs the abandoned section.
		// Acknowledge so the guest returns. Empty args are a bare "give up".
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

// historyLabels is the union of the provenance labels carried by every session-
// history entry — the taint the loopback carries. It seeds the reading run's
// taint (via the sys.input result), so a prior run's provenance is not laundered
// by re-reading its answer.
func historyLabels(history []HistoryMessage) []string {
	var labels []string
	for i := range history {
		labels = append(labels, history[i].Labels...)
	}
	return labels
}

// answerFromJournal reads a completed process's answer from the tail of its
// journal: the sys.output intent, and the completion that accepted it.
func (r *Runtime) answerFromJournal(processID string) (string, error) {
	journal, ok := r.liveJournal(processID)
	if !ok {
		return "", errors.New("agent process journal is unavailable")
	}
	length := journal.Length()
	if length < 2 {
		return "", errors.New("agent produced no journal records")
	}
	completion, err := journal.Load(length - 1)
	if err != nil {
		return "", err
	}
	if completion.Kind != journaled.KindCompletion {
		return "", fmt.Errorf("agent did not finish (journal tail is %s)", completion.Kind)
	}
	intent, err := journal.Load(length - 2)
	if err != nil {
		return "", err
	}
	if intent.Syscall == nil || intent.Syscall.Name != sys.SyscallOutput {
		name := ""
		if intent.Syscall != nil {
			name = intent.Syscall.Name
		}
		return "", fmt.Errorf("agent did not finish (last journal call was %q)", name)
	}
	// The sys.output completion must have SUCCEEDED. A schema-violating answer is
	// journaled as a failed completion (the lifecycle validates it), and must
	// never become the terminal answer just because the guest then returned
	// {"status":"completed"} — the tail shape alone does not prove the answer was
	// accepted.
	if completion.Result == nil || completion.Result.Status() != sys.StatusResult {
		return "", errors.New("agent did not finish (its final answer was rejected by the output schema)")
	}
	var args finishArgs
	if err := json.Unmarshal(intent.Syscall.Args, &args); err != nil {
		return "", fmt.Errorf("decode finish answer: %w", err)
	}
	if strings.TrimSpace(args.Answer) == "" {
		return "", errors.New("agent finish call is missing an answer")
	}
	return args.Answer, nil
}
