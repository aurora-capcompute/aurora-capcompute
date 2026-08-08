package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/program"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

type finishArgs struct {
	Answer string `json:"answer"`
}

type abortArgs struct {
	Reason       string `json:"reason"`
	RetrySeconds *int64 `json:"retry_seconds"`
}

type lifecycleDispatcher struct {
	next           sys.Dispatcher[ProcessContext]
	input          string
	inputLabels    []string
	history        []HistoryMessage
	manifest       manifest.Manifest
	attempt        int
	validateAnswer func(json.RawMessage) error
}

func newLifecycleDispatcher(
	next sys.Dispatcher[ProcessContext],
	input string,
	inputLabels []string,
	history []HistoryMessage,
	manifest manifest.Manifest,
	attempt int,
	validateAnswer func(json.RawMessage) error,
) *lifecycleDispatcher {
	return &lifecycleDispatcher{
		next:           next,
		input:          input,
		inputLabels:    inputLabels,
		history:        history,
		manifest:       manifest,
		attempt:        attempt,
		validateAnswer: validateAnswer,
	}
}

func (l *lifecycleDispatcher) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallInput:
		payload, err := json.Marshal(agentInput{
			Input:        l.input,
			History:      guestHistory(l.history),
			Capabilities: visibleCapabilities(l.next.Capabilities()),
			Attempt:      l.attempt,
		})
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		// The input is this run's loopback from everything that came before it:
		// the session history (prior runs) and, for a delegated child, the input
		// text a tainted parent composed. Stamp both provenances so the flow
		// monitor (which observes every result's labels) taints this run with
		// what its predecessors observed — closing the cross-run laundering path
		// and its downward mirror, a parent delegating a guarded sink to a
		// fresh, untainted child.
		return sys.Result(payload).WithLabels(append(historyLabels(l.history), l.inputLabels...)...), nil
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
		// The reason and retry delay travel in syscall.Args and are journaled as
		// the terminal call; the runtime reads them back, executes the registered
		// compensations, and applies the retry. Acknowledge so the guest returns.
		// Empty args are a bare "roll back now, no retry".
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

func (l *lifecycleDispatcher) Capabilities() []sys.Capability {
	caps := appendMissing(l.next.Capabilities(),
		sys.Capability{
			Name:        sys.SyscallInput,
			Description: "fetch this process's input, prior history, and the visible capability menu",
			Hidden:      true,
		},
		sys.Capability{
			Name:        sys.SyscallOutput,
			Description: "record this process's final answer on the journal",
			Hidden:      true,
		},
		sys.Capability{
			Name:        sys.SyscallAbort,
			Description: "roll the open section back (registered compensations run newest-first), then retry or stop",
			Hidden:      true,
		},
	)
	// sys.declassify is served by the processor Declassifier below the FlowMonitor
	// (which performs the actual taint lift on the approved result). Its
	// capability must appear in the grant set HERE so the Validator admits the
	// call — but only when the manifest granted it (declassification is opt-in
	// per program). It is advertised (not hidden) so the model can discover and
	// request it; every crossing still yields for human approval, so the guest
	// can propose a lift but never perform one itself.
	if _, ok := l.manifest.Grant(manifest.DeclassifySyscall); ok {
		caps = appendMissing(caps, sys.Capability{
			Name:        manifest.DeclassifySyscall,
			Description: "request lifting labels from this run's taint; each crossing requires human approval and is journaled with its reason",
			InputSchema: declassifyInputSchema,
		})
	}
	return caps
}

// declassifyInputSchema mirrors the processor Declassifier's sys.declassify input
// schema. The Declassifier is the authoritative validator (it re-checks labels,
// reason, and approval); this is the grant-set copy the Validator admits the
// call against, kept in step with capcompute's declassifyInputSchema.
var declassifyInputSchema = json.RawMessage(`{
	"type": "object",
	"required": ["labels", "reason"],
	"properties": {
		"labels": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
		"reason": {"type": "string", "minLength": 1}
	},
	"additionalProperties": false
}`)

// historyLabels is the union of the provenance labels carried by every session-
// history entry — the taint the loopback carries. It seeds the reading run's
// taint (via the sys.input result), so a prior run's provenance is not laundered
// by re-reading its answer.
// validateCompensationArgs holds a deferred inverse's args to the same input
// schema its forward call would face. The rollback path that fires the inverse
// at abort time does not re-run the Validator, so this is where a compensation
// with args that violate the capability's schema (its authority boundary) is
// refused — at registration, before it can be journaled and later executed.
func validateCompensationArgs(capability sys.Capability, rawArgs json.RawMessage) error {
	if len(capability.InputSchema) == 0 {
		return nil
	}
	schema, err := program.PrepareSchema("compensation", capability.InputSchema)
	if err != nil {
		return fmt.Errorf("compile %s schema: %w", capability.Name, err)
	}
	if err := schema.ValidateJSON(rawArgs); err != nil {
		return fmt.Errorf("%s args violate its input schema: %w", capability.Name, err)
	}
	return nil
}

func historyLabels(history []HistoryMessage) []string {
	var labels []string
	for i := range history {
		labels = append(labels, history[i].Labels...)
	}
	return labels
}

func (r *Runtime) answerFromJournal(processID string) (string, error) {
	journal, ok := r.Journal(processID)
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
