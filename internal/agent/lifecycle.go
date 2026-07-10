package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"
)

// Agent lifecycle syscalls. The guest fetches its input and reports its answer
// through these calls so both are recorded on the replay journal — making the
// per-process tape the full narrative: sys.input → capability calls → sys.output.
const (
	callSysInput  = "sys.input"
	callSysOutput = "sys.output"
	// callSysLog is the side-effect-free progress report, served by the
	// progress dispatcher below the task layer.
	callSysLog = "sys.log"
	// callSysCompensate registers an effect's undo: a deferred syscall the
	// runtime journals (name + concrete guest-supplied args) but executes only
	// if the critical section later aborts.
	callSysCompensate = sys.SyscallCompensate
	// callSysAbort rolls the open critical section back instead of finishing:
	// the runtime executes the registered compensations newest-first, then
	// retries the section after the declared delay or stops the process as
	// compensated. With no section open, the whole process rolls back. This
	// call is the guest's own way to abandon its revision — the only one that
	// belongs on the journal; the host's abandonments (failure, stop, restart)
	// are management state on the process, never journal records.
	callSysAbort = sys.SyscallAbort
)

type finishArgs struct {
	Answer string `json:"answer"`
}

type abortArgs struct {
	Reason string `json:"reason"`
	// RetrySeconds schedules a fresh attempt of the aborted section that many
	// seconds after the rollback (0 = immediately). Absent means no retry: the
	// process finishes as compensated.
	RetrySeconds *int64 `json:"retry_seconds"`
}

// The host's abandonment kinds — management state on the process
// (processState.abandoning), never journal records: the journal carries the
// guest's narrative, and the guest's own abandonment is its sys.abort call.
// The kind decides what follows once the rollback settles: failed (the
// recorded error standing), stopped, or re-run from scratch.
const (
	abandonFailure = "failure"
	abandonStop    = "stop"
	abandonRestart = "restart"
)

type compensateArgs struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// lifecycleDispatcher serves the sys.input/sys.output lifecycle syscalls
// below the replay layer (so they are journaled) and forwards everything else
// to the capability dispatcher. It publishes both — hidden — into the chain's
// capability set: the kernel's Validator enforces complete mediation from the
// grant set, so even the runtime's own protocol calls are granted explicitly
// rather than smuggled past the reference monitor.
type lifecycleDispatcher struct {
	next     sys.Dispatcher[ProcessContext]
	input    string
	history  []HistoryMessage
	manifest Manifest
	attempt  int
	// validateAnswer checks a finished answer against the program's declared
	// output schema; a rejected answer comes back as a failed result the guest
	// can react to.
	validateAnswer func(string) error
}

func newLifecycleDispatcher(
	next sys.Dispatcher[ProcessContext],
	input string,
	history []HistoryMessage,
	manifest Manifest,
	attempt int,
	validateAnswer func(string) error,
) *lifecycleDispatcher {
	return &lifecycleDispatcher{
		next:           next,
		input:          input,
		history:        history,
		manifest:       manifest,
		attempt:        attempt,
		validateAnswer: validateAnswer,
	}
}

func (l *lifecycleDispatcher) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case callSysInput:
		payload, err := json.Marshal(agentInput{
			Input:        l.input,
			History:      guestHistory(l.history),
			Capabilities: visibleCapabilities(l.next.Capabilities()),
			Attempt:      l.attempt,
		})
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		// The input carries the session history — a run-to-run loopback. Stamp it
		// with the union of the history's provenance labels so the flow monitor
		// (which observes every result's labels) taints this run with what prior
		// runs observed, closing the cross-run laundering path.
		return sys.Result(payload).WithLabels(historyLabels(l.history)...), nil
	case callSysOutput:
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
	case callSysCompensate:
		// Deferred: journal the registration, never execute it. The undo is a real
		// syscall waiting to happen, and the rollback path that fires it at abort
		// time does NOT re-run the Validator or FlowMonitor — so hold it to the
		// reference monitor's gates HERE, at registration, when the guest's intent
		// and the run's taint are both known:
		//   - granted name (a misspelled/ungranted undo surfaces immediately),
		//   - flow policy (a run that has already observed a label the capability
		//     forbids may not register it as an undo — this blocks smuggling a
		//     forbidden sink past the monitor by reading tainted data and then
		//     aborting, while still allowing an undo registered before an
		//     unrelated taint arrived), and
		//   - input schema (the args cannot violate the authority boundary the
		//     capability's schema encodes, e.g. a path prefix or an amount cap).
		var args compensateArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.compensate: %v", err)), nil
		}
		if strings.TrimSpace(args.Name) == "" {
			return sys.FailCode(sys.ErrnoInvalidArgs, "sys.compensate: a capability name is required"), nil
		}
		capability, ok := sys.FindCapability(l.next.Capabilities(), args.Name)
		if !ok {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("sys.compensate: capability %q is not granted", args.Name)), nil
		}
		if blocked := sys.BlockedBy(sys.Taint(ctx), capability.Forbid); len(blocked) > 0 {
			return sys.FailCode(sys.ErrnoDenied, fmt.Sprintf(
				"sys.compensate: this run has observed %v, which may not flow into %s", blocked, args.Name)), nil
		}
		if err := validateCompensationArgs(capability, args.Args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("sys.compensate: %v", err)), nil
		}
		return sys.Result(json.RawMessage(`{}`)), nil
	case callSysAbort:
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
			Name:        callSysInput,
			Description: "fetch this process's input, prior history, and the visible capability menu",
			Hidden:      true,
		},
		sys.Capability{
			Name:        callSysOutput,
			Description: "record this process's final answer on the journal",
			Hidden:      true,
		},
		sys.Capability{
			Name:        callSysCompensate,
			Description: "register an effect's undo, executed only if the section later aborts",
			Hidden:      true,
		},
		sys.Capability{
			Name:        callSysAbort,
			Description: "roll the open section back (registered compensations run newest-first), then retry or stop",
			Hidden:      true,
		},
	)
	// sys.declassify is served by the kernel Declassifier below the FlowMonitor
	// (which performs the actual taint lift on the approved result). Its
	// capability must appear in the grant set HERE so the Validator admits the
	// call — but only when the manifest granted it (declassification is opt-in
	// per program). It is advertised (not hidden) so the model can discover and
	// request it; every crossing still yields for human approval, so the guest
	// can propose a lift but never perform one itself.
	if _, ok := l.manifest.grant(DeclassifySyscall); ok {
		caps = appendMissing(caps, sys.Capability{
			Name:        DeclassifySyscall,
			Description: "request lifting labels from this run's taint; each crossing requires human approval and is journaled with its reason",
			InputSchema: declassifyInputSchema,
		})
	}
	return caps
}

// declassifyInputSchema mirrors the kernel Declassifier's sys.declassify input
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
func historyLabels(history []HistoryMessage) []string {
	var labels []string
	for i := range history {
		labels = append(labels, history[i].Labels...)
	}
	return labels
}

// answerFromJournal reads a completed process's answer from the journal's final
// intent/completion pair, which must be the sys.output syscall. The answer is
// therefore sourced from the tape (the single source of truth) rather than the
// guest's return value.
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
	if intent.Syscall == nil || intent.Syscall.Name != callSysOutput {
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
