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
	// callSysCompensate registers an effect's undo: a deferred syscall the
	// runtime journals (name + concrete guest-supplied args) but executes only
	// if the critical section later aborts.
	callSysCompensate = "sys.compensate"
	// callSysAbort rolls the open critical section back instead of finishing:
	// the runtime executes the registered compensations newest-first, then
	// retries the section after the declared delay or stops the process as
	// compensated. With no section open, the whole process rolls back.
	callSysAbort = "sys.abort"
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
	next         sys.Dispatcher[ProcessContext]
	message      string
	history      []HistoryMessage
	systemPrompt string
	manifest     Manifest
	attempt      int
}

func newLifecycleDispatcher(
	next sys.Dispatcher[ProcessContext],
	message string,
	history []HistoryMessage,
	manifest Manifest,
	attempt int,
) *lifecycleDispatcher {
	return &lifecycleDispatcher{
		next:         next,
		message:      message,
		history:      history,
		systemPrompt: manifest.SystemPrompt,
		manifest:     manifest,
		attempt:      attempt,
	}
}

func (l *lifecycleDispatcher) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case callSysInput:
		payload, err := json.Marshal(agentInput{
			Message:      l.message,
			History:      l.history,
			SystemPrompt: l.systemPrompt,
			Capabilities: visibleCapabilities(l.next.Capabilities()),
			Attempt:      l.attempt,
		})
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		return sys.Result(payload), nil
	case callSysOutput:
		// The answer travels in syscall.Args and is recorded on the journal; the
		// host reads it back from there. Acknowledge so the guest can return.
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	case callSysCompensate:
		// Deferred: journal the registration, never execute it. The undo is a
		// syscall like any other — the same granted-name check every dispatch
		// gets, applied at registration so a misspelled or ungranted undo
		// surfaces to the guest immediately rather than at abort time.
		var args compensateArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.compensate: %v", err)), nil
		}
		if strings.TrimSpace(args.Name) == "" {
			return sys.FailCode(sys.ErrnoInvalidArgs, "sys.compensate: a capability name is required"), nil
		}
		if _, ok := sys.FindCapability(l.next.Capabilities(), args.Name); !ok {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("sys.compensate: capability %q is not granted", args.Name)), nil
		}
		return sys.Result(json.RawMessage(`{}`)), nil
	case callSysAbort:
		// The reason and retry delay travel in syscall.Args and are journaled as
		// the terminal call; the runtime reads them back, executes the registered
		// compensations, and applies the retry. Acknowledge so the guest returns.
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	default:
		return l.next.Dispatch(ctx, cred, syscall, auth)
	}
}

func (l *lifecycleDispatcher) Capabilities() []sys.Capability {
	return appendMissing(l.next.Capabilities(),
		sys.Capability{
			Name:        callSysInput,
			Description: "fetch this process's input: message, history, system prompt, and the visible capability menu",
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
}

// answerFromJournal reads a completed process's answer from the journal's final
// intent/completion pair, which must be the sys.output syscall. The answer is
// therefore sourced from the tape (the single source of truth) rather than the
// guest's return value.
func (r *Runtime) answerFromJournal(processID string) (string, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	var journal *logJournal
	if proc != nil {
		journal = proc.journal
	}
	r.mu.Unlock()
	if journal == nil {
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
	var args finishArgs
	if err := json.Unmarshal(intent.Syscall.Args, &args); err != nil {
		return "", fmt.Errorf("decode finish answer: %w", err)
	}
	if strings.TrimSpace(args.Answer) == "" {
		return "", errors.New("agent finish call is missing an answer")
	}
	return args.Answer, nil
}
