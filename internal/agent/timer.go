package agent

// The sys.timer syscall, served by the runtime below the task layer: a valid
// call yields, and the task layer above turns the yield into a durable task
// the application's scheduler fires once the duration elapses — resuming the
// process from the same point. It lives with the runtime because the runtime
// itself leans on it: abort-retry parks are sys.timer tasks the runtime
// authors (see compensate.go). The dispatcher is only ever invoked for the
// initial yield; on resume the resolved task data is served by the task
// layer without re-dispatching here.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// defaultMaxTimer bounds how far in the future a timer may be set when the
// grant declares no bound. It guards against unbounded waits and keeps
// timers within any task expiry window the host configures.
const defaultMaxTimer = 24 * time.Hour

// timerRequest is the guest payload for sys.timer.
type timerRequest struct {
	DurationSeconds int64  `json:"duration_seconds"`
	Label           string `json:"label,omitempty"`
}

type timerDispatcher struct {
	next        sys.Dispatcher[ProcessContext]
	maxDuration time.Duration
	hidden      bool
}

func newTimerDispatcher(next sys.Dispatcher[ProcessContext], grant Syscall) *timerDispatcher {
	var settings TimerSettings
	if len(grant.Settings) > 0 {
		// Validated at the manifest door; a decode failure here leaves the
		// default bound.
		_ = json.Unmarshal(grant.Settings, &settings)
	}
	maxDuration := time.Duration(settings.MaxDurationMS) * time.Millisecond
	if maxDuration <= 0 {
		maxDuration = defaultMaxTimer
	}
	return &timerDispatcher{next: next, maxDuration: maxDuration, hidden: grant.Hidden}
}

// Dispatch validates the request and yields a durable task. A valid call
// always yields; invalid input fails immediately so the agent gets feedback.
func (t *timerDispatcher) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != TimerSyscall {
		return t.next.Dispatch(ctx, cred, syscall, auth)
	}
	var request timerRequest
	if err := json.Unmarshal(syscall.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.timer request: %v", err)), nil
	}
	if request.DurationSeconds <= 0 {
		return sys.FailCode(sys.ErrnoInvalidArgs, "duration_seconds must be positive"), nil
	}
	duration := time.Duration(request.DurationSeconds) * time.Second
	if duration > t.maxDuration {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("duration_seconds must be at most %d", int64(t.maxDuration/time.Second))), nil
	}
	if request.Label != "" {
		return sys.Yield(fmt.Sprintf("Timer for %s: %s", duration, request.Label)), nil
	}
	return sys.Yield(fmt.Sprintf("Timer for %s", duration)), nil
}

func (t *timerDispatcher) Capabilities() []sys.Capability {
	return append(t.next.Capabilities(), sys.Capability{
		Name: TimerSyscall,
		Description: fmt.Sprintf(
			"Set a relative timer and be replayed when it fires. The process pauses until the duration elapses, then continues. Maximum %s.",
			t.maxDuration,
		),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"integer","minimum":1},"label":{"type":"string"}},"required":["duration_seconds"],"additionalProperties":false}`),
		Hidden:      t.hidden,
	})
}
