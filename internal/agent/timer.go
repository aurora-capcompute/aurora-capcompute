package agent

// The sys.timer syscall, served by the runtime below the task layer: a valid
// call yields, and the task layer above turns the yield into a durable task
// the runtime's task sweep fires once the duration elapses — resuming the
// process from the same point. The dispatcher is only ever invoked for the
// initial yield; on resume the resolved task data is served by the task
// layer without re-dispatching here.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/capcompute/sys"
)

// defaultMaxTimer bounds how far in the future a timer may be set when the
// grant declares no bound. It guards against unbounded waits. Timer tasks
// carry no task TTL: the fire time is their deadline.
const defaultMaxTimer = 24 * time.Hour

// timerRequest is the guest payload for sys.timer.
type timerRequest struct {
	DurationSeconds int64  `json:"duration_seconds"`
	Label           string `json:"label,omitempty"`
}

type timerDispatcher struct {
	next sys.Dispatcher[durable.ProcessContext]
}

func newTimerDispatcher(next sys.Dispatcher[durable.ProcessContext], grant manifest.Syscall, table *capability.Table) (*timerDispatcher, error) {
	var settings manifest.TimerSettings
	if len(grant.Config) > 0 {
		// Validated at the manifest door; a decode failure here leaves the
		// default bound.
		_ = json.Unmarshal(grant.Config, &settings)
	}
	maxDuration := time.Duration(settings.MaxDurationMS) * time.Millisecond
	if maxDuration <= 0 {
		maxDuration = defaultMaxTimer
	}
	// Declared where it is built: the bound the guest is told about is the
	// bound the Validator enforces, through the schema.
	err := table.Reserve(capability.Descriptor{
		Name: manifest.TimerSyscall,
		Description: fmt.Sprintf(
			"Set a relative timer and be replayed when it fires. The process pauses until the duration elapses, then continues. Maximum %s.",
			maxDuration,
		),
		InputSchema: json.RawMessage(fmt.Sprintf(
			`{"type":"object","properties":{"duration_seconds":{"type":"integer","minimum":1,"maximum":%d},"label":{"type":"string"}},"required":["duration_seconds"],"additionalProperties":false}`,
			int64(maxDuration/time.Second))),
		Hidden: grant.Hidden,
	})
	if err != nil {
		return nil, err
	}
	return &timerDispatcher{next: next}, nil
}

// timerFireAt is when a timer task fires: its creation plus the duration the
// guest asked for. The call was validated before it yielded, so a task that
// does not decode is not a timer.
func timerFireAt(record durable.TaskRecord) (time.Time, bool) {
	request, ok := timerTaskRequest(record)
	if !ok {
		return time.Time{}, false
	}
	return record.CreatedAt.Add(time.Duration(request.DurationSeconds) * time.Second), true
}

// timerFired is the result a fired timer hands the guest.
func timerFired(record durable.TaskRecord) (json.RawMessage, bool) {
	request, ok := timerTaskRequest(record)
	if !ok {
		return nil, false
	}
	fired, err := json.Marshal(map[string]string{"status": "fired", "label": request.Label})
	return fired, err == nil
}

func timerTaskRequest(record durable.TaskRecord) (timerRequest, bool) {
	var request timerRequest
	if record.Syscall.Name != manifest.TimerSyscall || json.Unmarshal(record.Syscall.Args, &request) != nil {
		return timerRequest{}, false
	}
	return request, true
}

// Dispatch yields a durable task. The Validator already held the request to the
// schema, including the maximum duration, so a call that reaches here is valid.
func (t *timerDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != manifest.TimerSyscall {
		return t.next.Dispatch(ctx, cred, syscall, auth)
	}
	var request timerRequest
	if err := json.Unmarshal(syscall.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.timer request: %v", err)), nil
	}
	duration := time.Duration(request.DurationSeconds) * time.Second
	if request.Label != "" {
		return sys.Yield(fmt.Sprintf("Timer for %s: %s", duration, request.Label)), nil
	}
	return sys.Yield(fmt.Sprintf("Timer for %s", duration)), nil
}
