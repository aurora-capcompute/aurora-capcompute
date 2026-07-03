package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/capcompute/sys"
)

// progressDispatcher serves the aurora.log syscall: a side-effect-free progress
// report published to live session subscribers. It sits below the replay layer
// (reports are journaled like any syscall) and publishes its capability —
// hidden — so the Validator's grant set covers it.
type progressDispatcher struct {
	next      sys.Dispatcher[RunContext]
	publish   func(sessionID string, event Event)
	sessionID string
	runID     string
}

type progressArgs struct {
	Message string `json:"message"`
}

func newProgressDispatcher(next sys.Dispatcher[RunContext], publish func(string, Event), sessionID, runID string) *progressDispatcher {
	return &progressDispatcher{next: next, publish: publish, sessionID: sessionID, runID: runID}
}

func (d *progressDispatcher) Dispatch(ctx context.Context, cred RunContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == "aurora.log" {
		var args progressArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode aurora.log: %v", err)), nil
		}
		d.publish(d.sessionID, Event{
			Type: "progress",
			Data: ProgressEvent{RunID: d.runID, Message: args.Message},
		})
		return sys.Result(json.RawMessage(`{}`)), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}

func (d *progressDispatcher) Capabilities() []sys.Capability {
	return appendMissing(d.next.Capabilities(), sys.Capability{
		Name:        "aurora.log",
		Description: "report a short progress message to the user while working",
		Hidden:      true,
	})
}

// appendMissing adds capabilities the set does not already name — assemblies
// may register a capability (e.g. aurora.log) themselves, and the grant set
// must stay duplicate-free.
func appendMissing(capabilities []sys.Capability, extra ...sys.Capability) []sys.Capability {
	for _, candidate := range extra {
		if _, exists := sys.FindCapability(capabilities, candidate.Name); !exists {
			capabilities = append(capabilities, candidate)
		}
	}
	return capabilities
}

type ProgressEvent struct {
	RunID   string `json:"run_id"`
	Message string `json:"message"`
}
