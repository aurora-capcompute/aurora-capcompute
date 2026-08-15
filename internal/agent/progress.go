package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/capcompute/sys"
)

// progressDispatcher serves the sys.log syscall: a side-effect-free progress
// report. It sits below the replay layer, so the report is journalled like any
// other syscall — and that is the whole of its delivery: a watcher reads it off
// the durable stream, there is nothing to push. It publishes its capability —
// hidden — so the Validator's grant set covers it.
type progressDispatcher struct {
	next sys.Dispatcher[ProcessContext]
}

type progressArgs struct {
	Message string `json:"message"`
}

func newProgressDispatcher(next sys.Dispatcher[ProcessContext]) *progressDispatcher {
	return &progressDispatcher{next: next}
}

func (d *progressDispatcher) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == callSysLog {
		var args progressArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.log: %v", err)), nil
		}
		return sys.Result(json.RawMessage(`{}`)), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}

func (d *progressDispatcher) Capabilities() []sys.Capability {
	return appendMissing(d.next.Capabilities(), sys.Capability{
		Name:        callSysLog,
		Description: "report a short progress message to the user while working",
		Hidden:      true,
	})
}

// appendMissing adds capabilities the set does not already name — assemblies
// may register a capability (e.g. sys.log) themselves, and the grant set
// must stay duplicate-free.
func appendMissing(capabilities []sys.Capability, extra ...sys.Capability) []sys.Capability {
	for _, candidate := range extra {
		if _, exists := sys.FindCapability(capabilities, candidate.Name); !exists {
			capabilities = append(capabilities, candidate)
		}
	}
	return capabilities
}
