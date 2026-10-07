package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute/sys"
)

// progressDispatcher serves the sys.log syscall: a side-effect-free progress
// report. It sits below the replay layer, so the report is journalled like any
// other syscall — and that is the whole of its delivery: a watcher reads it off
// the durable stream, there is nothing to push. It publishes its capability —
// hidden — so the Validator's grant set covers it.
type progressDispatcher struct {
	next sys.Dispatcher[durable.ProcessContext]
}

type progressArgs struct {
	Message string `json:"message"`
}

func newProgressDispatcher(next sys.Dispatcher[durable.ProcessContext], table *capability.Table) (*progressDispatcher, error) {
	// Declared where it is built: the layer that serves sys.log is the layer that
	// puts it in the grant set, so the two cannot come apart.
	err := table.ReserveMissing(capability.Descriptor{
		Name:        callSysLog,
		Description: "report a short progress message to the user while working",
		Hidden:      true,
	})
	if err != nil {
		return nil, err
	}
	return &progressDispatcher{next: next}, nil
}

func (d *progressDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == callSysLog {
		var args progressArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.log: %v", err)), nil
		}
		return sys.Result(json.RawMessage(`{}`)), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}
