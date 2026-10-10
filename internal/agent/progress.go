package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute/sys"
)

// progressDispatcher serves sys.log, a progress report with no effect. It sits
// below the replay layer, so the report is journaled, and that is how it is
// delivered: a watcher reads it off the journal.
type progressDispatcher struct {
	next sys.Dispatcher[durable.ProcessContext]
}

type progressArgs struct {
	Message string `json:"message"`
}

func newProgressDispatcher(next sys.Dispatcher[durable.ProcessContext], table *capability.Table) (*progressDispatcher, error) {
	err := table.Reserve(capability.Descriptor{
		Name:        sys.SyscallLog,
		Description: "report a short progress message to the user while working",
		Hidden:      true,
	})
	if err != nil {
		return nil, err
	}
	return &progressDispatcher{next: next}, nil
}

func (d *progressDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == sys.SyscallLog {
		var args progressArgs
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.log: %v", err)), nil
		}
		return sys.Result(json.RawMessage(`{}`)), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}
