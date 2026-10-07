package agent

import (
	"context"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute/sys"
)

// savepointResult is the canonical, side-effect-free result recorded for every
// marker syscall. It is constant so replay matching stays deterministic.
var savepointResult = []byte("{}")

// savepointDispatcher serves the reserved sys.begin/sys.commit markers with a
// fixed Result without invoking Next. Every other syscall passes through
// unchanged. It sits just below the replay layer (so markers are journaled as
// intent/completion pairs) and above the task layer (so
// markers never become durable tasks or reach a driver). A guest brackets a
// unit of retryable work with begin … commit; on a failed process the runtime
// forks resume just past the outermost begin that was never committed.
type savepointDispatcher struct {
	next sys.Dispatcher[durable.ProcessContext]
}

func (d *savepointDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == sys.SyscallBegin || syscall.Name == sys.SyscallCommit {
		return sys.Result(savepointResult), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}
