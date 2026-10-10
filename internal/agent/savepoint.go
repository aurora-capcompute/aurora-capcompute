package agent

import (
	"context"
	"encoding/json"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute/sys"
)

// savepointDispatcher serves the section markers sys.begin and sys.commit. A
// marker has no effect: it is answered with a fixed result. It sits below the
// replay layer, so the markers are journaled, and that is their whole job: the
// runtime finds open sections by reading them off the journal
// (outermostOpenBegin).
type savepointDispatcher struct {
	next sys.Dispatcher[durable.ProcessContext]
}

func (d *savepointDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name == sys.SyscallBegin || syscall.Name == sys.SyscallCommit {
		return sys.Result(json.RawMessage(`{}`)), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}
