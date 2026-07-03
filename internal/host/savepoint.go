package host

import (
	"context"

	"github.com/aurora-capcompute/capcompute/sys"
)

// IsSavepoint reports whether name is one of the kernel's reserved savepoint
// markers (sys.begin / sys.commit).
func IsSavepoint(name string) bool {
	return name == sys.SyscallBegin || name == sys.SyscallCommit
}

// savepointResult is the canonical, side-effect-free result recorded for every
// marker syscall. It is constant so replay matching stays deterministic.
var savepointResult = []byte("{}")

// savepointDispatcher serves the reserved sys.begin/sys.commit markers with a
// fixed Result without invoking Next. Every other syscall passes through
// unchanged. It sits just below the replay layer (so markers are journaled as
// intent/completion pairs) and above the task and delegation layers (so
// markers never become durable tasks or reach a driver). A guest brackets a
// unit of retryable work with begin … commit; on a failed run the runtime
// forks resume just past the outermost begin that was never committed.
type savepointDispatcher[K any] struct {
	next sys.Dispatcher[K]
}

func (d *savepointDispatcher[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if IsSavepoint(syscall.Name) {
		return sys.Result(savepointResult), nil
	}
	return d.next.Dispatch(ctx, cred, syscall, auth)
}

func (d *savepointDispatcher[K]) Capabilities() []sys.Capability {
	return d.next.Capabilities()
}
