// Package task owns durable approval: when a program's syscall yields for
// out-of-band confirmation, this package turns the yield into a persisted task
// record, mints an HMAC-derived token the caller resolves against, and on
// approval replays the original syscall back through the wrapped dispatcher
// with the stored resolution as its Authorization. This is the approval
// injection seam the processor deliberately does not own: the processor's syscall
// host path always passes a zero Authorization, so promoting a human decision
// into a dispatch is the runtime's job, keyed by the intent the replay layer
// journaled.
//
// It owns the task lifecycle, not the capability behind the task and not what
// the task is once written down: the underlying dispatcher and the durable
// store are injected, and the record itself is durable vocabulary, defined in
// internal/agent/durable.
package task

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Store is the durable task store the dispatcher mints and reads records in.
type Store interface {
	Find(ctx context.Context, scope durable.ProcessContext, position int) (durable.TaskRecord, bool, error)
	Create(ctx context.Context, record durable.TaskRecord) error
}

// Dispatcher sits below the replay layer: by the time a syscall reaches it,
// the replay dispatcher has already journaled the intent, so the current
// journal tail is this syscall's intent record. That intent position is the
// task's identity within the process revision — a resumed process reaches the
// same position again and finds the same task.
type Dispatcher struct {
	Next        sys.Dispatcher[durable.ProcessContext]
	Store       Store
	Journal     journaled.Journal
	Now         func() time.Time
	TokenSecret []byte
	TaskTTL     time.Duration
}

func (d *Dispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	// The replay layer appends the intent before delegating, so the syscall's
	// journal position is the current tail.
	position := d.Journal.Length() - 1
	// Replay refuses a different call at a recorded position, and a fork mints a
	// new revision, so (process revision, position) names one call.
	record, found, err := d.Store.Find(ctx, cred, position)
	if err != nil {
		return sys.SyscallResult{}, err
	}
	if found {
		return d.resume(ctx, cred, record)
	}

	result, err := d.Next.Dispatch(ctx, cred, syscall, auth)
	if err != nil || result.Status() != sys.StatusYield {
		return result, err
	}
	now := d.now()
	taskID, err := randomID()
	if err != nil {
		return sys.SyscallResult{}, err
	}
	record = durable.TaskRecord{
		Scope:           cred,
		ID:              taskID,
		JournalPosition: position,
		Syscall:         syscall.Copy(),
		Summary:         result.Message(),
		State:           durable.TaskPending,
		CreatedAt:       now,
	}
	// The TTL bounds a wait on someone's decision. A timer waits on nobody: its
	// fire time is its deadline, and the runtime's task sweep resolves it then,
	// however late (an elapsed timer fires at boot), so a TTL could only race it.
	if d.TaskTTL > 0 && syscall.Name != sys.SyscallTimer {
		expires := now.Add(d.TaskTTL)
		record.ExpiresAt = &expires
	}
	durable.StampTaskToken(&record, d.TokenSecret)
	if err := d.Store.Create(ctx, record); err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Yield(record.ID), nil
}

func (d *Dispatcher) resume(ctx context.Context, cred durable.ProcessContext, record durable.TaskRecord) (sys.SyscallResult, error) {
	switch record.State {
	case durable.TaskPending:
		if record.ExpiresAt != nil && !d.now().Before(*record.ExpiresAt) {
			return sys.FailCode(sys.ErrnoExpired, "external task expired"), nil
		}
		return sys.Yield(record.ID), nil
	case durable.TaskApproved:
		return d.Next.Dispatch(ctx, cred, record.Syscall, record.Resolution)
	case durable.TaskCompleted:
		return sys.Result(record.Resolution.Data), nil
	case durable.TaskDenied:
		return sys.FailCode(sys.ErrnoDenied, cmp.Or(record.Resolution.Reason, "external task denied")), nil
	case durable.TaskFailed:
		return sys.FailCode(sys.ErrnoInternal, cmp.Or(record.Resolution.Reason, "external task failed")), nil
	case durable.TaskCancelled:
		return sys.FailCode(sys.ErrnoDenied, "external task cancelled"), nil
	case durable.TaskExpired:
		return sys.FailCode(sys.ErrnoExpired, "external task expired"), nil
	default:
		return sys.SyscallResult{}, fmt.Errorf("unsupported task state %q", record.State)
	}
}

func (d *Dispatcher) now() time.Time { return d.Now().UTC() }

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "task_" + hex.EncodeToString(raw[:]), nil
}
