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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Dispatcher sits below the replay layer: by the time a syscall reaches it,
// the replay dispatcher has already journaled the intent, so the current
// journal tail is this syscall's intent record. That intent position is the
// task's identity within the process revision — a resumed process re-reaches the same
// position and finds the same task.
type Dispatcher[K any] struct {
	Next        sys.Dispatcher[K]
	Store       durable.TaskStore
	Journal     journaled.Journal
	Scope       func(K) durable.TaskScope
	Now         func() time.Time
	TokenSecret []byte
	TaskTTL     time.Duration
}

func (d *Dispatcher[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if d.Next == nil || d.Store == nil || d.Journal == nil || d.Scope == nil {
		return sys.SyscallResult{}, errors.New("task dispatcher is not configured")
	}
	scope := d.Scope(cred)
	// The replay layer appends the intent before delegating, so the syscall's
	// journal position is the current tail.
	position := max(d.Journal.Length()-1, 0)
	callHash := HashCall(syscall)
	record, found, err := d.Store.Find(ctx, scope, position, callHash)
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
		Scope:           scope,
		ID:              taskID,
		JournalPosition: position,
		CallHash:        callHash,
		Syscall:         syscall.Copy(),
		Summary:         result.Message(),
		State:           durable.TaskPending,
		CreatedAt:       now,
	}
	if d.TaskTTL > 0 {
		expires := now.Add(d.TaskTTL)
		record.ExpiresAt = &expires
	}
	durable.StampTaskToken(&record, d.TokenSecret)
	if err := d.Store.Create(ctx, record); err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Yield(record.ID), nil
}

func (d *Dispatcher[K]) resume(ctx context.Context, cred K, record durable.TaskRecord) (sys.SyscallResult, error) {
	if record.ExpiresAt != nil && !d.now().Before(*record.ExpiresAt) && record.State == durable.TaskPending {
		return sys.FailCode(sys.ErrnoExpired, "external task expired"), nil
	}
	switch record.State {
	case durable.TaskPending:
		return sys.Yield(record.ID), nil
	case durable.TaskApproved:
		result, err := d.Next.Dispatch(ctx, cred, record.Syscall, record.Resolution)
		if err == nil && result.Status() != sys.StatusYield {
			_ = d.Store.MarkExecuted(ctx, record.Scope.TenantID, record.ID, d.now())
		}
		return result, err
	case durable.TaskCompleted:
		return sys.Result(record.Resolution.Data), nil
	case durable.TaskDenied:
		return sys.FailCode(sys.ErrnoDenied, nonempty(record.Resolution.Reason, "external task denied")), nil
	case durable.TaskFailed:
		return sys.FailCode(sys.ErrnoInternal, nonempty(record.Resolution.Reason, "external task failed")), nil
	case durable.TaskCancelled:
		return sys.FailCode(sys.ErrnoDenied, "external task cancelled"), nil
	case durable.TaskExpired:
		return sys.FailCode(sys.ErrnoExpired, "external task expired"), nil
	case durable.TaskExecuted:
		return d.Next.Dispatch(ctx, cred, record.Syscall, record.Resolution)
	default:
		return sys.SyscallResult{}, fmt.Errorf("unsupported task state %q", record.State)
	}
}

// HashCall is a call's identity within one journal position: the same position
// reached with different arguments is a different task.
func HashCall(syscall sys.Syscall) string {
	sum := sha256.New()
	_, _ = sum.Write([]byte(syscall.Name))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write(syscall.Args)
	return hex.EncodeToString(sum.Sum(nil))
}

func (d *Dispatcher[K]) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "task_" + hex.EncodeToString(raw[:]), nil
}

func nonempty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
