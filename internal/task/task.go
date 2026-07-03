// Package task owns durable approval: when a program's syscall yields for
// out-of-band confirmation, this package turns the yield into a persisted task
// record, mints an HMAC-derived token the caller resolves against, and on
// approval replays the original syscall back through the wrapped dispatcher
// with the stored resolution as its Authorization. This is the approval
// injection seam the kernel deliberately does not own: the kernel's syscall
// host path always passes a zero Authorization, so promoting a human decision
// into a dispatch is the runtime's job, keyed by the intent the replay layer
// journaled. A task's token hash is the only secret-derived value the store
// persists out of band; the record itself omits it from JSON.
//
// It owns the task lifecycle and token scheme, not the capability behind the
// task — the underlying dispatcher and the durable store are injected.
package task

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"
)

type Scope struct {
	TenantID  string
	SessionID string
	RunID     string
	Revision  uint64
}

type State = sys.Decision

const (
	StatePending   State = "pending"
	StateApproved        = sys.Approved
	StateCompleted       = sys.Completed
	StateFailed          = sys.Failed
	StateDenied          = sys.Denied
	StateCancelled       = sys.Cancelled
	StateExpired   State = "expired"
	StateExecuted  State = "executed"
)

type Resolution = sys.Authorization

type Record struct {
	Scope           Scope       `json:"scope"`
	ID              string      `json:"id"`
	JournalPosition int         `json:"journal_position"`
	CallHash        string      `json:"call_hash"`
	Syscall         sys.Syscall `json:"syscall"`
	Summary         string      `json:"summary"`
	State           State       `json:"state"`
	TokenHash       []byte      `json:"-"`
	Resolution      Resolution  `json:"resolution,omitempty"`
	CreatedAt       time.Time   `json:"created_at"`
	ExpiresAt       *time.Time  `json:"expires_at,omitempty"`
	ResolvedAt      *time.Time  `json:"resolved_at,omitempty"`
}

type Store interface {
	Find(context.Context, Scope, int, string) (Record, bool, error)
	Create(context.Context, Record) error
	Get(context.Context, string, string) (Record, error)
	List(context.Context, string, string) ([]Record, error)
	Resolve(context.Context, string, string, []byte, Resolution, time.Time) (Record, error)
	MarkExecuted(context.Context, string, string, time.Time) error
}

var (
	ErrNotFound     = errors.New("task not found")
	ErrConflict     = errors.New("task resolution conflict")
	ErrGone         = errors.New("task is no longer resolvable")
	ErrUnauthorized = errors.New("invalid task token")
)

// Dispatcher sits below the replay layer: by the time a syscall reaches it,
// the replay dispatcher has already journaled the intent, so the current
// journal tail is this syscall's intent record. That intent position is the
// task's identity within the run revision — a resumed run re-reaches the same
// position and finds the same task.
type Dispatcher[K any] struct {
	Next          sys.Dispatcher[K]
	Store         Store
	Journal       journaled.Journal
	Scope         func(K) Scope
	Now           func() time.Time
	TokenSecret   []byte
	TaskTTL       time.Duration
	OnTaskCreated func(Record)
}

func (d *Dispatcher[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if d.Next == nil || d.Store == nil || d.Journal == nil || d.Scope == nil {
		return sys.SyscallResult{}, errors.New("task dispatcher is not configured")
	}
	scope := d.Scope(cred)
	// The replay layer appends the intent before delegating, so the syscall's
	// journal position is the current tail.
	position := d.Journal.Length() - 1
	if position < 0 {
		position = 0
	}
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
	record = Record{
		Scope:           scope,
		ID:              taskID,
		JournalPosition: position,
		CallHash:        callHash,
		Syscall:         syscall.Copy(),
		Summary:         result.Message(),
		State:           StatePending,
		CreatedAt:       now,
	}
	if d.TaskTTL > 0 {
		expires := now.Add(d.TaskTTL)
		record.ExpiresAt = &expires
	}
	token := Token(d.TokenSecret, scope.TenantID, record.ID)
	sum := sha256.Sum256([]byte(token))
	record.TokenHash = sum[:]
	if err := d.Store.Create(ctx, record); err != nil {
		return sys.SyscallResult{}, err
	}
	if d.OnTaskCreated != nil {
		d.OnTaskCreated(record)
	}
	return sys.Yield(record.ID), nil
}

func (d *Dispatcher[K]) resume(ctx context.Context, cred K, record Record) (sys.SyscallResult, error) {
	if record.ExpiresAt != nil && !d.now().Before(*record.ExpiresAt) && record.State == StatePending {
		return sys.FailCode(sys.ErrnoExpired, "external task expired"), nil
	}
	switch record.State {
	case StatePending:
		return sys.Yield(record.ID), nil
	case StateApproved:
		result, err := d.Next.Dispatch(ctx, cred, record.Syscall, record.Resolution)
		if err == nil && result.Status() != sys.StatusYield {
			_ = d.Store.MarkExecuted(ctx, record.Scope.TenantID, record.ID, d.now())
		}
		return result, err
	case StateCompleted:
		return sys.Result(record.Resolution.Data), nil
	case StateDenied:
		return sys.FailCode(sys.ErrnoDenied, nonempty(record.Resolution.Reason, "external task denied")), nil
	case StateFailed:
		return sys.FailCode(sys.ErrnoInternal, nonempty(record.Resolution.Reason, "external task failed")), nil
	case StateCancelled:
		return sys.FailCode(sys.ErrnoDenied, "external task cancelled"), nil
	case StateExpired:
		return sys.FailCode(sys.ErrnoExpired, "external task expired"), nil
	case StateExecuted:
		return d.Next.Dispatch(ctx, cred, record.Syscall, record.Resolution)
	default:
		return sys.SyscallResult{}, fmt.Errorf("unsupported task state %q", record.State)
	}
}

func (d *Dispatcher[K]) Capabilities() []sys.Capability {
	return d.Next.Capabilities()
}

func HashCall(syscall sys.Syscall) string {
	sum := sha256.New()
	_, _ = sum.Write([]byte(syscall.Name))
	_, _ = sum.Write([]byte{0})
	_, _ = sum.Write(syscall.Args)
	return hex.EncodeToString(sum.Sum(nil))
}

func Token(secret []byte, tenantID, taskID string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(tenantID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(taskID))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyToken(expectedHash []byte, token string) bool {
	sum := sha256.Sum256([]byte(token))
	return hmac.Equal(expectedHash, sum[:])
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
