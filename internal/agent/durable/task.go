package durable

// A durable approval task: what survives of one syscall that yielded for an
// out-of-band decision. The record is persisted vocabulary like Process and
// Session — task.created / task.resolved / task.executed carry it, and Fold
// restores it — so it lives here. The dispatcher that mints and resolves these
// records lives in internal/agent/task, above this package: it is behaviour, and
// behaviour depends on schema rather than the other way round.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

type TaskScope struct {
	SessionID string
	ProcessID string
	Revision  uint64
}

type TaskState = sys.Decision

const (
	TaskPending   TaskState = "pending"
	TaskApproved            = sys.Approved
	TaskCompleted           = sys.Completed
	TaskFailed              = sys.Failed
	TaskDenied              = sys.Denied
	TaskCancelled           = sys.Cancelled
	TaskExpired   TaskState = "expired"
	TaskExecuted  TaskState = "executed"
)

type TaskResolution = sys.Authorization

type TaskRecord struct {
	Scope           TaskScope      `json:"scope"`
	ID              string         `json:"id"`
	JournalPosition int            `json:"journal_position"`
	CallHash        string         `json:"call_hash"`
	Syscall         sys.Syscall    `json:"syscall"`
	Summary         string         `json:"summary"`
	State           TaskState      `json:"state"`
	TokenHash       []byte         `json:"-"`
	Resolution      TaskResolution `json:"resolution"`
	CreatedAt       time.Time      `json:"created_at"`
	ExpiresAt       *time.Time     `json:"expires_at,omitempty"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
}

type TaskStore interface {
	Find(context.Context, TaskScope, int, string) (TaskRecord, bool, error)
	Create(context.Context, TaskRecord) error
	MarkExecuted(context.Context, string, time.Time) error
}

var (
	ErrTaskNotFound     = errors.New("task not found")
	ErrTaskConflict     = errors.New("task resolution conflict")
	ErrTaskGone         = errors.New("task is no longer resolvable")
	ErrTaskUnauthorized = errors.New("invalid task token")
)

func TaskToken(secret []byte, taskID string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(taskID))
	return hex.EncodeToString(mac.Sum(nil))
}

// StampTaskToken derives the record's resolution token from the secret and
// stores its hash on the record — the one way a task is armed. Only the hash is
// ever persisted; the bearer token itself is recomputed on demand from the same
// inputs.
func StampTaskToken(record *TaskRecord, secret []byte) {
	sum := sha256.Sum256([]byte(TaskToken(secret, record.ID)))
	record.TokenHash = sum[:]
}
