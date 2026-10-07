package aurora

import (
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// DTOs

type Manifest = manifest.Manifest
type Syscall = manifest.Syscall
type SessionSummary = agent.SessionSummary
type SessionSnapshot = agent.SessionSnapshot
type HistoryMessage = agent.HistoryMessage
type ProcessSnapshot = agent.ProcessSnapshot
type TaskSnapshot = agent.TaskSnapshot
type JournalEntry = agent.JournalEntry
type JournalOutcome = agent.JournalOutcome
type ProcessLog = agent.ProcessLog
type ProgramID = agent.ProgramID
type ProgramArtifact = agent.Program
type ProgramData = agent.ProgramData

// Status types

type ProcessStatus = durable.ProcessStatus

const (
	ProcessQueued      = durable.ProcessQueued
	ProcessRunning     = durable.ProcessRunning
	ProcessStopping    = durable.ProcessStopping
	ProcessYielded     = durable.ProcessYielded
	ProcessWaitingTask = durable.ProcessWaitingTask
	ProcessInterrupted = durable.ProcessInterrupted
	ProcessCompleted   = durable.ProcessCompleted
	ProcessStopped     = durable.ProcessStopped
	ProcessFailed      = durable.ProcessFailed
)

type RetryMode = agent.RetryMode

const (
	RetryResume  = agent.RetryResume
	RetryRestart = agent.RetryRestart
)

// Construction

type Config = agent.Config
type DispatcherProvider = agent.DispatcherProvider

// Event log: the single append-only source of truth. Applications provide an
// EventLog implementation; the runtime folds the log into session/process/task
// projections.
// This module ships the interfaces only — concrete stores (in-memory, SQLite)
// are assembly ingredients that live in their own modules.

type EventLog = eventlog.Log
type LogEvent = eventlog.Event
type LogScope = eventlog.Scope
type ProcessContext = agent.ProcessContext

// Task types

type TaskScope = durable.TaskScope
type TaskState = sys.Decision
type Resolution = sys.Authorization

const (
	TaskStatePending   = durable.TaskPending
	TaskStateApproved  = durable.TaskApproved
	TaskStateCompleted = durable.TaskCompleted
	TaskStateFailed    = durable.TaskFailed
	TaskStateDenied    = durable.TaskDenied
	TaskStateCancelled = durable.TaskCancelled
	TaskStateExpired   = durable.TaskExpired
	TaskStateExecuted  = durable.TaskExecuted
)

// Error sentinels

var (
	ErrNotFound = errs.NotFound
	ErrConflict = errs.Conflict
	ErrInvalid  = errs.Invalid

	ErrTaskNotFound     = durable.ErrTaskNotFound
	ErrTaskConflict     = durable.ErrTaskConflict
	ErrTaskGone         = durable.ErrTaskGone
	ErrTaskUnauthorized = durable.ErrTaskUnauthorized
)

// Constants

const (
	DefaultTenantID   = agent.DefaultTenantID
	ManifestVersion   = manifest.Version
	TimerSyscall      = manifest.TimerSyscall
	DeclassifySyscall = manifest.DeclassifySyscall
)
