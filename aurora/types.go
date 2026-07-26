package aurora

import (
	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/program"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
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
type ProcessGraphNode = agent.ProcessGraphNode
type SessionGraph = agent.SessionGraph
type SessionGraphProcess = agent.SessionGraphProcess
type Event = agent.Event
type JournalEvent = agent.JournalEvent
type ProgressEvent = agent.ProgressEvent
type ProgramArtifact = program.Artifact
type ProgramData = program.Data
type Schema = program.Schema

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
	ProcessCompensated = durable.ProcessCompensated
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
// EventLog implementation (and a Leases implementation for cross-instance
// coordination); the runtime folds the log into session/process/task projections.
// This module ships the interfaces only — concrete stores (in-memory, SQLite)
// are assembly ingredients that live in their own modules.

type EventLog = eventlog.Log
type LogEvent = eventlog.Event
type LogScope = eventlog.Scope
type Leases = agent.Leases
type ProcessContext = agent.ProcessContext

// Quota bounds one tenant's concurrent process quanta (see Config.QuotaOf).
type Quota = sched.Quota

// Task types

type TaskScope = task.Scope
type TaskRecord = task.Record
type TaskState = sys.Decision
type Resolution = sys.Authorization

const (
	TaskStatePending   = task.StatePending
	TaskStateApproved  = task.StateApproved
	TaskStateCompleted = task.StateCompleted
	TaskStateFailed    = task.StateFailed
	TaskStateDenied    = task.StateDenied
	TaskStateCancelled = task.StateCancelled
	TaskStateExpired   = task.StateExpired
	TaskStateExecuted  = task.StateExecuted
)

// Error sentinels

var (
	ErrNotFound = errs.NotFound
	ErrConflict = errs.Conflict
	ErrInvalid  = errs.Invalid

	ErrTaskNotFound     = task.ErrNotFound
	ErrTaskConflict     = task.ErrConflict
	ErrTaskGone         = task.ErrGone
	ErrTaskUnauthorized = task.ErrUnauthorized
)

// Constants

const (
	DefaultTenantID   = agent.DefaultTenantID
	ManifestVersion   = manifest.Version
	SpawnSyscall      = manifest.SpawnSyscall
	TimerSyscall      = manifest.TimerSyscall
	DeclassifySyscall = manifest.DeclassifySyscall
)
