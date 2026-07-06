package aurora

import (
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sched"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

// DTOs

type Manifest = agent.Manifest
type Syscall = agent.Syscall
type SpawnSettings = agent.SpawnSettings
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
type ProgramArtifact = agent.ProgramArtifact

// Status types

type ProcessStatus = agent.ProcessStatus

const (
	ProcessQueued      = agent.ProcessQueued
	ProcessRunning     = agent.ProcessRunning
	ProcessStopping    = agent.ProcessStopping
	ProcessYielded     = agent.ProcessYielded
	ProcessWaitingTask = agent.ProcessWaitingTask
	ProcessInterrupted = agent.ProcessInterrupted
	ProcessCompleted   = agent.ProcessCompleted
	ProcessStopped     = agent.ProcessStopped
	ProcessFailed      = agent.ProcessFailed
	ProcessCompensated = agent.ProcessCompensated
)

type RetryMode = agent.RetryMode

const (
	RetryResume  = agent.RetryResume
	RetryRestart = agent.RetryRestart
)

// Construction

type Config = agent.Config
type ProgramSource = agent.ProgramSource
type ProgramProvider = agent.ProgramProvider
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

// ProcessTable is the kernel's process lookup boundary, re-exported at the
// runtime's credential type. Applications supply an implementation (the
// syscall host path resolves each guest syscall through it).
type ProcessTable = capcompute.ProcessTable[string, ProcessContext]

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
	ErrNotFound = agent.ErrNotFound
	ErrConflict = agent.ErrConflict
	ErrInvalid  = agent.ErrInvalid

	ErrTaskNotFound     = task.ErrNotFound
	ErrTaskConflict     = task.ErrConflict
	ErrTaskGone         = task.ErrGone
	ErrTaskUnauthorized = task.ErrUnauthorized
)

// Constants

const (
	DefaultTenantID    = agent.DefaultTenantID
	DefaultProgramID   = agent.DefaultProgramID
	ManifestVersion    = agent.ManifestVersion
	SpawnType          = agent.SpawnType
	OnFailureReport    = agent.OnFailureReport
	OnFailurePropagate = agent.OnFailurePropagate
)
