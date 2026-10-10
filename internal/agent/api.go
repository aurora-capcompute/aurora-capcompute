package agent

// The types the API returns. The aurora package re-exports them.

import (
	"encoding/json"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// RetryMode is how Retry runs a process again: resume continues its journal,
// restart begins a new revision from the start.
type RetryMode string

const (
	RetryResume  RetryMode = "resume"
	RetryRestart RetryMode = "restart"
)

// HistoryMessage is one turn of a session's conversation: a completed
// process's input (role "user") or answer (role "assistant").
type HistoryMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	// Labels is the taint of the run that wrote an answer. A later process that
	// reads the history inherits it, so re-reading an answer cannot launder
	// what that run observed.
	Labels []string `json:"labels,omitempty"`
}

type SessionSummary struct {
	ID string `json:"id"`
	// Name is the session's explicit, human-readable handle (set at creation,
	// renamable). Empty when the session was created without one — its id is
	// then the handle. Unique when set.
	Name            string            `json:"name,omitempty"`
	Title           string            `json:"title"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	ProcessCount    int               `json:"process_count"`
	ActiveProcessID string            `json:"active_process_id,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// SessionSnapshot is the one session read: the session, its conversation
// history, and every process with its whole journal and its tasks. Every
// narrower view — one revision's journal, a task list — is a grouping of it.
type SessionSnapshot struct {
	SessionSummary `json:"session"`
	History        []HistoryMessage `json:"history,omitempty"`
	Processes      []ProcessLog     `json:"processes"`
}

// ProcessLog is one process's complete durable state: its snapshot, every
// journal entry ever written across all its revisions (each carries its
// position and the revision that wrote it, so the fork structure is
// recoverable), and its tasks.
type ProcessLog struct {
	ProcessSnapshot
	Entries []JournalEntry `json:"entries"`
	Tasks   []TaskSnapshot `json:"tasks,omitempty"`
}

type ProcessSnapshot struct {
	ID            string                `json:"id"`
	SessionID     string                `json:"session_id"`
	Input         string                `json:"input"`
	Status        durable.ProcessStatus `json:"status"`
	Attempt       int                   `json:"attempt"`
	Revision      uint64                `json:"revision"`
	Answer        string                `json:"answer,omitempty"`
	Error         string                `json:"error,omitempty"`
	JournalLength int                   `json:"journal_length"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	StartedAt     *time.Time            `json:"started_at,omitempty"`
	CompletedAt   *time.Time            `json:"completed_at,omitempty"`
	Manifest      manifest.Manifest     `json:"manifest"`
	ProgramDigest string                `json:"program_digest"`
	// Labels is the run's accumulated taint at snapshot time (the union of every
	// source class it has observed). A completed process carries its final taint.
	Labels []string `json:"labels,omitempty"`
}

type TaskSnapshot struct {
	ID              string                 `json:"id"`
	ProcessID       string                 `json:"process_id"`
	Revision        uint64                 `json:"revision"`
	JournalPosition int                    `json:"journal_position"`
	Syscall         sys.Syscall            `json:"syscall"`
	Summary         string                 `json:"summary"`
	State           durable.TaskState      `json:"state"`
	Resolution      durable.TaskResolution `json:"resolution,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	// ResolutionToken is the bearer credential ResolveTask authenticates
	// against — the runtime's only secret-derived task value. How it reaches
	// the resolver (a webhook URL, a chat button callback, a CLI) is the
	// assembly's concern.
	ResolutionToken string `json:"resolution_token"`
}

// JournalEntry is one syscall of a process's journal: the intent (its position
// in the record sequence and the syscall itself) folded together with its
// completion. An entry whose completion has not been journaled yet —
// an in-flight syscall or a pending external task — carries a yield outcome.
type JournalEntry struct {
	Position int            `json:"position"`
	Revision uint64         `json:"revision"`
	Syscall  sys.Syscall    `json:"syscall"`
	Outcome  JournalOutcome `json:"outcome"`
}

type JournalOutcome struct {
	Status  sys.SyscallStatus `json:"status"`
	Code    sys.Errno         `json:"code,omitempty"`
	Result  json.RawMessage   `json:"result,omitempty"`
	Message string            `json:"message,omitempty"`
	Labels  []string          `json:"labels,omitempty"`
}
