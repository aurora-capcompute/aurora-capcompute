package agent

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

type RetryMode string

const (
	RetryResume  RetryMode = "resume"
	RetryRestart RetryMode = "restart"
)

type HistoryMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	// Labels is the provenance taint of the run that produced this entry (the
	// assistant answer). Session history is a run-to-run loopback: when a later
	// process reads this history through sys.input, the runtime seeds its taint
	// with these labels, so data a prior run observed (e.g. a source class it
	// read) cannot be laundered across turns by re-reading the answer.
	Labels []string `json:"labels,omitempty"`
}

// DispatcherProvider builds the grant table one process runs under, and
// canonicalizes the grant configs a manifest declares. It lives here rather
// than beside the manifest because building a table needs a process
// credential, which the manifest layer knows nothing about; manifest validation
// asks only for the Normalize half (manifest.Normalizer), which this satisfies.
//
// It returns the index rather than a dispatcher because one index has to answer
// three questions at once — what routes, what the monitor may admit, and what
// flow policy applies — and handing back only a dispatcher would leave the
// other two to be reconstructed, which is where they could disagree.
type DispatcherProvider interface {
	ValidateConfig(syscall string, config json.RawMessage) error
	NewDispatcher(context.Context, durable.ProcessContext, manifest.Manifest) (*capability.Table, error)
}

// Config wires a Runtime. Everything concrete is injected: programs, capability
// drivers and the event log are supplied by the application — this module ships
// interfaces and orchestration only.
type Config struct {
	Dispatchers DispatcherProvider
	Log         eventlog.Log
	Now         func() time.Time
	TaskSecret  []byte
	TaskTTL     time.Duration

	// MaxConcurrentProcesses bounds simultaneously executing process quanta across the
	// runtime (0 = a default of 16).
	MaxConcurrentProcesses int
	// QuantumDeadline bounds one guest quantum's wall-clock time (0 = a default
	// of 2 minutes). A guest still running at the deadline is stopped, so an
	// infinite loop cannot hold a slot forever. Syscalls that wait on the outside
	// world yield (they do not spin), so this bounds only a guest's own
	// uninterrupted compute between yields; a process stopped by the deadline is
	// interrupted, not failed, and re-drives deterministically by replay.
	QuantumDeadline time.Duration
}

type Runtime struct {
	mu sync.Mutex
	// baseCtx is cancelled by Close; long-running background work derives from
	// it so shutdown can interrupt an in-flight driver call rather than wait out
	// its timeout. Metadata appends deliberately do NOT use it — they must
	// complete on shutdown to persist final state.
	baseCtx         context.Context
	cancel          context.CancelFunc
	programs        *programRegistry
	pool            *pool
	taints          *monitor.Taints[durable.ProcessContext]
	log             eventlog.Log
	tasks           *eventTaskStore
	sessions        map[string]*sessionState
	processes       map[string]*processState
	now             func() time.Time
	taskSecret      []byte
	taskTTL         time.Duration
	quantumDeadline time.Duration
	dispatchers     DispatcherProvider
	wg              sync.WaitGroup
	closed          bool
}

type sessionState struct {
	id              string
	name            string
	title           string
	createdAt       time.Time
	updatedAt       time.Time
	history         []HistoryMessage
	processIDs      []string
	activeProcessID string
	tags            map[string]string
}

type processState struct {
	id          string
	sessionID   string
	input       string
	history     []HistoryMessage
	status      durable.ProcessStatus
	attempt     int
	createdAt   time.Time
	updatedAt   time.Time
	startedAt   *time.Time
	completedAt *time.Time
	answer      string
	err         string
	journal     *logJournal
	// labels is the run's accumulated taint, snapshotted at completion (before the
	// per-revision taint is released) so it can ride onto the session-history entry
	// this process contributes and, through it, into a later run that reads it.
	labels []string
	// stop aborts the process's in-flight quantum — the handle the scheduler
	// returned. Nil when no quantum is in flight.
	stop          func()
	stopRequested bool
	manifest      manifest.Manifest
	revision      uint64
	digest        string
	// forkOffset is the current revision's copy-on-write fork point (positions
	// [0, forkOffset) are served from the shared history). It is persisted so a
	// revision that was forked but crashed before logging any record can be
	// reconstructed on restore.
	forkOffset int
	// lastFailureLength is the journal length observed at this revision's most
	// recent guest failure — the re-drive progress guard. Failing again at the
	// same length means the re-drive appended nothing: a deterministic wall,
	// resume is impossible, and the process fails. In-memory only (length
	// grows monotonically within a revision, so losing it to a crash merely
	// buys one extra re-drive); cleared when the journal forks.
	lastFailureLength int
	// abortRetries counts how many times this process forked to re-run a section
	// its guest abandoned with sys.abort. Bounded by maxAbortRetries — the
	// guard against a guest that aborts forever. Being a budget rather than
	// revision state, it survives both the fork it authorized and (being
	// persisted) a host restart: a reset budget is an unbounded loop.
	abortRetries int
}

// context is the identity of the process's current revision.
func (p *processState) context() durable.ProcessContext {
	return durable.ProcessContext{SessionID: p.sessionID, ProcessID: p.id, Revision: p.revision}
}

type agentInput struct {
	Input string `json:"input"`
	// History is the guest-facing role/content projection of the session history.
	// The provenance labels are deliberately NOT here: they seed the flow monitor
	// host-side (via historyLabels) and are never serialized to the guest, so
	// "only role/content reach the guest input" is a host guarantee, not a
	// property of the guest's struct shape (an untrusted guest could read a label
	// field if we sent one — the taint taxonomy and credential fingerprints stay
	// host-only).
	History      []guestHistoryMessage   `json:"history,omitempty"`
	Capabilities []capability.Descriptor `json:"capabilities,omitempty"`
	// Attempt is which run of this process the guest is on (1 = first). A
	// retried process — including an abort-retry — sees a higher attempt, so a
	// program can back off or change strategy.
	Attempt int `json:"attempt,omitempty"`
}

// guestHistoryMessage is a session-history entry as the guest sees it: role and
// content only, never the provenance labels.
type guestHistoryMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// guestHistory projects session history to its guest-facing shape, dropping the
// host-only provenance labels.
func guestHistory(history []HistoryMessage) []guestHistoryMessage {
	if len(history) == 0 {
		return nil
	}
	out := make([]guestHistoryMessage, len(history))
	for i, m := range history {
		out[i] = guestHistoryMessage{Role: m.Role, Content: m.Content}
	}
	return out
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
