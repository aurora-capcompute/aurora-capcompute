package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	internalhost "github.com/aurora-capcompute/aurora-capcompute/internal/agent/host"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("lifecycle conflict")
	ErrInvalid  = errors.New("invalid request")
)

type ProcessStatus string

const (
	ProcessQueued      ProcessStatus = "queued"
	ProcessRunning     ProcessStatus = "running"
	ProcessStopping    ProcessStatus = "stopping"
	ProcessYielded     ProcessStatus = "yielded"
	ProcessWaitingTask ProcessStatus = "waiting_for_task"
	ProcessInterrupted ProcessStatus = "interrupted"
	ProcessCompleted   ProcessStatus = "completed"
	ProcessStopped     ProcessStatus = "stopped"
	ProcessFailed      ProcessStatus = "failed"
	// ProcessCompensated is terminal: the guest rolled the process back with
	// sys.abort — its registered compensations ran — and declared no retry,
	// or exhausted the retry budget.
	ProcessCompensated ProcessStatus = "compensated"
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

// Config wires a Runtime. Everything concrete is injected: programs, capability
// drivers, the event log, leases, and the kernel's process table are supplied
// by the application — this module ships interfaces and orchestration only.
type Config struct {
	Programs    ProgramProvider
	Dispatchers DispatcherProvider
	Log         eventlog.Log
	Leases      Leases
	IDSource    func(prefix string) (string, error)
	Now         func() time.Time
	EventSize   int
	TenantID    string
	TaskSecret  []byte
	TaskTTL     time.Duration
	InstanceID  string
	LeaseTTL    time.Duration

	// MaxConcurrentProcesses bounds simultaneously executing process quanta across the
	// runtime (0 = a default of 16). Delegated child processes execute inside their
	// parent's quantum and are not counted.
	MaxConcurrentProcesses int
	// MaxResidentProcesses bounds warm (yielded but activated) guest instances;
	// least-recently-used instances are deactivated past it and reactivate by
	// journal replay (0 = a default of 64).
	MaxResidentProcesses int
	// MaxAbortRetries bounds how many rollbacks a process gets before a
	// sys.abort retry is refused and the process finishes as compensated
	// (0 = a default of 10) — the guard against a guest that aborts forever.
	// The budget counts rollback cycles (revisions minted), not quanta: crash
	// re-drives and approval parks never spend it.
	MaxAbortRetries int
	// QuotaOf reports a tenant's scheduling quota. Nil means unlimited.
	QuotaOf func(tenant string) sched.Quota

	// NonIdempotentSyscalls names capabilities whose re-execution is unsafe (a
	// second POST charges twice; a second delete errors). On crash-resume the
	// runtime meets an open intent — an effect journaled but with no recorded
	// completion, so its outcome is unknown. By default it retries under the
	// original idempotency key (at-least-once, safe when the driver dedups on the
	// key). For a capability named here it instead surfaces the intent as
	// indeterminate for review rather than silently re-applying it — at-most-once
	// for effects a driver cannot make idempotent. Matched by capability name.
	NonIdempotentSyscalls []string

	// ProcessMemoryPages caps each guest process's linear memory in 64 KiB wasm
	// pages (0 = a default of 4096 = 256 MiB). A guest that allocates past the
	// cap traps and its quantum fails, so a runaway allocation cannot exhaust
	// host memory. Set a negative value to disable the cap (unbounded — a guest
	// may then grow to the wasm 4 GiB ceiling; not recommended in production).
	ProcessMemoryPages int
	// ResumeQuantumTimeout bounds one guest quantum's wall-clock time (0 = a
	// default of 2 minutes). A guest still running at the deadline is stopped,
	// so an infinite loop cannot hold a scheduler slot forever. Syscalls that
	// wait on the outside world yield (they do not spin), so this bounds only a
	// guest's own uninterrupted compute between yields; a stopped quantum
	// re-drives deterministically by replay. Set a negative value to disable it.
	ResumeQuantumTimeout time.Duration
}

type Runtime struct {
	mu sync.Mutex
	// baseCtx is cancelled by Close; long-running background work (rollback
	// compensations) derives from it so shutdown can interrupt an in-flight
	// driver call rather than wait out its timeout. Metadata appends deliberately
	// do NOT use it — they must complete on shutdown to persist final state.
	baseCtx         context.Context
	cancel          context.CancelFunc
	images          map[string]*capcompute.Program
	programs        *loadedPrograms
	scheduler       *sched.Scheduler[string, ProcessContext]
	taints          *monitor.Taints[string]
	log             eventlog.Log
	leases          Leases
	tasks           *eventTaskStore
	tenantID        string
	sessions        map[string]*sessionState
	processes       map[string]*processState
	subscribers     map[string]map[uint64]chan Event
	nextSubID       uint64
	idSource        func(string) (string, error)
	now             func() time.Time
	eventSize       int
	taskSecret      []byte
	taskTTL         time.Duration
	instanceID      string
	leaseTTL        time.Duration
	maxAbortRetries int
	memoryPages     uint32
	resumeTimeout   time.Duration
	dispatchers     DispatcherProvider
	factory         internalhost.Factory[string, ProcessContext]
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
	status      ProcessStatus
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
	// inputLabels is the provenance the process's input arrived with — for a
	// delegated child, the parent's taint snapshot at spawn. sys.input stamps
	// them on its result (beside the history labels) so the child observes what
	// the parent had observed: the input text was composed from the parent's
	// sources, and a fresh, untainted child would otherwise launder them downward
	// — the mirror of the child→parent stamp on the spawn answer.
	inputLabels []string
	// stop aborts the process's in-flight quantum: the scheduler submission for a
	// root process, the direct resume handle for a delegated child. Nil when no
	// quantum is in flight.
	stop          func()
	stopRequested bool
	manifest      Manifest
	revision      uint64
	programDigest string
	// hideHistory suppresses the session history in this process's sys.input —
	// set when it was spawned under a sys.spawn grant with history:false, so an
	// isolated child sees only its input. Persisted, so a restart re-serves the
	// same isolated input. (A hidden capability menu needs no field: the child's
	// grants are simply marked hidden in its stored manifest.)
	hideHistory bool
	// parentProcessID and childProcessIDs make delegated processes addressable: a child knows
	// the process that spawned it, and a parent records its children in spawn order.
	parentProcessID string
	childProcessIDs []string
	// childSpawnOffsets records, parallel to childProcessIDs, the journal length at
	// the moment each child was spawned (one past the delegation intent). It
	// lets a fork-from-offset retry start the cascade cursor past children whose
	// delegation call is replayed from the shared prefix, so only re-executed
	// children are reused.
	childSpawnOffsets []int
	// forkOffset is the current revision's copy-on-write fork point (positions
	// [0, forkOffset) are served from the shared history). It is persisted so a
	// revision that was forked but crashed before logging any record can be
	// reconstructed on restore.
	forkOffset int
	// lastFailureLength is the journal length observed at this revision's most
	// recent guest failure — the re-drive progress guard. Failing again at the
	// same length means the re-drive appended nothing: a deterministic wall,
	// resume is impossible, the section rolls back. In-memory only (length
	// grows monotonically within a revision, so losing it to a crash merely
	// buys one extra re-drive); cleared when the journal forks.
	lastFailureLength int
	// abandoning records the host's abandonment of this revision —
	// abandonFailure, abandonStop, or abandonRestart — set durably (a process
	// event) before its rollback runs, so a crash mid-rollback resumes it to
	// the right end. The stamp stands past the terminal conclusion as the
	// record that the revision was abandoned — the license for a later retry
	// to fork over its settled rollback, which a zero-registration scope
	// leaves no journal trace of — and is cleared only by the fork that opens
	// the successor revision. It is management state and lives here, in the
	// management plane: the journal carries only what the guest did (its
	// calls, and the execution of the undos it registered). The guest's own
	// sys.abort needs no field — its record is in its journal.
	abandoning string
	// cascade re-execution state: when a process is restarted, cascade is set so the
	// delegation router reuses (retries) the existing children at cascadeCursor in
	// spawn order rather than spawning fresh ones. cascadeMode records whether the
	// parent was resumed or restarted so children inherit the right retry mode.
	cascade       bool
	cascadeCursor int
	cascadeMode   RetryMode
	// reconnectChildren makes the delegation router reuse a finished child's
	// terminal result directly when the parent is re-driven after that child's
	// out-of-band approval resolved. Consumed and cleared when the play ends.
	reconnectChildren bool
}

// ProcessContext is the host-side credential for one process revision: the syscall
// triad's "who". The kernel keys instances by PID(); two revisions of one process
// are distinct processes, so a forked retry (a rollback's re-run, a restart)
// can never resume a stale instance. A plain resume deliberately keeps its
// revision — it continues the same attempt — and activates fresh by replay,
// since the scheduler retains only yielded processes as warm residents.
type ProcessContext struct {
	TenantID  string `json:"tenant_id"`
	SessionID string `json:"session_id"`
	ProcessID string `json:"process_id"`
	Revision  uint64 `json:"revision"`
}

func (r ProcessContext) PID() string {
	return processPID(r.ProcessID, r.Revision)
}

// taskScope is the same credential in the task store's scope shape.
func (r ProcessContext) taskScope() task.Scope {
	return task.Scope{
		TenantID:  r.TenantID,
		SessionID: r.SessionID,
		ProcessID: r.ProcessID,
		Revision:  r.Revision,
	}
}

// processPID derives the kernel process identity for one process revision.
func processPID(processID string, revision uint64) string {
	return fmt.Sprintf("%s@%d", processID, revision)
}

type agentInput struct {
	Input string `json:"input"`
	// History is the guest-facing role/content projection of the session history.
	// The provenance labels are deliberately NOT here: they seed the FlowMonitor
	// host-side (via historyLabels) and are never serialized to the guest, so
	// "only role/content reach the guest input" is a host guarantee, not a
	// property of the guest's struct shape (an untrusted guest could read a label
	// field if we sent one — the taint taxonomy and credential fingerprints stay
	// host-only).
	History      []guestHistoryMessage `json:"history,omitempty"`
	Capabilities []sys.Capability      `json:"capabilities,omitempty"`
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
	// then the handle. Unique per tenant when set.
	Name            string            `json:"name,omitempty"`
	Title           string            `json:"title"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	ProcessCount    int               `json:"process_count"`
	ActiveProcessID string            `json:"active_process_id,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
}

type SessionSnapshot struct {
	SessionSummary
	History   []HistoryMessage  `json:"history"`
	Processes []ProcessSnapshot `json:"processes"`
}

type ProcessSnapshot struct {
	ID            string        `json:"id"`
	SessionID     string        `json:"session_id"`
	Input         string        `json:"input"`
	Status        ProcessStatus `json:"status"`
	Attempt       int           `json:"attempt"`
	Revision      uint64        `json:"revision"`
	Answer        string        `json:"answer,omitempty"`
	Error         string        `json:"error,omitempty"`
	JournalLength int           `json:"journal_length"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	StartedAt     *time.Time    `json:"started_at,omitempty"`
	CompletedAt   *time.Time    `json:"completed_at,omitempty"`
	Manifest      Manifest      `json:"manifest"`
	ProgramDigest string        `json:"program_digest"`
	// Labels is the run's accumulated taint at snapshot time (the union of every
	// source class it has observed). A completed process carries its final taint,
	// which the spawn boundary reads to propagate a child's provenance to its
	// parent — so a parent cannot launder a forbidden source by delegating the
	// read to a child and reading the answer back.
	Labels []string `json:"labels,omitempty"`
	// Delegation lineage, so a single-process read shows the call tree the same
	// way StoredProcess and the session graph do.
	ParentProcessID string   `json:"parent_process_id,omitempty"`
	ChildProcessIDs []string `json:"child_process_ids,omitempty"`
}

type TaskSnapshot struct {
	ID              string          `json:"id"`
	ProcessID       string          `json:"process_id"`
	Revision        uint64          `json:"revision"`
	JournalPosition int             `json:"journal_position"`
	Syscall         sys.Syscall     `json:"syscall"`
	Summary         string          `json:"summary"`
	State           task.State      `json:"state"`
	Resolution      task.Resolution `json:"resolution,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	ExpiresAt       *time.Time      `json:"expires_at,omitempty"`
	ResolvedAt      *time.Time      `json:"resolved_at,omitempty"`
	// ResolutionToken is the bearer credential ResolveTask authenticates
	// against — the runtime's only secret-derived task value. How it reaches
	// the resolver (a webhook URL, a chat button callback, a CLI) is the
	// assembly's concern.
	ResolutionToken string `json:"resolution_token"`
}

// JournalEntry is one syscall of a process's journal: the intent (its position in
// the hash-chained record sequence and the syscall itself) folded together
// with its completion. An entry whose completion has not been journaled yet —
// an in-flight syscall or a pending external task — carries a yield outcome.
type JournalEntry struct {
	Position int            `json:"position"`
	Revision uint64         `json:"revision"`
	Syscall  sys.Syscall    `json:"syscall"`
	Outcome  JournalOutcome `json:"outcome"`
	// Compensates names the intent position this entry undoes, for entries in
	// the journal's compensation section (saga unwinding).
	Compensates *int `json:"compensates,omitempty"`
}

type JournalOutcome struct {
	Status  sys.SyscallStatus `json:"status"`
	Code    sys.Errno         `json:"code,omitempty"`
	Result  json.RawMessage   `json:"result,omitempty"`
	Message string            `json:"message,omitempty"`
	Labels  []string          `json:"labels,omitempty"`
}

type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

type JournalEvent struct {
	ProcessID     string            `json:"process_id"`
	Position      int               `json:"position"`
	Revision      uint64            `json:"revision"`
	Kind          journaled.Kind    `json:"kind"`
	Syscall       string            `json:"syscall"`
	OutcomeStatus sys.SyscallStatus `json:"outcome_status,omitempty"`
	OutcomeSize   int               `json:"outcome_size,omitempty"`
}
