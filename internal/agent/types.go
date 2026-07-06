package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sched"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

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
}

// Config wires a Runtime. Everything concrete is injected: programs, capability
// drivers, the event log, leases, and the kernel's process table are supplied
// by the application — this module ships interfaces and orchestration only.
type Config struct {
	Programs     ProgramProvider
	Dispatchers  DispatcherProvider
	Log          eventlog.Log
	Leases       Leases
	ProcessTable capcompute.ProcessTable[string, ProcessContext]
	IDSource     func(prefix string) (string, error)
	Now          func() time.Time
	EventSize    int
	TenantID     string
	TaskSecret   []byte
	TaskTTL      time.Duration
	InstanceID   string
	LeaseTTL     time.Duration

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
}

type Runtime struct {
	mu              sync.Mutex
	kernels         map[string]*capcompute.Kernel[string, ProcessContext]
	programs        *loadedPrograms
	processTable    capcompute.ProcessTable[string, ProcessContext]
	scheduler       *sched.Scheduler[string, ProcessContext]
	taints          *capcompute.Taints[string]
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
	dispatchers     DispatcherProvider
	factory         internalhost.Factory[string, ProcessContext]
	wg              sync.WaitGroup
	closed          bool
}

type sessionState struct {
	id              string
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
	message     string
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
	// stop aborts the process's in-flight quantum: the scheduler submission for a
	// root process, the direct resume handle for a delegated child. Nil when no
	// quantum is in flight.
	stop          func()
	stopRequested bool
	manifest      Manifest
	revision      uint64
	programDigest string
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
	// failure forces the run to finish as failed regardless of how its play ends;
	// set when a delegated child fails under an OnFailurePropagate policy.
	failure error
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
	Message      string           `json:"message"`
	History      []HistoryMessage `json:"history,omitempty"`
	SystemPrompt string           `json:"system_prompt,omitempty"`
	Capabilities []sys.Capability `json:"capabilities,omitempty"`
	// Attempt is which run of this process the guest is on (1 = first). A
	// retried process — including an abort-retry — sees a higher attempt, so a
	// program can back off or change strategy.
	Attempt int `json:"attempt,omitempty"`
}

type SessionSummary struct {
	ID              string            `json:"id"`
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
	Message       string        `json:"message"`
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
