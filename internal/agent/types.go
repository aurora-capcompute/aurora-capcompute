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

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
	internalhost "github.com/aurora-capcompute/aurora-capcompute/internal/host"
	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("lifecycle conflict")
	ErrInvalid  = errors.New("invalid request")
)

type RunStatus string

const (
	RunQueued      RunStatus = "queued"
	RunRunning     RunStatus = "running"
	RunStopping    RunStatus = "stopping"
	RunYielded     RunStatus = "yielded"
	RunWaitingTask RunStatus = "waiting_for_task"
	RunInterrupted RunStatus = "interrupted"
	RunCompleted   RunStatus = "completed"
	RunStopped     RunStatus = "stopped"
	RunFailed      RunStatus = "failed"
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

// Config wires a Runtime. Everything concrete is injected: brains, capability
// drivers, the event log, leases, and the kernel's process table are supplied
// by the application — this module ships interfaces and orchestration only.
type Config struct {
	Brains       BrainProvider
	Dispatchers  DispatcherProvider
	Log          eventlog.Log
	Leases       Leases
	ProcessTable capcompute.ProcessTable[string, RunContext]
	IDSource     func(prefix string) (string, error)
	Now          func() time.Time
	EventSize    int
	TenantID     string
	TaskSecret   []byte
	TaskTTL      time.Duration
	InstanceID   string
	LeaseTTL     time.Duration

	// MaxConcurrentRuns bounds simultaneously executing run quanta across the
	// runtime (0 = a default of 16). Delegated child runs execute inside their
	// parent's quantum and are not counted.
	MaxConcurrentRuns int
	// MaxResidentRuns bounds warm (yielded but activated) guest instances;
	// least-recently-used instances are deactivated past it and reactivate by
	// journal replay (0 = a default of 64).
	MaxResidentRuns int
	// QuotaOf reports a tenant's scheduling quota. Nil means unlimited.
	QuotaOf func(tenant string) sched.Quota
}

type Runtime struct {
	mu           sync.Mutex
	kernels      map[string]*capcompute.Kernel[string, RunContext]
	brains       *loadedBrains
	processTable capcompute.ProcessTable[string, RunContext]
	scheduler    *sched.Scheduler[string, RunContext]
	taints       *capcompute.Taints[string]
	log          eventlog.Log
	leases       Leases
	tasks        *eventTaskStore
	tenantID     string
	threads      map[string]*threadState
	runs         map[string]*runState
	subscribers  map[string]map[uint64]chan Event
	nextSubID    uint64
	idSource     func(string) (string, error)
	now          func() time.Time
	eventSize    int
	taskSecret   []byte
	taskTTL      time.Duration
	instanceID   string
	leaseTTL     time.Duration
	dispatchers  DispatcherProvider
	factory      internalhost.Factory[string, RunContext]
	wg           sync.WaitGroup
	closed       bool
}

type threadState struct {
	id          string
	title       string
	createdAt   time.Time
	updatedAt   time.Time
	history     []HistoryMessage
	runIDs      []string
	activeRunID string
	tags        map[string]string
}

type runState struct {
	id          string
	threadID    string
	message     string
	history     []HistoryMessage
	status      RunStatus
	attempt     int
	createdAt   time.Time
	updatedAt   time.Time
	startedAt   *time.Time
	completedAt *time.Time
	answer      string
	err         string
	journal     *logJournal
	// stop aborts the run's in-flight quantum: the scheduler submission for a
	// root run, the direct resume handle for a delegated child. Nil when no
	// quantum is in flight.
	stop            func()
	stopRequested   bool
	manifest        Manifest
	revision        uint64
	brainDigest     string
	// parentRunID and childRunIDs make delegated runs addressable: a child knows
	// the run that spawned it, and a parent records its children in spawn order.
	parentRunID string
	childRunIDs []string
	// childSpawnOffsets records, parallel to childRunIDs, the journal length at
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
	// cascade re-execution state: when a run is restarted, cascade is set so the
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

// RunContext is the host-side credential for one run revision: the syscall
// triad's "who". The kernel keys processes by PID(); two revisions of one run
// are distinct processes, so a forked retry can never resume a stale instance.
type RunContext struct {
	TenantID string `json:"tenant_id"`
	ThreadID string `json:"thread_id"`
	RunID    string `json:"run_id"`
	Revision uint64 `json:"revision"`
}

func (r RunContext) PID() string {
	return runPID(r.RunID, r.Revision)
}

// runPID derives the kernel process identity for one run revision.
func runPID(runID string, revision uint64) string {
	return fmt.Sprintf("%s@%d", runID, revision)
}

type agentInput struct {
	Message      string           `json:"message"`
	History      []HistoryMessage `json:"history,omitempty"`
	SystemPrompt string           `json:"system_prompt,omitempty"`
	Capabilities []sys.Capability `json:"capabilities,omitempty"`
}

type ThreadSummary struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	RunCount    int               `json:"run_count"`
	ActiveRunID string            `json:"active_run_id,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type ThreadSnapshot struct {
	ThreadSummary
	History []HistoryMessage `json:"history"`
	Runs    []RunSnapshot    `json:"runs"`
}

type RunSnapshot struct {
	ID            string     `json:"id"`
	ThreadID      string     `json:"thread_id"`
	Message       string     `json:"message"`
	Status        RunStatus  `json:"status"`
	Attempt       int        `json:"attempt"`
	Revision      uint64     `json:"revision"`
	Answer        string     `json:"answer,omitempty"`
	Error         string     `json:"error,omitempty"`
	JournalLength int        `json:"journal_length"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Manifest      Manifest   `json:"manifest"`
	BrainDigest   string     `json:"brain_digest"`
}

type TaskSnapshot struct {
	ID              string          `json:"id"`
	RunID           string          `json:"run_id"`
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

// JournalEntry is one syscall of a run's journal: the intent (its position in
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
	RunID         string            `json:"run_id"`
	Position      int               `json:"position"`
	Revision      uint64            `json:"revision"`
	Kind          journaled.Kind    `json:"kind"`
	Syscall       string            `json:"syscall"`
	OutcomeStatus sys.SyscallStatus `json:"outcome_status,omitempty"`
	OutcomeSize   int               `json:"outcome_size,omitempty"`
}
