// Package agent is the runtime: it owns session and process lifecycle, the
// scheduler-driven quanta that resume Wasm programs on the capcompute processor,
// durable approval tasks and timers, retries, and the session read the public
// API exposes. All
// durable state is a fold of one append-only event stream per session — the
// runtime keeps no mutable row store, and restore rebuilds in-memory state by
// replaying each stream from the beginning.
//
// It does not own capability implementations, program bytes, or any concrete
// store: dispatchers, programs, the event log, leases, and the processor's process
// table are all injected. The aurora package re-exports this package's types
// as the module's public surface.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	internalhost "github.com/aurora-capcompute/aurora-capcompute/internal/agent/host"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

const (
	defaultMaxConcurrentProcesses = 16
	// defaultProcessMemoryPages caps a guest's linear memory at 256 MiB by
	// default, so no single guest can walk the runtime toward the 4 GiB wasm
	// ceiling. defaultMaxQuantumDuration stops a guest that spins without
	// yielding after two minutes of wall-clock. Both are host-safety bounds the
	// distribution can raise, lower, or disable via Config.
	defaultProcessMemoryPages = 4096
	defaultMaxQuantumDuration = 2 * time.Minute
	// defaultMaxAbortRetries bounds how many times a process may abort and re-run
	// the section it abandoned before the retry is refused.
	defaultMaxAbortRetries = 10
)

// evictionDrainTimeout bounds how long RemoveProgram waits for the processes it
// stopped to reach a terminal state before it releases the program image
// anyway. A driver that ignores its cancellation must not hold a withdrawal
// hostage.
const evictionDrainTimeout = 5 * time.Second

// evictionPollInterval is how often the drain re-reads the state of the
// processes it is waiting on.
const evictionPollInterval = 10 * time.Millisecond

// resolveGuestLimits maps the Config knobs to the host's per-process bounds:
// zero requests the safe default, a positive value is used verbatim, and a
// negative value disables the bound (0 = unbounded). Keeping this pure makes the
// "bounded by default, never accidentally unbounded" policy directly testable
// without compiling a guest. The returned duration is the quantum ceiling: the
// default when a caller names no deadline, and the most any caller may ask for.
func resolveGuestLimits(memoryPages int, maxQuantum time.Duration) (pages uint32, ceiling time.Duration) {
	switch {
	case memoryPages < 0:
		pages = 0 // explicitly unbounded
	case memoryPages == 0:
		pages = defaultProcessMemoryPages
	default:
		pages = uint32(memoryPages)
	}
	switch {
	case maxQuantum < 0:
		ceiling = 0 // explicitly unbounded
	case maxQuantum == 0:
		ceiling = defaultMaxQuantumDuration
	default:
		ceiling = maxQuantum
	}
	return pages, ceiling
}

// clampDeadline resolves a caller's requested quantum bound against the host's.
// The host ceiling is a bound, never a grant: a caller may ask for less than the
// host allows and never for more, and asking for nothing takes the host's own
// value. A host that disabled the bound (ceiling 0) honours the request
// verbatim, since there is nothing to clamp to.
func (r *Runtime) clampDeadline(requested time.Duration) time.Duration {
	if requested <= 0 {
		return r.quantumCeiling
	}
	if r.quantumCeiling > 0 && requested > r.quantumCeiling {
		return r.quantumCeiling
	}
	return requested
}

// reconcileGrants fails closed when the dispatcher provider advertises a
// capability the manifest did not grant. The grant set the processor Validator
// enforces is the process's grant table, so a provider that publishes more than
// the manifest declared would silently widen a process's authority beyond its
// manifest — the confused-deputy gap. Reconciling the
// provider's leaf output against the manifest here makes the manifest the
// enforced source of truth rather than a trusted input.
//
// Only the provider's own leaf capabilities are checked: the runtime reserves
// its protocol syscalls (sys.input/output/log/abort/now/random and the
// manifest-gated sys.timer) into the table afterwards, so they are not yet in
// `advertised` when this runs and need no exception here. Under-advertising (a leaf
// grant the provider chose not to serve) is not a leak — the guest simply cannot
// call it — so only over-advertising fails the check.
func reconcileGrants(advertised []capability.Descriptor, manifest manifest.Manifest) error {
	granted := make(map[string]struct{}, len(manifest.Syscalls))
	for _, leaf := range manifest.LeafSyscalls() {
		granted[leaf.Syscall] = struct{}{}
	}
	var leaked []string
	for _, capability := range advertised {
		if _, ok := granted[capability.Name]; !ok {
			leaked = append(leaked, capability.Name)
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		return fmt.Errorf("%w: dispatcher provider advertises capabilities the manifest did not grant: %s",
			errs.Invalid, strings.Join(leaked, ", "))
	}
	return nil
}

// openIntentPolicy turns the operator's non-idempotent capability set into a
// replay open-intent policy: an open intent (a journaled effect with no recorded
// completion, met on crash-resume) for one of those capabilities is surfaced as
// indeterminate rather than silently re-executed, giving at-most-once for
// effects that must not run twice. Empty set → nil → retry everything (the
// framework default: at-least-once).
func openIntentPolicy(nonIdempotent []string) replay.OpenIntentPolicy {
	if len(nonIdempotent) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(nonIdempotent))
	for _, name := range nonIdempotent {
		if name = strings.TrimSpace(name); name != "" {
			set[name] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return func(syscall sys.Syscall) replay.OpenIntentDecision {
		if _, ok := set[syscall.Name]; ok {
			return replay.FailOpenIntent
		}
		return replay.RetryOpenIntent
	}
}

func NewRuntime(ctx context.Context, config Config) (*Runtime, error) {
	if config.Dispatchers == nil {
		return nil, fmt.Errorf("%w: dispatcher provider is required", errs.Invalid)
	}
	if config.Log == nil {
		return nil, fmt.Errorf("%w: event log is required", errs.Invalid)
	}
	if len(config.TaskSecret) == 0 {
		return nil, fmt.Errorf("%w: task secret is required", errs.Invalid)
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	var err error
	memoryPages, quantumCeiling := resolveGuestLimits(config.ProcessMemoryPages, config.MaxQuantumDuration)
	runtime := &Runtime{
		baseCtx:         baseCtx,
		cancel:          cancel,
		taints:          monitor.NewTaints[processKey](),
		log:             config.Log,
		tenantID:        strings.TrimSpace(config.TenantID),
		sessions:        make(map[string]*sessionState),
		processes:       make(map[string]*processState),
		idSource:        config.IDSource,
		now:             config.Now,
		taskSecret:      append([]byte(nil), config.TaskSecret...),
		taskTTL:         config.TaskTTL,
		maxAbortRetries: config.MaxAbortRetries,
		dispatchers:     config.Dispatchers,
	}
	runtime.memoryPages, runtime.quantumCeiling = memoryPages, quantumCeiling
	if runtime.tenantID == "" {
		runtime.tenantID = DefaultTenantID
	}
	if runtime.idSource == nil {
		runtime.idSource = randomID
	}
	if runtime.now == nil {
		runtime.now = time.Now
	}
	runtime.tasks = newEventTaskStore(runtime.log, runtime.now)
	if runtime.taskTTL <= 0 {
		runtime.taskTTL = 24 * time.Hour
	}
	if runtime.maxAbortRetries <= 0 {
		runtime.maxAbortRetries = defaultMaxAbortRetries
	}
	if err := runtime.restore(ctx); err != nil {
		return nil, fmt.Errorf("restore runtime: %w", err)
	}

	runtime.factory, err = internalhost.New(internalhost.Config[processKey, ProcessContext]{
		Environment: runtime,
		Taints:      runtime.taints,
		Tasks:       runtime.tasks,
		TaskSecret:  runtime.taskSecret,
		TaskTTL:     runtime.taskTTL,
		Wrap:        runtime.wrapProtocol,
		OpenIntents: openIntentPolicy(config.NonIdempotentSyscalls),
		Now:         runtime.now,
	})
	if err != nil {
		return nil, err
	}

	maxConcurrent := config.MaxConcurrentProcesses
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentProcesses
	}
	runtime.programs = newProgramRegistry(memoryPages)
	runtime.pool = newPool(baseCtx, maxConcurrent)

	go runtime.sweepLoop()
	return runtime, nil
}

// taskSweepInterval is how often the runtime settles due tasks and wakes the
// processes parked on settled ones. A timer fires within this of its time.
const taskSweepInterval = time.Second

// sweepLoop sweeps once at start — deadlines can pass while the host is down —
// and then on every interval, until the runtime closes.
func (r *Runtime) sweepLoop() {
	ticker := time.NewTicker(taskSweepInterval)
	defer ticker.Stop()
	for {
		r.sweepTasks()
		select {
		case <-r.baseCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepTasks settles every pending task whose deadline passed — a timer fires,
// an unanswered approval expires and the guest gets errno expired — and then
// wakes every process parked on a task that is no longer pending. The wake is
// read from state rather than carried by the resolution, so a wake that fails
// (at boot, before the programs are loaded) happens on a later sweep. The task
// store decides each task under its lock, so a human resolving at the deadline
// and the sweep cannot both win.
func (r *Runtime) sweepTasks() {
	now := r.now().UTC()
	for _, taskID := range r.tasks.Due(now) {
		if err := r.tasks.Settle(context.Background(), r.tenantID, taskID, now); err != nil {
			slog.Warn("settle task", "task_id", taskID, "error", err)
		}
	}
	for _, processID := range r.parkedOnSettledTasks() {
		if err := r.wake(processID); err != nil {
			slog.Debug("wake process", "process_id", processID, "error", err)
		}
	}
}

// parkedOnSettledTasks lists the processes waiting on a task that no longer
// waits on anyone.
func (r *Runtime) parkedOnSettledTasks() []string {
	r.mu.Lock()
	var waiting []string
	for id, proc := range r.processes {
		if proc.status == durable.ProcessWaitingTask {
			waiting = append(waiting, id)
		}
	}
	r.mu.Unlock()
	var settled []string
	for _, id := range waiting {
		records, err := r.tasks.List(context.Background(), r.tenantID, id)
		if err == nil && !hasPendingTask(records) {
			settled = append(settled, id)
		}
	}
	return settled
}

// wake resumes a process parked on a task. It leaves a process in any other
// state alone, so the resolver and the sweep may both call it.
func (r *Runtime) wake(processID string) error {
	r.mu.Lock()
	proc := r.processes[processID]
	waiting := proc != nil && proc.status == durable.ProcessWaitingTask
	r.mu.Unlock()
	if !waiting {
		return nil
	}
	_, err := r.Retry(processID, RetryResume)
	return err
}

// Drivers builds the driver chain below the task layer for one process: the
// application's capability dispatcher wrapped with progress reporting.
func (r *Runtime) Drivers(resolveCtx context.Context, cred ProcessContext) (sys.Dispatcher[ProcessContext], *capability.Table, error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	var spec manifest.Manifest
	if proc != nil {
		spec = proc.manifest.Clone()
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, nil, fmt.Errorf("%w: process %s", errs.NotFound, cred.ProcessID)
	}
	table, err := r.dispatchers.NewDispatcher(resolveCtx, cred, spec)
	if err != nil {
		return nil, nil, err
	}
	if err := reconcileGrants(table.Descriptors(), spec); err != nil {
		return nil, nil, err
	}
	// The routing dispatcher is built here, from the table the provider returned,
	// rather than by the provider: the chain that serves a call and the index the
	// monitor judges it against are then the same object by construction.
	var base sys.Dispatcher[ProcessContext] = capability.NewDispatcher[ProcessContext](table)
	if grant, ok := spec.FindSyscall(manifest.TimerSyscall); ok {
		// sys.timer is the runtime's own, served below the task layer so its
		// yield becomes a durable timer task.
		base, err = newTimerDispatcher(base, grant, table)
		if err != nil {
			return nil, nil, err
		}
	}
	progress, err := newProgressDispatcher(base, table)
	if err != nil {
		return nil, nil, err
	}
	return progress, table, nil
}

// wrapProtocol stacks the runtime's protocol layers above the task layer: the
// agent lifecycle outermost, whose sys.input payload advertises every capability
// beneath it.
func (r *Runtime) wrapProtocol(cred ProcessContext, next sys.Dispatcher[ProcessContext], table *capability.Table) (sys.Dispatcher[ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	var spec manifest.Manifest
	var input string
	var history []HistoryMessage
	var attempt int
	if proc != nil {
		spec = proc.manifest.Clone()
		input = proc.input
		// A manifest declaring history:false serves no session history on its
		// sys.input — the process sees only its own input.
		if !proc.hideHistory {
			history = append([]HistoryMessage(nil), proc.history...)
		}
		attempt = proc.attempt
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", errs.NotFound, cred.ProcessID)
	}
	return newLifecycleDispatcher(
		next,
		input,
		history,
		spec,
		attempt,
		func(answer string) error {
			program, ok := r.programs.get(ProgramID(spec.Program))
			if !ok {
				return fmt.Errorf("%w: program %q is not loaded", errs.Conflict, spec.Program)
			}
			return program.validateOutput(answer)
		},
		table,
	)
}

// ProcessJournal returns the process's live journal view.
func (r *Runtime) ProcessJournal(_ context.Context, cred ProcessContext) (journaled.Journal, error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	r.mu.Unlock()
	if proc == nil || proc.journal == nil {
		return nil, fmt.Errorf("%w: process %s has no journal", errs.NotFound, cred.ProcessID)
	}
	if proc.journal.rev != cred.Revision {
		return nil, fmt.Errorf("%w: process %s journal is at revision %d, not %d",
			errs.Conflict, cred.ProcessID, proc.journal.rev, cred.Revision)
	}
	return proc.journal, nil
}

// TaskScope is the credential in the task store's scope shape.
//
// Drivers, ProcessJournal, Header and TaskScope together are the runtime's
// half of host.Environment — everything one process's dispatcher chain needs
// that only the runtime can know. They are exported for that seam, not for
// callers: aurora.Runtime is a closed interface and does not list them.
func (r *Runtime) TaskScope(cred ProcessContext) durable.TaskScope { return cred.taskScope() }

// Header is the journal writer identity for one process revision: the
// syscall ABI, the program digest as the program, and the process id. The
// tape refuses to replay a journal whose recorded header differs — the
// versioned-replay law.
func (r *Runtime) Header(cred ProcessContext) journaled.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	program := ""
	if proc := r.processes[cred.ProcessID]; proc != nil {
		program = proc.digest
	}
	return journaled.Header{ABI: sys.ABIVersion, Program: program, Process: cred.ProcessID}
}

// AddProgram registers one program and compiles its wasm. Registering is always
// a replace: a taken id is withdrawn first — settling the processes bound to it
// — and the incoming program takes its place. A program is never swapped under a
// live process, because processes are immutably bound to the (name, identity)
// they were created from; the withdrawal is what settles them.
func (r *Runtime) AddProgram(ctx context.Context, data ProgramData) error {
	if _, taken := r.programs.get(data.ID); taken {
		if err := r.RemoveProgram(ctx, string(data.ID)); err != nil {
			return err
		}
	}
	if err := r.programs.add(ctx, data); err != nil {
		return err
	}
	// A Close that raced this registration has already drained the registry, so
	// check after publishing and undo: otherwise the image this call compiled
	// would stay open with nothing left to close it.
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		if release, ok := r.programs.remove(data.ID); ok {
			_ = release(context.Background())
		}
		return fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	return nil
}

// RemoveProgram unregisters a program and settles the processes bound to it: each
// is stopped and ejected, so nothing keeps running against code the app has
// withdrawn. They stay auditable, and they stay bound to the identity they were
// created from — re-adding the same bytes and the same contract lets them retry,
// while a changed program leaves them stranded (the immutability law, enforced on
// every execution attempt).
//
// A process that cannot be stopped — one parked mid-rollback, which has to settle
// its effects first — is left alone and logged. It can still never execute under a
// changed program.
func (r *Runtime) RemoveProgram(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	release, ok := r.programs.remove(ProgramID(id))
	if !ok {
		return fmt.Errorf("%w: program %q is not registered", errs.NotFound, id)
	}
	r.mu.Lock()
	var bound []string
	for processID, proc := range r.processes {
		if proc.manifest.Program == id && !isTerminal(proc.status) {
			bound = append(bound, processID)
		}
	}
	r.mu.Unlock()

	sort.Strings(bound)
	for _, processID := range bound {
		if _, err := r.Stop(processID); err != nil {
			slog.Warn("eject process on program removal", "program", id, "process", processID, "error", err)
		}
	}
	// A stop is asynchronous: it asks, the process goroutine settles. Wait for
	// that before releasing the image, so an evicted process records the stop it
	// was given rather than whatever the processor reports when its compiled
	// module is closed mid-quantum. Both are terminal — closing an image under a
	// live module is recovered by the processor, not a crash — but a process is an
	// audit target and its final state must not turn on which of the two won.
	r.drainProcesses(ctx, id, bound)
	_ = release(context.Background())
	return nil
}

// drainProcesses waits, bounded, for stopped processes to reach a terminal
// state. The bound is what keeps a driver that ignores its cancellation from
// holding a program withdrawal hostage: whatever is still unwinding when the
// caller's context is done — or when the standing bound expires, whichever comes
// first — is logged and left to settle on its own. It polls rather than
// subscribing because the processes span sessions and the wait is short.
func (r *Runtime) drainProcesses(ctx context.Context, programID string, processIDs []string) {
	if len(processIDs) == 0 {
		return
	}
	// Wall-clock, not r.now: this waits on real goroutines, and an injected test
	// clock that never advances would wait forever.
	expired := time.After(evictionDrainTimeout)
	ticker := time.NewTicker(evictionPollInterval)
	defer ticker.Stop()
	pending := processIDs
	for {
		if pending = r.unsettled(pending); len(pending) == 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			slog.Warn("program withdrawal stopped waiting on unwinding processes",
				"program", programID, "processes", pending, "error", ctx.Err())
			return
		case <-expired:
			slog.Warn("program withdrawn with processes still unwinding",
				"program", programID, "processes", pending)
			return
		}
	}
}

// unsettled filters process ids down to those that have not reached a terminal
// state (an id the runtime no longer holds counts as settled). It returns a new
// slice rather than filtering in place, so a caller's list survives the call.
func (r *Runtime) unsettled(processIDs []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	pending := make([]string, 0, len(processIDs))
	for _, processID := range processIDs {
		if proc := r.processes[processID]; proc != nil && !isTerminal(proc.status) {
			pending = append(pending, processID)
		}
	}
	return pending
}

// CreateSession opens a session under the tenant. An explicit name is the
// session's handle (unique per tenant; empty means unnamed — its id is then the
// handle). The session's identity is persisted immediately as a session.state
// event, so a named session survives a restart even before it runs anything.
func (r *Runtime) CreateSession(name string, tags map[string]string) (SessionSnapshot, error) {
	name = strings.TrimSpace(name)
	id, err := r.idSource("ses_")
	if err != nil {
		return SessionSnapshot{}, err
	}
	now := r.now().UTC()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	if err := r.checkSessionNameFreeLocked(name, ""); err != nil {
		return SessionSnapshot{}, err
	}
	session := &sessionState{id: id, name: name, title: durable.DefaultSessionTitle, createdAt: now, updatedAt: now, tags: durable.CloneTags(tags)}
	r.sessions[id] = session
	if err := r.appendSession(session); err != nil {
		delete(r.sessions, id)
		return SessionSnapshot{}, err
	}
	return r.sessionSnapshotLocked(session), nil
}

// RenameSession changes a session's explicit handle. The new name must be free
// within the tenant; empty clears it (the id becomes the handle again).
func (r *Runtime) RenameSession(sessionID, name string) (SessionSnapshot, error) {
	name = strings.TrimSpace(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		return SessionSnapshot{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	if err := r.checkSessionNameFreeLocked(name, sessionID); err != nil {
		return SessionSnapshot{}, err
	}
	previous := session.name
	session.name = name
	session.updatedAt = r.now().UTC()
	if err := r.appendSession(session); err != nil {
		session.name = previous
		return SessionSnapshot{}, err
	}
	return r.sessionSnapshotLocked(session), nil
}

// checkSessionNameFreeLocked rejects a name already held by another session of
// the tenant. An empty name is always free (unnamed sessions coexist).
func (r *Runtime) checkSessionNameFreeLocked(name, exceptID string) error {
	if name == "" {
		return nil
	}
	for id, session := range r.sessions {
		if id != exceptID && session.name == name {
			return fmt.Errorf("%w: a session named %q already exists", errs.Conflict, name)
		}
	}
	return nil
}

func (r *Runtime) ListSessions() []SessionSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionSummary, 0, len(r.sessions))
	for _, session := range r.sessions {
		out = append(out, r.sessionSummaryLocked(session))
	}
	return out
}

func (r *Runtime) Programs() []Program {
	return r.programs.list()
}

func (r *Runtime) GetSession(sessionID string) (SessionSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.sessions[sessionID]
	if session == nil {
		return SessionSnapshot{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	return r.sessionSnapshotLocked(session), nil
}

// enrollLocked adds one goroutine to the runtime's wait group. It must be
// called under the same unbroken hold of r.mu as the caller's r.closed check:
// Close sets closed under r.mu and then waits on the group, so an Add landing
// after the counter began draining would panic on a reused WaitGroup. Holding
// the lock across both is what makes that ordering impossible, and this is the
// one place that rule is written down.
func (r *Runtime) enrollLocked() { r.wg.Add(1) }

// MakeProcess starts a process on a session. deadline bounds each of its
// quanta — the guest's own uninterrupted compute between syscalls, and anything
// between syscalls. Zero takes the host default; anything above
// the host ceiling is clamped down to it, so a caller can only ever ask for less
// than the host allows.
func (r *Runtime) CreateProcess(sessionID string, input string, spec manifest.Manifest, deadline time.Duration) (ProcessSnapshot, error) {
	if input == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: input is required", errs.Invalid)
	}
	spec, err := manifest.Validate(spec, r.dispatchers)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	// A process that opts out of capability sharing keeps its grants off its own
	// sys.input menu (it still holds them). manifest.Validate returned a clone, so
	// this is local. History is applied below via hideHistory.
	if !spec.SharesCapabilities() {
		for i := range spec.Syscalls {
			spec.Syscalls[i].Hidden = true
		}
	}
	program, ok := r.programs.get(ProgramID(spec.Program))
	if !ok {
		return ProcessSnapshot{}, fmt.Errorf("%w: program %q is not registered", errs.Invalid, spec.Program)
	}
	if err := program.validateInput(input); err != nil {
		return ProcessSnapshot{}, err
	}
	processID, err := r.idSource("proc_")
	if err != nil {
		return ProcessSnapshot{}, err
	}
	now := r.now().UTC()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	if session.activeProcessID != "" {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", errs.Conflict, session.activeProcessID)
	}
	proc := &processState{
		id:        processID,
		sessionID: sessionID,
		input:     input,
		history:   append([]HistoryMessage(nil), session.history...),
		status:    durable.ProcessQueued,
		attempt:   1,
		createdAt: now,
		updatedAt: now,
		manifest:  spec,
		revision:  1,
		digest:    program.Digest,
		deadline:  r.clampDeadline(deadline),
		// A root manifest with history:false opts out of session-history sharing —
		// each run sees only its own input and inherits no cross-run taint. Reuses
		// the hideHistory delivery gate (and its persistence).
		hideHistory: !spec.SharesHistory(),
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	r.processes[processID] = proc
	session.processIDs = append(session.processIDs, processID)
	if len(session.processIDs) == 1 {
		session.title = durable.SessionTitle(input)
	}
	session.activeProcessID = processID
	session.updatedAt = now
	if err := r.appendProcess(proc); err != nil {
		delete(r.processes, processID)
		session.processIDs = session.processIDs[:len(session.processIDs)-1]
		session.activeProcessID = ""
		r.mu.Unlock()
		return ProcessSnapshot{}, err
	}
	snapshot := r.processSnapshotLocked(proc)
	r.enrollLocked()
	r.mu.Unlock()

	go r.execute(processID)
	return snapshot, nil
}

func (r *Runtime) GetProcess(processID string) (ProcessSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil {
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	return r.processSnapshotLocked(proc), nil
}

func (r *Runtime) ResolveTask(taskID, token string, resolution durable.TaskResolution) (TaskSnapshot, error) {
	switch resolution.Decision {
	case durable.TaskApproved, durable.TaskCompleted, durable.TaskFailed, durable.TaskDenied, durable.TaskCancelled:
	default:
		return TaskSnapshot{}, fmt.Errorf("%w: unsupported task decision %q", errs.Invalid, resolution.Decision)
	}
	if resolution.Decision == durable.TaskCompleted && !json.Valid(resolution.Data) {
		return TaskSnapshot{}, fmt.Errorf("%w: completed task data must be valid JSON", errs.Invalid)
	}
	sum := sha256.Sum256([]byte(token))
	record, err := r.tasks.Resolve(
		context.Background(), r.tenantID, taskID, sum[:], resolution, r.now().UTC(),
	)
	if err != nil {
		return TaskSnapshot{}, err
	}

	// The resolution stands whether or not the wake works: a process that cannot
	// resume now (its program is not loaded) is woken by a later sweep.
	if err := r.wake(record.Scope.ProcessID); err != nil {
		slog.Warn("wake process after task resolution", "process_id", record.Scope.ProcessID, "task_id", record.ID, "error", err)
	}
	return r.taskSnapshot(record), nil
}

func (r *Runtime) Stop(processID string) (ProcessSnapshot, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	switch proc.status {
	case durable.ProcessQueued, durable.ProcessRunning:
		proc.stopRequested = true
		proc.status = durable.ProcessStopping
		proc.updatedAt = r.now().UTC()
		if proc.stop != nil {
			proc.stop()
		}
	case durable.ProcessYielded, durable.ProcessWaitingTask:
		// A parked process stops where it stands. Its journal is the record of
		// what ran — nothing is undone — so an open savepoint section is left
		// open, and a later retry resumes or restarts from it.
		r.finishLocked(proc, durable.ProcessStopped, "", context.Canceled)
	case durable.ProcessStopping, durable.ProcessStopped:
	default:
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot be stopped from %s", errs.Conflict, processID, proc.status)
	}
	_ = r.appendProcess(proc)
	snapshot := r.processSnapshotLocked(proc)
	r.mu.Unlock()
	return snapshot, nil
}

// Retry re-drives a process on a fresh quantum of its own.
func (r *Runtime) Retry(processID string, mode RetryMode) (ProcessSnapshot, error) {
	if mode != RetryResume && mode != RetryRestart {
		return ProcessSnapshot{}, fmt.Errorf("%w: retry mode must be resume or restart", errs.Invalid)
	}

	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	// Every branch below relaunches the guest. A process is an audit target: it
	// never resumes or restarts under different program bytes. The quantum checks
	// the same binding again before it runs; this is the early, legible refusal.
	if _, err := r.programs.bound(ProgramID(proc.manifest.Program), proc.digest); err != nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, err
	}
	switch proc.status {
	case durable.ProcessYielded, durable.ProcessWaitingTask, durable.ProcessStopped, durable.ProcessFailed, durable.ProcessInterrupted:
	case durable.ProcessCompleted:
		// A completed process has nothing to resume, but it can be restarted from
		// scratch (re-run as a new copy-on-write revision).
		if mode != RetryRestart {
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf("%w: completed process %s can only be restarted, not resumed", errs.Conflict, processID)
		}
	default:
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot retry from %s", errs.Conflict, processID, proc.status)
	}
	session := r.sessions[proc.sessionID]
	// Only the latest process in a session may be retried: an earlier one's
	// answer is already folded into the history the later ones read.
	if len(session.processIDs) == 0 || session.processIDs[len(session.processIDs)-1] != proc.id {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: only the latest session process can be retried", errs.Conflict)
	}
	if session.activeProcessID != "" && session.activeProcessID != proc.id {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", errs.Conflict, session.activeProcessID)
	}

	if mode == RetryRestart {
		// Hard restart: fork from the beginning, giving the program a completely
		// fresh revision with no shared prefix. The abandoned attempt stays in
		// the log as an audited, closed revision; nothing it did is undone.
		proc.err = ""
		r.forkJournalLocked(proc, 0)
	} else if proc.status == durable.ProcessYielded || proc.status == durable.ProcessWaitingTask {
		// Resume from a park: no fork. The journal's open intent at the tail is
		// re-driven by replay, and a resolved task's stored authorization is
		// injected by the task layer.
	} else if forkOffset, open := proc.journal.outermostOpenBegin(); open {
		// Failed/stopped inside a savepoint section: fork at the section's
		// sys.begin so the whole declared unit re-executes live. That is what
		// the brackets are for — without the fork, a deterministic failure
		// replays its broken completion to the same wall forever.
		proc.err = ""
		r.forkJournalLocked(proc, forkOffset)
	}
	// Nothing bracketed: same revision, no fork. A resume continues the attempt —
	// replay serves everything recorded (an open intent at the tail re-drives
	// under its original key) and the guest proceeds mid-flight, so an
	// interruption never opens a new key space.
	return r.relaunchLocked(proc)
}

// relaunchLocked resets a process for a fresh quantum and starts it: queued,
// attempt bumped, terminal fields cleared, its session made active, and the
// transition appended and published. Called with r.mu held; unlocks it.
func (r *Runtime) relaunchLocked(proc *processState) (ProcessSnapshot, error) {
	// Refuse to enroll a new quantum once shutdown has begun: Close sets closed
	// under r.mu then waits on r.wg, so a Retry/ResolveTask racing
	// Close must not wg.Add after the counter may already be draining (a reuse of
	// the WaitGroup would panic) — mirrors CreateProcess.
	if r.closed {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	proc.status = durable.ProcessQueued
	proc.attempt++
	proc.answer = ""
	proc.err = ""
	proc.stopRequested = false
	proc.startedAt = nil
	proc.completedAt = nil
	proc.updatedAt = r.now().UTC()
	if session := r.sessions[proc.sessionID]; session != nil {
		session.activeProcessID = proc.id
		session.updatedAt = proc.updatedAt
	}
	if err := r.appendProcess(proc); err != nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, err
	}
	snapshot := r.processSnapshotLocked(proc)
	processID := proc.id
	r.enrollLocked()
	r.mu.Unlock()

	go r.execute(processID)
	return snapshot, nil
}

// forkJournalLocked re-forks a process's journal at forkOffset as a new
// revision. Forks happen only where an attempt boundary is real — an abandoned
// section re-running, or an explicit restart — never for a plain resume, which
// continues the same revision. Must be called with the runtime mutex held.
func (r *Runtime) forkJournalLocked(proc *processState, forkOffset int) {
	parent := proc.journal
	// The outgoing revision can never run again — this fork is its abandonment —
	// so release its taint. Otherwise the shared taint map accumulates one dead
	// entry per abort-retry/restart fork for the runtime's lifetime; the new
	// revision rebuilds its own taint by replaying the shared prefix's labels.
	r.taints.ForgetProcess(proc.key())
	proc.revision++
	proc.forkOffset = forkOffset
	proc.lastFailureLength = 0
	proc.journal = newLogJournal(
		parent.log, parent.scope, parent.proc, proc.revision,
		parent.history, forkOffset,
		parent.now,
	)
}

func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	stops := make([]func(), 0)
	for _, proc := range r.processes {
		if proc.stop != nil && (proc.status == durable.ProcessRunning || proc.status == durable.ProcessStopping || proc.status == durable.ProcessQueued) {
			stops = append(stops, proc.stop)
		}
	}
	r.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
	// Interrupt in-flight driver calls rather than wait each out to its own
	// timeout. A cancelled call leaves its intent open on the journal, so a
	// restart re-drives it.
	r.cancel()

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Closing the pool drops the waiting quanta and waits out the running ones;
	// then every compiled image is released.
	r.pool.close()
	return errors.Join(r.programs.close(context.Background())...)
}
