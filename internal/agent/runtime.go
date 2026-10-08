// Package agent is the runtime: it owns session and process lifecycle, the
// scheduler-driven quanta that resume Wasm programs on the capcompute processor,
// durable approval tasks and timers, retries, and the session read the public
// API exposes. All
// durable state is a fold of one append-only event stream per session — the
// runtime keeps no mutable row store, and restore rebuilds in-memory state by
// replaying each stream from the beginning.
//
// It does not own capability implementations, program bytes, or any concrete
// store: dispatchers, programs and the event log are injected. The aurora package re-exports this package's types
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
	"github.com/aurora-capcompute/aurora-capcompute/monitor"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

const (
	defaultMaxConcurrentProcesses = 16
	// processMemoryPages caps a guest's linear memory at 256 MiB, so no single
	// guest can walk the runtime toward the 4 GiB wasm ceiling.
	processMemoryPages = 4096
	// defaultQuantumDeadline stops a quantum after 30 minutes of wall-clock. A
	// quantum includes the driver calls it makes, so the bound must hold an agent
	// run of many LLM and tool calls between two yields.
	defaultQuantumDeadline = 30 * time.Minute
	// maxAbortRetries bounds how many times a process may abort and re-run the
	// section it abandoned before the retry is refused.
	maxAbortRetries = 10
)

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
	runtime := &Runtime{
		baseCtx:         baseCtx,
		cancel:          cancel,
		taints:          monitor.NewTaints[durable.ProcessContext](),
		log:             config.Log,
		sessions:        make(map[string]*sessionState),
		processes:       make(map[string]*processState),
		now:             config.Now,
		taskSecret:      append([]byte(nil), config.TaskSecret...),
		taskTTL:         config.TaskTTL,
		quantumDeadline: config.QuantumDeadline,
		dispatchers:     config.Dispatchers,
	}
	if runtime.now == nil {
		runtime.now = time.Now
	}
	runtime.tasks = newEventTaskStore(runtime.log, runtime.now)
	if runtime.taskTTL <= 0 {
		runtime.taskTTL = 24 * time.Hour
	}
	if runtime.quantumDeadline <= 0 {
		runtime.quantumDeadline = defaultQuantumDeadline
	}
	if err := runtime.restore(ctx); err != nil {
		return nil, fmt.Errorf("restore runtime: %w", err)
	}

	maxConcurrent := config.MaxConcurrentProcesses
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentProcesses
	}
	programs, err := newProgramRegistry(ctx, config.Programs)
	if err != nil {
		return nil, err
	}
	runtime.programs = programs
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
// (the process's program is not loaded) happens on a later sweep. The task
// store decides each task under its lock, so a human resolving at the deadline
// and the sweep cannot both win.
func (r *Runtime) sweepTasks() {
	now := r.now().UTC()
	for _, taskID := range r.tasks.Due(now) {
		if err := r.tasks.Settle(context.Background(), taskID, now); err != nil {
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
		if !hasPendingTask(r.tasks.List(id)) {
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

// CreateSession opens a session. An explicit name is the session's handle
// (unique; empty means unnamed — its id is then the
// handle). The session's identity is persisted immediately as a session.state
// event, so a named session survives a restart even before it runs anything.
func (r *Runtime) CreateSession(name string, tags map[string]string) (SessionSnapshot, error) {
	name = strings.TrimSpace(name)
	id, err := randomID("ses_")
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
	session := &sessionState{id: id, name: name, createdAt: now, updatedAt: now, tags: durable.CloneTags(tags)}
	r.sessions[id] = session
	if err := r.appendSession(session); err != nil {
		delete(r.sessions, id)
		return SessionSnapshot{}, err
	}
	return r.sessionSnapshotLocked(session), nil
}

// RenameSession changes a session's explicit handle. The new name must be free
// empty clears it (the id becomes the handle again).
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
// another session. An empty name is always free (unnamed sessions coexist).
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

// CreateProcess starts a process on a session.
func (r *Runtime) CreateProcess(sessionID string, input string, spec manifest.Manifest) (ProcessSnapshot, error) {
	if input == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: input is required", errs.Invalid)
	}
	spec, err := manifest.Validate(spec, r.dispatchers)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	program, ok := r.programs[ProgramID(spec.Program)]
	if !ok {
		return ProcessSnapshot{}, fmt.Errorf("%w: program %q is not registered", errs.Invalid, spec.Program)
	}
	if err := program.validateInput(input); err != nil {
		return ProcessSnapshot{}, err
	}
	processID, err := randomID("proc_")
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
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	r.processes[processID] = proc
	session.processIDs = append(session.processIDs, processID)
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
		context.Background(), taskID, sum[:], resolution, r.now().UTC(),
	)
	if err != nil {
		return TaskSnapshot{}, err
	}

	// The resolution stands whether or not the wake works: a process that cannot
	// resume now (its program is not loaded) is woken by the first sweep after a
	// restart that loads it.
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
	case durable.ProcessWaitingTask:
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
	case durable.ProcessWaitingTask, durable.ProcessStopped, durable.ProcessFailed, durable.ProcessInterrupted:
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
	} else if proc.status == durable.ProcessWaitingTask {
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
	// replay serves everything recorded (an open intent at the tail is driven
	// again) and the guest proceeds mid-flight, so an interruption never opens
	// a new revision.
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
	r.taints.ForgetProcess(proc.context())
	proc.revision++
	proc.forkOffset = forkOffset
	proc.lastFailureLength = 0
	proc.journal = newLogJournal(
		parent.log, parent.session, parent.proc, proc.revision,
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
