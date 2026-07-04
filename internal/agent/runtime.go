// Package agent is the runtime: it owns session and process lifecycle, the
// scheduler-driven quanta that resume Wasm programs on the capcompute kernel,
// durable approval tasks, retries, event subscriptions, and the read
// projections (snapshots, journal, call graph) the public API exposes. All
// durable state is a fold of one append-only event stream per session — the
// runtime keeps no mutable row store, and restore rebuilds in-memory state by
// replaying each stream from the beginning.
//
// It does not own capability implementations, program bytes, or any concrete
// store: dispatchers, programs, the event log, leases, and the kernel's process
// table are all injected. The aurora package re-exports this package's types
// as the module's public surface.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sched"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

	internalhost "github.com/aurora-capcompute/aurora-capcompute/internal/host"
	"github.com/aurora-capcompute/aurora-capcompute/internal/task"

	extism "github.com/extism/go-sdk"
)

const (
	defaultMaxConcurrentProcesses = 16
	defaultMaxResidentProcesses   = 64
)

func NewRuntime(ctx context.Context, config Config) (*Runtime, error) {
	if config.Dispatchers == nil {
		return nil, fmt.Errorf("%w: dispatcher provider is required", ErrInvalid)
	}
	if config.Log == nil {
		return nil, fmt.Errorf("%w: event log is required", ErrInvalid)
	}
	if config.Leases == nil {
		return nil, fmt.Errorf("%w: leases are required", ErrInvalid)
	}
	if config.ProcessTable == nil {
		return nil, fmt.Errorf("%w: process table is required", ErrInvalid)
	}
	if len(config.TaskSecret) == 0 {
		return nil, fmt.Errorf("%w: task secret is required", ErrInvalid)
	}
	programs, err := loadPrograms(ctx, config.Programs)
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		kernels:      make(map[string]*capcompute.Kernel[string, ProcessContext]),
		programs:     programs,
		processTable: config.ProcessTable,
		taints:       capcompute.NewTaints[string](),
		log:          config.Log,
		leases:       config.Leases,
		tenantID:     strings.TrimSpace(config.TenantID),
		sessions:     make(map[string]*sessionState),
		processes:    make(map[string]*processState),
		subscribers:  make(map[string]map[uint64]chan Event),
		idSource:     config.IDSource,
		now:          config.Now,
		eventSize:    config.EventSize,
		taskSecret:   append([]byte(nil), config.TaskSecret...),
		taskTTL:      config.TaskTTL,
		instanceID:   strings.TrimSpace(config.InstanceID),
		leaseTTL:     config.LeaseTTL,
		dispatchers:  config.Dispatchers,
	}
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
	if runtime.eventSize <= 0 {
		runtime.eventSize = 32
	}
	if runtime.taskTTL <= 0 {
		runtime.taskTTL = 24 * time.Hour
	}
	if runtime.instanceID == "" {
		instanceID, err := randomID("instance_")
		if err != nil {
			return nil, err
		}
		runtime.instanceID = instanceID
	}
	if runtime.leaseTTL <= 0 {
		runtime.leaseTTL = time.Hour
	}
	if err := runtime.restore(ctx); err != nil {
		return nil, fmt.Errorf("restore runtime: %w", err)
	}

	runtime.factory = internalhost.Factory[string, ProcessContext]{
		Drivers:    runtime.processDrivers,
		Wrap:       runtime.wrapProtocol,
		NewJournal: runtime.journalFor,
		Header:     runtime.headerFor,
		Taints:     runtime.taints,
		Tasks:      runtime.tasks,
		TaskSecret: runtime.taskSecret,
		TaskTTL:    runtime.taskTTL,
		TaskScope: func(cred ProcessContext) task.Scope {
			return task.Scope{
				TenantID:  cred.TenantID,
				SessionID: cred.SessionID,
				ProcessID: cred.ProcessID,
				Revision:  cred.Revision,
			}
		},
		OnTaskCreated: func(record task.Record) {
			runtime.publish(record.Scope.SessionID, Event{
				Type: "task.created",
				Data: runtime.taskSnapshot(record),
			})
		},
	}

	maxConcurrent := config.MaxConcurrentProcesses
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentProcesses
	}
	maxResident := config.MaxResidentProcesses
	if maxResident <= 0 {
		maxResident = defaultMaxResidentProcesses
	}
	runtime.scheduler, err = sched.New(sched.Config[string, ProcessContext]{
		Activate: runtime.activateProcess,
		Resume:   runtime.resumeProcess,
		Deactivate: func(pid string, process *capcompute.Process[ProcessContext]) {
			_ = process.Close(context.Background())
		},
		QuotaOf:       config.QuotaOf,
		MaxConcurrent: maxConcurrent,
		MaxResident:   maxResident,
	})
	if err != nil {
		return nil, err
	}

	for _, artifact := range programs.List() {
		source, err := programs.Source(artifact.ID)
		if err != nil {
			return nil, err
		}
		kernel, err := runtime.compileProgram(ctx, artifact.ID, source.Wasm, artifact.Digest)
		if err != nil {
			for _, opened := range runtime.kernels {
				_ = opened.Shutdown(context.Background())
			}
			return nil, err
		}
		runtime.kernels[artifact.ID] = kernel
	}
	return runtime, nil
}

// processDrivers builds the driver chain below the task layer for one process: the
// application's capability dispatcher wrapped with progress reporting.
func (r *Runtime) processDrivers(resolveCtx context.Context, cred ProcessContext) (sys.Dispatcher[ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	var manifest Manifest
	if proc != nil {
		manifest = cloneManifest(proc.manifest)
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", ErrNotFound, cred.ProcessID)
	}
	base, err := r.dispatchers.NewDispatcher(resolveCtx, cred, manifest)
	if err != nil {
		return nil, err
	}
	return newProgressDispatcher(base, r.publish, cred.SessionID, cred.ProcessID), nil
}

// wrapProtocol stacks the runtime's protocol layers above the task layer:
// the delegation router (above tasks, so a delegated child's park suspends
// the parent transparently instead of becoming a human-approvable task), then
// the agent lifecycle outermost — its sys.input payload advertises every
// capability beneath it, delegation tools included.
func (r *Runtime) wrapProtocol(cred ProcessContext, next sys.Dispatcher[ProcessContext]) (sys.Dispatcher[ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	var manifest Manifest
	var message string
	var history []HistoryMessage
	if proc != nil {
		manifest = cloneManifest(proc.manifest)
		message = proc.message
		history = append([]HistoryMessage(nil), proc.history...)
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", ErrNotFound, cred.ProcessID)
	}
	if agents := manifest.agentTools(); len(agents) > 0 {
		router, err := newAgentRouter(next, agents, r)
		if err != nil {
			return nil, err
		}
		next = router
	}
	return newLifecycleDispatcher(next, message, history, manifest), nil
}

// journalFor returns the process's live journal view.
func (r *Runtime) journalFor(_ context.Context, cred ProcessContext) (journaled.Journal, error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	r.mu.Unlock()
	if proc == nil || proc.journal == nil {
		return nil, fmt.Errorf("%w: process %s has no journal", ErrNotFound, cred.ProcessID)
	}
	if proc.journal.rev != cred.Revision {
		return nil, fmt.Errorf("%w: process %s journal is at revision %d, not %d",
			ErrConflict, cred.ProcessID, proc.journal.rev, cred.Revision)
	}
	return proc.journal, nil
}

// headerFor is the journal writer identity for one process revision: the
// syscall ABI, the program digest as the program, and the process id. The
// tape refuses to
// replay a journal whose recorded header differs — the versioned-replay law.
func (r *Runtime) headerFor(cred ProcessContext) journaled.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	program := ""
	if proc := r.processes[cred.ProcessID]; proc != nil {
		program = proc.programDigest
	}
	return journaled.Header{ABI: sys.ABIVersion, Program: program, Process: cred.ProcessID}
}

// compileProgram compiles a program's wasm into a kernel. It is pure with respect
// to runtime state, so it can be called outside the runtime mutex while
// preparing a SetPrograms swap.
func (r *Runtime) compileProgram(ctx context.Context, id string, wasm []byte, digest string) (*capcompute.Kernel[string, ProcessContext], error) {
	kernel, err := capcompute.NewKernel(ctx, capcompute.Config[string, ProcessContext]{
		Image: extism.Manifest{
			Wasm: []extism.Wasm{extism.WasmData{Data: wasm, Hash: digest, Name: id}},
		},
		PluginConfig: extism.PluginConfig{EnableWasi: true},
		ProcessTable: r.processTable,
	})
	if err != nil {
		return nil, fmt.Errorf("compile program %q: %w", id, err)
	}
	return kernel, nil
}

// SetPrograms declaratively reconciles the registered programs to the given set:
// programs absent from the set are removed, new or content-changed programs are
// (re)compiled, and unchanged programs are left running. It is safe to call at any
// time; the control plane uses it to hot-load programs from Program CRDs without a
// restart. Compilation happens outside the runtime mutex so dispatch is only
// briefly paused for the swap. If any program fails to compile, no change is
// applied. Removing a program that an in-flight process is using is best-effort:
// that process fails on its next step.
func (r *Runtime) SetPrograms(ctx context.Context, sources []ProgramSource) error {
	current := r.programs.digests()
	desired := make(map[string]struct{}, len(sources))

	// Compile additions/replacements outside the lock; fail atomically.
	type compiled struct {
		id     string
		wasm   []byte
		digest string
		kernel *capcompute.Kernel[string, ProcessContext]
	}
	var fresh []compiled
	for _, src := range sources {
		id := strings.TrimSpace(src.ID)
		if id == "" || len(src.Wasm) == 0 {
			return fmt.Errorf("%w: program id and wasm bytes are required", ErrInvalid)
		}
		if _, dup := desired[id]; dup {
			return fmt.Errorf("%w: duplicate program %q", ErrInvalid, id)
		}
		desired[id] = struct{}{}
		wasm := append([]byte(nil), src.Wasm...)
		digest := digestOf(wasm)
		if cur, ok := current[id]; ok && cur == digest {
			continue // unchanged
		}
		kernel, err := r.compileProgram(ctx, id, wasm, digest)
		if err != nil {
			for _, c := range fresh {
				_ = c.kernel.Shutdown(context.Background())
			}
			return err
		}
		fresh = append(fresh, compiled{id: id, wasm: wasm, digest: digest, kernel: kernel})
	}

	// Swap under the runtime mutex (which guards r.kernels), collecting the
	// kernels that are being replaced or removed so they can be shut down
	// after the lock is released.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		for _, c := range fresh {
			_ = c.kernel.Shutdown(context.Background())
		}
		return fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	var retired []*capcompute.Kernel[string, ProcessContext]
	for _, c := range fresh {
		if old := r.kernels[c.id]; old != nil {
			retired = append(retired, old)
		}
		r.kernels[c.id] = c.kernel
		r.programs.put(c.id, c.wasm, c.digest)
	}
	for id := range current {
		if _, keep := desired[id]; keep {
			continue
		}
		if old := r.kernels[id]; old != nil {
			retired = append(retired, old)
		}
		delete(r.kernels, id)
		r.programs.remove(id)
	}
	r.mu.Unlock()

	for _, old := range retired {
		_ = old.Shutdown(context.Background())
	}
	return nil
}

func (r *Runtime) CreateSession(tags map[string]string) (SessionSnapshot, error) {
	id, err := r.idSource("ses_")
	if err != nil {
		return SessionSnapshot{}, err
	}
	now := r.now().UTC()
	session := &sessionState{id: id, title: "New session", createdAt: now, updatedAt: now, tags: cloneTags(tags)}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	r.sessions[id] = session
	return r.sessionSnapshotLocked(session), nil
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

func (r *Runtime) Programs() []ProgramArtifact {
	return r.programs.List()
}

func (r *Runtime) GetSession(sessionID string) (SessionSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.sessions[sessionID]
	if session == nil {
		return SessionSnapshot{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	return r.sessionSnapshotLocked(session), nil
}

func (r *Runtime) CreateProcess(sessionID string, message string, manifest Manifest) (ProcessSnapshot, error) {
	if message == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: message is required", ErrInvalid)
	}
	if strings.TrimSpace(manifest.Program) == "" {
		manifest.Program = r.programs.DefaultID()
	}
	manifest, err := ValidateManifest(manifest, r.dispatchers)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	program, err := r.programs.Resolve(manifest.Program)
	if err != nil {
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
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	if session.activeProcessID != "" {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", ErrConflict, session.activeProcessID)
	}
	proc := &processState{
		id:            processID,
		sessionID:     sessionID,
		message:       message,
		history:       append([]HistoryMessage(nil), session.history...),
		status:        ProcessQueued,
		attempt:       1,
		createdAt:     now,
		updatedAt:     now,
		manifest:      manifest,
		revision:      1,
		programDigest: program.Digest,
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	r.processes[processID] = proc
	session.processIDs = append(session.processIDs, processID)
	if len(session.processIDs) == 1 {
		session.title = sessionTitle(message)
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
	r.mu.Unlock()

	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	r.wg.Add(1)
	go r.execute(processID)
	return snapshot, nil
}

func (r *Runtime) GetProcess(processID string) (ProcessSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil {
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", ErrNotFound, processID)
	}
	return r.processSnapshotLocked(proc), nil
}

// Journal returns the process's current-revision journal as per-syscall entries:
// each intent folded together with its completion, open intents rendered as
// in-flight. Entry positions are intent-record positions in the hash-chained
// journal.
func (r *Runtime) Journal(processID string) ([]JournalEntry, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", ErrNotFound, processID)
	}
	if proc.journal == nil {
		return nil, fmt.Errorf("%w: process %s has no readable journal", ErrNotFound, processID)
	}
	return proc.journal.entries()
}

// JournalRevisions returns a per-revision snapshot of the process's journal.
// For each revision r the snapshot contains, at every position, the record with
// the highest revision ≤ r — i.e. the effective state of the process at that point.
// Each entry's Revision field reflects when it was first written, so callers can
// distinguish steps carried forward from earlier revisions versus steps first
// executed at revision r.
func (r *Runtime) JournalRevisions(processID string) (map[uint64][]JournalEntry, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", ErrNotFound, processID)
	}
	if proc.journal == nil {
		return nil, fmt.Errorf("%w: process %s has no readable journal", ErrNotFound, processID)
	}
	journal := proc.journal
	revs := journal.history.allRevisions()
	result := make(map[uint64][]JournalEntry, len(revs))
	for _, rev := range revs {
		view := newLogJournal(journal.log, journal.scope, journal.proc, rev,
			journal.history, journal.history.lengthAt(rev), journal.now, nil)
		entries, err := view.entries()
		if err != nil {
			return nil, err
		}
		result[rev] = entries
	}
	return result, nil
}

func (r *Runtime) Tasks(processID string) ([]TaskSnapshot, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", ErrNotFound, processID)
	}
	records, err := r.tasks.List(context.Background(), r.tenantID, processID)
	if err != nil {
		return nil, err
	}
	out := make([]TaskSnapshot, 0, len(records))
	for _, record := range records {
		out = append(out, r.taskSnapshot(record))
	}
	return out, nil
}

func (r *Runtime) ResolveTask(taskID, token string, resolution task.Resolution) (TaskSnapshot, error) {
	switch resolution.Decision {
	case task.StateApproved, task.StateCompleted, task.StateFailed, task.StateDenied, task.StateCancelled:
	default:
		return TaskSnapshot{}, fmt.Errorf("%w: unsupported task decision %q", ErrInvalid, resolution.Decision)
	}
	if resolution.Decision == task.StateCompleted && !json.Valid(resolution.Data) {
		return TaskSnapshot{}, fmt.Errorf("%w: completed task data must be valid JSON", ErrInvalid)
	}
	acquired, err := r.leases.Acquire(
		context.Background(), r.tenantID, "task", taskID,
		r.instanceID, r.now().UTC(), time.Minute,
	)
	if err != nil {
		return TaskSnapshot{}, err
	}
	if !acquired {
		return TaskSnapshot{}, fmt.Errorf("%w: task is being resolved", ErrConflict)
	}
	defer r.leases.Release(context.Background(), r.tenantID, "task", taskID, r.instanceID)

	sum := sha256.Sum256([]byte(token))
	record, err := r.tasks.Resolve(
		context.Background(), r.tenantID, taskID, sum[:], resolution, r.now().UTC(),
	)
	if err != nil {
		return TaskSnapshot{}, err
	}
	r.publish(record.Scope.SessionID, Event{Type: "task.updated", Data: r.taskSnapshot(record)})

	r.mu.Lock()
	proc := r.processes[record.Scope.ProcessID]
	shouldResume := proc != nil && proc.status == ProcessWaitingTask
	r.mu.Unlock()
	if shouldResume {
		if _, retryErr := r.Retry(record.Scope.ProcessID, RetryResume); retryErr != nil {
			return TaskSnapshot{}, retryErr
		}
	}
	return r.taskSnapshot(record), nil
}

func (r *Runtime) Stop(processID string) (ProcessSnapshot, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", ErrNotFound, processID)
	}
	switch proc.status {
	case ProcessQueued:
		proc.stopRequested = true
		proc.status = ProcessStopping
		proc.updatedAt = r.now().UTC()
		if proc.stop != nil {
			proc.stop()
		}
	case ProcessRunning:
		proc.stopRequested = true
		proc.status = ProcessStopping
		proc.updatedAt = r.now().UTC()
		if proc.stop != nil {
			proc.stop()
		}
	case ProcessYielded, ProcessWaitingTask:
		r.finishLocked(proc, ProcessStopped, "", context.Canceled)
	case ProcessStopping, ProcessStopped:
	default:
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot be stopped from %s", ErrConflict, processID, proc.status)
	}
	snapshot := r.processSnapshotLocked(proc)
	_ = r.appendProcess(proc)
	r.mu.Unlock()
	r.publish(proc.sessionID, Event{Type: "process.updated", Data: snapshot})
	return snapshot, nil
}

func (r *Runtime) Retry(processID string, mode RetryMode) (ProcessSnapshot, error) {
	if mode != RetryResume && mode != RetryRestart {
		return ProcessSnapshot{}, fmt.Errorf("%w: retry mode must be resume or restart", ErrInvalid)
	}

	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", ErrNotFound, processID)
	}
	switch proc.status {
	case ProcessYielded, ProcessWaitingTask, ProcessStopped, ProcessFailed, ProcessInterrupted:
	case ProcessCompleted:
		// A completed process has nothing to resume, but it can be restarted from
		// scratch (re-run as a new copy-on-write revision). This also lets a
		// parent restart cascade into already-completed children.
		if mode != RetryRestart {
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf("%w: completed process %s can only be restarted, not resumed", ErrConflict, processID)
		}
	default:
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot retry from %s", ErrConflict, processID, proc.status)
	}
	session := r.sessions[proc.sessionID]
	if proc.parentProcessID == "" {
		// Root processes may only be retried if no later user-initiated process has arrived.
		// Child processes that were added to the same session by delegation do not count.
		lastRootID := ""
		for i := len(session.processIDs) - 1; i >= 0; i-- {
			if r.processes[session.processIDs[i]] != nil && r.processes[session.processIDs[i]].parentProcessID == "" {
				lastRootID = session.processIDs[i]
				break
			}
		}
		if lastRootID == "" || lastRootID != proc.id {
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf("%w: only the latest session process can be retried", ErrConflict)
		}
	}
	// Allow cascade retry of a child while its parent holds activeProcessID.
	if session.activeProcessID != "" && session.activeProcessID != proc.id &&
		(proc.parentProcessID == "" || session.activeProcessID != proc.parentProcessID) {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", ErrConflict, session.activeProcessID)
	}

	if mode == RetryRestart {
		// Hard restart: always fork from the beginning (the sys.input step),
		// giving the program a completely fresh revision with no shared prefix.
		r.forkJournalLocked(proc, 0, RetryRestart)
	} else if proc.status == ProcessYielded || proc.status == ProcessWaitingTask {
		// Resume from a park: no fork. The journal's open intent at the tail is
		// re-driven by replay under its original idempotency key; a resolved
		// task's stored authorization is injected by the task layer. When the
		// park was a delegated child's approval, enable cascade reconnection so
		// the re-executed delegation call reuses the now-finished child.
		if proc.reconnectChildren {
			proc.cascade = true
			proc.cascadeMode = RetryResume
			proc.cascadeCursor = childrenBefore(proc.childSpawnOffsets, proc.journal.Length())
		} else {
			proc.cascade = false
		}
	} else {
		// Failed/stopped/interrupted resume: fork at the end of the journal and
		// let the program continue, replaying every recorded outcome including
		// soft failures. A failed process only forks earlier when the program
		// explicitly left a savepoint open: we fork right after the outermost
		// still-open sys.begin so its whole body re-executes live under the
		// bumped revision.
		forkOffset := proc.journal.Length()
		if proc.status == ProcessFailed {
			if off, ok := proc.journal.outermostOpenBegin(); ok {
				forkOffset = off
			}
		}
		r.forkJournalLocked(proc, forkOffset, RetryResume)
	}
	proc.status = ProcessQueued
	proc.attempt++
	proc.answer = ""
	proc.err = ""
	proc.failure = nil
	proc.stopRequested = false
	proc.startedAt = nil
	proc.completedAt = nil
	proc.updatedAt = r.now().UTC()
	session.activeProcessID = proc.id
	session.updatedAt = proc.updatedAt
	if err := r.appendProcess(proc); err != nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, err
	}
	snapshot := r.processSnapshotLocked(proc)
	r.mu.Unlock()

	r.publish(proc.sessionID, Event{Type: "process.updated", Data: snapshot})
	r.wg.Add(1)
	go r.execute(processID)
	return snapshot, nil
}

// forkJournalLocked re-forks process's journal at forkOffset as a new revision,
// records the retry mode for downstream cascade children, and positions the
// cascade cursor. Must be called with the runtime mutex held.
func (r *Runtime) forkJournalLocked(proc *processState, forkOffset int, mode RetryMode) {
	parent := proc.journal
	proc.revision++
	proc.forkOffset = forkOffset
	proc.journal = newLogJournal(
		parent.log, parent.scope, parent.proc, proc.revision,
		parent.history, forkOffset,
		parent.now, parent.onAppend,
	)
	// Reuse the existing child subtree in spawn order (deep cascade resume).
	// Children whose delegation call is replayed from the shared prefix are
	// skipped; the cursor starts at the first child re-executed past the fork.
	proc.cascade = true
	proc.cascadeMode = mode
	proc.cascadeCursor = childrenBefore(proc.childSpawnOffsets, forkOffset)
}

// childrenBefore counts the children whose delegation completion sits inside
// the shared prefix [0, offset). A spawn offset is one past the delegation
// intent, so a child is prefix-served — and skipped by the cascade cursor —
// exactly when its offset is strictly below the fork offset; a child whose
// intent closes the prefix (offset == fork offset) is re-executed and must be
// the first the cursor reuses.
func childrenBefore(spawnOffsets []int, offset int) int {
	n := 0
	for _, off := range spawnOffsets {
		if off < offset {
			n++
		}
	}
	return n
}

func (r *Runtime) Subscribe(sessionID string) (Event, <-chan Event, func(), error) {
	r.mu.Lock()
	session := r.sessions[sessionID]
	if session == nil {
		r.mu.Unlock()
		return Event{}, nil, nil, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	r.nextSubID++
	id := r.nextSubID
	ch := make(chan Event, r.eventSize)
	if r.subscribers[sessionID] == nil {
		r.subscribers[sessionID] = make(map[uint64]chan Event)
	}
	r.subscribers[sessionID][id] = ch
	snapshot := Event{Type: "snapshot", Data: r.sessionSnapshotLocked(session)}
	r.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subscribers[sessionID], id)
			r.mu.Unlock()
		})
	}
	return snapshot, ch, unsubscribe, nil
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
		if proc.stop != nil && (proc.status == ProcessRunning || proc.status == ProcessStopping || proc.status == ProcessQueued) {
			stops = append(stops, proc.stop)
		}
	}
	r.mu.Unlock()
	for _, stop := range stops {
		stop()
	}

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		r.scheduler.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	closeErrors := []error{}
	for _, kernel := range r.kernels {
		closeErrors = append(closeErrors, kernel.Shutdown(context.Background()))
	}
	return errors.Join(closeErrors...)
}
