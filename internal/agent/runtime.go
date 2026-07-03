// Package agent is the runtime: it owns thread and run lifecycle, the
// scheduler-driven quanta that resume Wasm brains on the capcompute kernel,
// durable approval tasks, retries, event subscriptions, and the read
// projections (snapshots, journal, call graph) the public API exposes. All
// durable state is a fold of one append-only event stream per thread — the
// runtime keeps no mutable row store, and restore rebuilds in-memory state by
// replaying each stream from the beginning.
//
// It does not own capability implementations, brain bytes, or any concrete
// store: dispatchers, brains, the event log, leases, and the kernel's process
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
	defaultMaxConcurrentRuns = 16
	defaultMaxResidentRuns   = 64
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
	brains, err := loadBrains(ctx, config.Brains)
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		kernels:      make(map[string]*capcompute.Kernel[string, RunContext]),
		brains:       brains,
		processTable: config.ProcessTable,
		taints:       capcompute.NewTaints[string](),
		log:          config.Log,
		leases:       config.Leases,
		tenantID:     strings.TrimSpace(config.TenantID),
		threads:      make(map[string]*threadState),
		runs:         make(map[string]*runState),
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

	runtime.factory = internalhost.Factory[string, RunContext]{
		Drivers:    runtime.runDrivers,
		Wrap:       runtime.wrapProtocol,
		NewJournal: runtime.journalFor,
		Header:     runtime.headerFor,
		Taints:     runtime.taints,
		Tasks:      runtime.tasks,
		TaskSecret: runtime.taskSecret,
		TaskTTL:    runtime.taskTTL,
		TaskScope: func(cred RunContext) task.Scope {
			return task.Scope{
				TenantID: cred.TenantID,
				ThreadID: cred.ThreadID,
				RunID:    cred.RunID,
				Revision: cred.Revision,
			}
		},
		OnTaskCreated: func(record task.Record) {
			runtime.publish(record.Scope.ThreadID, Event{
				Type: "task.created",
				Data: runtime.taskSnapshot(record),
			})
		},
	}

	maxConcurrent := config.MaxConcurrentRuns
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRuns
	}
	maxResident := config.MaxResidentRuns
	if maxResident <= 0 {
		maxResident = defaultMaxResidentRuns
	}
	runtime.scheduler, err = sched.New(sched.Config[string, RunContext]{
		Activate: runtime.activateProcess,
		Resume:   runtime.resumeProcess,
		Deactivate: func(pid string, process *capcompute.Process[RunContext]) {
			_ = process.Close(context.Background())
		},
		QuotaOf:       config.QuotaOf,
		MaxConcurrent: maxConcurrent,
		MaxResident:   maxResident,
	})
	if err != nil {
		return nil, err
	}

	for _, artifact := range brains.List() {
		source, err := brains.Source(artifact.ID)
		if err != nil {
			return nil, err
		}
		kernel, err := runtime.compileBrain(ctx, artifact.ID, source.Wasm, artifact.Digest)
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

// runDrivers builds the driver chain below the task layer for one run: the
// application's capability dispatcher wrapped with progress reporting.
func (r *Runtime) runDrivers(resolveCtx context.Context, cred RunContext) (sys.Dispatcher[RunContext], error) {
	r.mu.Lock()
	run := r.runs[cred.RunID]
	var manifest Manifest
	if run != nil {
		manifest = cloneManifest(run.manifest)
	}
	r.mu.Unlock()
	if run == nil {
		return nil, fmt.Errorf("%w: run %s", ErrNotFound, cred.RunID)
	}
	base, err := r.dispatchers.NewDispatcher(resolveCtx, cred, manifest)
	if err != nil {
		return nil, err
	}
	return newProgressDispatcher(base, r.publish, cred.ThreadID, cred.RunID), nil
}

// wrapProtocol stacks the runtime's protocol layers above the task layer:
// the delegation router (above tasks, so a delegated child's park suspends
// the parent transparently instead of becoming a human-approvable task), then
// the agent lifecycle outermost — its agent.input payload advertises every
// capability beneath it, delegation tools included.
func (r *Runtime) wrapProtocol(cred RunContext, next sys.Dispatcher[RunContext]) (sys.Dispatcher[RunContext], error) {
	r.mu.Lock()
	run := r.runs[cred.RunID]
	var manifest Manifest
	var message string
	var history []HistoryMessage
	if run != nil {
		manifest = cloneManifest(run.manifest)
		message = run.message
		history = append([]HistoryMessage(nil), run.history...)
	}
	r.mu.Unlock()
	if run == nil {
		return nil, fmt.Errorf("%w: run %s", ErrNotFound, cred.RunID)
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

// journalFor returns the run's live journal view.
func (r *Runtime) journalFor(_ context.Context, cred RunContext) (journaled.Journal, error) {
	r.mu.Lock()
	run := r.runs[cred.RunID]
	r.mu.Unlock()
	if run == nil || run.journal == nil {
		return nil, fmt.Errorf("%w: run %s has no journal", ErrNotFound, cred.RunID)
	}
	if run.journal.rev != cred.Revision {
		return nil, fmt.Errorf("%w: run %s journal is at revision %d, not %d",
			ErrConflict, cred.RunID, run.journal.rev, cred.Revision)
	}
	return run.journal, nil
}

// headerFor is the journal writer identity for one run revision: the syscall
// ABI, the brain digest as the program, and the run id. The tape refuses to
// replay a journal whose recorded header differs — the versioned-replay law.
func (r *Runtime) headerFor(cred RunContext) journaled.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	program := ""
	if run := r.runs[cred.RunID]; run != nil {
		program = run.brainDigest
	}
	return journaled.Header{ABI: sys.ABIVersion, Program: program, Run: cred.RunID}
}

// compileBrain compiles a brain's wasm into a kernel. It is pure with respect
// to runtime state, so it can be called outside the runtime mutex while
// preparing a SetBrains swap.
func (r *Runtime) compileBrain(ctx context.Context, id string, wasm []byte, digest string) (*capcompute.Kernel[string, RunContext], error) {
	kernel, err := capcompute.NewKernel(ctx, capcompute.Config[string, RunContext]{
		Image: extism.Manifest{
			Wasm: []extism.Wasm{extism.WasmData{Data: wasm, Hash: digest, Name: id}},
		},
		PluginConfig: extism.PluginConfig{EnableWasi: true},
		ProcessTable: r.processTable,
	})
	if err != nil {
		return nil, fmt.Errorf("compile brain %q: %w", id, err)
	}
	return kernel, nil
}

// SetBrains declaratively reconciles the registered brains to the given set:
// brains absent from the set are removed, new or content-changed brains are
// (re)compiled, and unchanged brains are left running. It is safe to call at any
// time; the control plane uses it to hot-load brains from Brain CRDs without a
// restart. Compilation happens outside the runtime mutex so dispatch is only
// briefly paused for the swap. If any brain fails to compile, no change is
// applied. Removing a brain that an in-flight run is using is best-effort: that
// run fails on its next step.
func (r *Runtime) SetBrains(ctx context.Context, sources []BrainSource) error {
	current := r.brains.digests()
	desired := make(map[string]struct{}, len(sources))

	// Compile additions/replacements outside the lock; fail atomically.
	type compiled struct {
		id     string
		wasm   []byte
		digest string
		kernel *capcompute.Kernel[string, RunContext]
	}
	var fresh []compiled
	for _, src := range sources {
		id := strings.TrimSpace(src.ID)
		if id == "" || len(src.Wasm) == 0 {
			return fmt.Errorf("%w: brain id and wasm bytes are required", ErrInvalid)
		}
		if _, dup := desired[id]; dup {
			return fmt.Errorf("%w: duplicate brain %q", ErrInvalid, id)
		}
		desired[id] = struct{}{}
		wasm := append([]byte(nil), src.Wasm...)
		digest := digestOf(wasm)
		if cur, ok := current[id]; ok && cur == digest {
			continue // unchanged
		}
		kernel, err := r.compileBrain(ctx, id, wasm, digest)
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
	var retired []*capcompute.Kernel[string, RunContext]
	for _, c := range fresh {
		if old := r.kernels[c.id]; old != nil {
			retired = append(retired, old)
		}
		r.kernels[c.id] = c.kernel
		r.brains.put(c.id, c.wasm, c.digest)
	}
	for id := range current {
		if _, keep := desired[id]; keep {
			continue
		}
		if old := r.kernels[id]; old != nil {
			retired = append(retired, old)
		}
		delete(r.kernels, id)
		r.brains.remove(id)
	}
	r.mu.Unlock()

	for _, old := range retired {
		_ = old.Shutdown(context.Background())
	}
	return nil
}

func (r *Runtime) CreateThread(tags map[string]string) (ThreadSnapshot, error) {
	id, err := r.idSource("thr_")
	if err != nil {
		return ThreadSnapshot{}, err
	}
	now := r.now().UTC()
	thread := &threadState{id: id, title: "New thread", createdAt: now, updatedAt: now, tags: cloneTags(tags)}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ThreadSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	r.threads[id] = thread
	return r.threadSnapshotLocked(thread), nil
}

func (r *Runtime) ListThreads() []ThreadSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ThreadSummary, 0, len(r.threads))
	for _, thread := range r.threads {
		out = append(out, r.threadSummaryLocked(thread))
	}
	return out
}

func (r *Runtime) Brains() []BrainArtifact {
	return r.brains.List()
}

func (r *Runtime) GetThread(threadID string) (ThreadSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[threadID]
	if thread == nil {
		return ThreadSnapshot{}, fmt.Errorf("%w: thread %s", ErrNotFound, threadID)
	}
	return r.threadSnapshotLocked(thread), nil
}

func (r *Runtime) CreateRun(threadID string, message string, manifest Manifest) (RunSnapshot, error) {
	if message == "" {
		return RunSnapshot{}, fmt.Errorf("%w: message is required", ErrInvalid)
	}
	if strings.TrimSpace(manifest.Brain) == "" {
		manifest.Brain = r.brains.DefaultID()
	}
	manifest, err := ValidateManifest(manifest, r.dispatchers)
	if err != nil {
		return RunSnapshot{}, err
	}
	brain, err := r.brains.Resolve(manifest.Brain)
	if err != nil {
		return RunSnapshot{}, err
	}
	runID, err := r.idSource("run_")
	if err != nil {
		return RunSnapshot{}, err
	}
	now := r.now().UTC()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	thread := r.threads[threadID]
	if thread == nil {
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: thread %s", ErrNotFound, threadID)
	}
	if thread.activeRunID != "" {
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: thread already has active run %s", ErrConflict, thread.activeRunID)
	}
	run := &runState{
		id:          runID,
		threadID:    threadID,
		message:     message,
		history:     append([]HistoryMessage(nil), thread.history...),
		status:      RunQueued,
		attempt:     1,
		createdAt:   now,
		updatedAt:   now,
		manifest:    manifest,
		revision:    1,
		brainDigest: brain.Digest,
	}
	run.journal = r.newJournal(run, newRunHistory(), 0)
	r.runs[runID] = run
	thread.runIDs = append(thread.runIDs, runID)
	if len(thread.runIDs) == 1 {
		thread.title = threadTitle(message)
	}
	thread.activeRunID = runID
	thread.updatedAt = now
	if err := r.appendRun(run); err != nil {
		delete(r.runs, runID)
		thread.runIDs = thread.runIDs[:len(thread.runIDs)-1]
		thread.activeRunID = ""
		r.mu.Unlock()
		return RunSnapshot{}, err
	}
	snapshot := r.runSnapshotLocked(run)
	r.mu.Unlock()

	r.publish(threadID, Event{Type: "run.updated", Data: snapshot})
	r.wg.Add(1)
	go r.execute(runID)
	return snapshot, nil
}

func (r *Runtime) GetRun(runID string) (RunSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[runID]
	if run == nil {
		return RunSnapshot{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	return r.runSnapshotLocked(run), nil
}

// Journal returns the run's current-revision journal as per-syscall entries:
// each intent folded together with its completion, open intents rendered as
// in-flight. Entry positions are intent-record positions in the hash-chained
// journal.
func (r *Runtime) Journal(runID string) ([]JournalEntry, error) {
	r.mu.Lock()
	run := r.runs[runID]
	r.mu.Unlock()
	if run == nil {
		return nil, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	if run.journal == nil {
		return nil, fmt.Errorf("%w: run %s has no readable journal", ErrNotFound, runID)
	}
	return run.journal.entries()
}

// JournalRevisions returns a per-revision snapshot of the run's journal.
// For each revision r the snapshot contains, at every position, the record with
// the highest revision ≤ r — i.e. the effective state of the run at that point.
// Each entry's Revision field reflects when it was first written, so callers can
// distinguish steps carried forward from earlier revisions versus steps first
// executed at revision r.
func (r *Runtime) JournalRevisions(runID string) (map[uint64][]JournalEntry, error) {
	r.mu.Lock()
	run := r.runs[runID]
	r.mu.Unlock()
	if run == nil {
		return nil, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	if run.journal == nil {
		return nil, fmt.Errorf("%w: run %s has no readable journal", ErrNotFound, runID)
	}
	journal := run.journal
	revs := journal.history.allRevisions()
	result := make(map[uint64][]JournalEntry, len(revs))
	for _, rev := range revs {
		view := newLogJournal(journal.log, journal.scope, journal.run, rev,
			journal.history, journal.history.lengthAt(rev), journal.now, nil)
		entries, err := view.entries()
		if err != nil {
			return nil, err
		}
		result[rev] = entries
	}
	return result, nil
}

func (r *Runtime) Tasks(runID string) ([]TaskSnapshot, error) {
	r.mu.Lock()
	run := r.runs[runID]
	r.mu.Unlock()
	if run == nil {
		return nil, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	records, err := r.tasks.List(context.Background(), r.tenantID, runID)
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
	r.publish(record.Scope.ThreadID, Event{Type: "task.updated", Data: r.taskSnapshot(record)})

	r.mu.Lock()
	run := r.runs[record.Scope.RunID]
	shouldResume := run != nil && run.status == RunWaitingTask
	r.mu.Unlock()
	if shouldResume {
		if _, retryErr := r.Retry(record.Scope.RunID, RetryResume); retryErr != nil {
			return TaskSnapshot{}, retryErr
		}
	}
	return r.taskSnapshot(record), nil
}

func (r *Runtime) Stop(runID string) (RunSnapshot, error) {
	r.mu.Lock()
	run := r.runs[runID]
	if run == nil {
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	switch run.status {
	case RunQueued:
		run.stopRequested = true
		run.status = RunStopping
		run.updatedAt = r.now().UTC()
		if run.stop != nil {
			run.stop()
		}
	case RunRunning:
		run.stopRequested = true
		run.status = RunStopping
		run.updatedAt = r.now().UTC()
		if run.stop != nil {
			run.stop()
		}
	case RunYielded, RunWaitingTask:
		r.finishLocked(run, RunStopped, "", context.Canceled)
	case RunStopping, RunStopped:
	default:
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: run %s cannot be stopped from %s", ErrConflict, runID, run.status)
	}
	snapshot := r.runSnapshotLocked(run)
	_ = r.appendRun(run)
	r.mu.Unlock()
	r.publish(run.threadID, Event{Type: "run.updated", Data: snapshot})
	return snapshot, nil
}

func (r *Runtime) Retry(runID string, mode RetryMode) (RunSnapshot, error) {
	if mode != RetryResume && mode != RetryRestart {
		return RunSnapshot{}, fmt.Errorf("%w: retry mode must be resume or restart", ErrInvalid)
	}

	r.mu.Lock()
	run := r.runs[runID]
	if run == nil {
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	switch run.status {
	case RunYielded, RunWaitingTask, RunStopped, RunFailed, RunInterrupted:
	case RunCompleted:
		// A completed run has nothing to resume, but it can be restarted from
		// scratch (re-run as a new copy-on-write revision). This also lets a
		// parent restart cascade into already-completed children.
		if mode != RetryRestart {
			r.mu.Unlock()
			return RunSnapshot{}, fmt.Errorf("%w: completed run %s can only be restarted, not resumed", ErrConflict, runID)
		}
	default:
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: run %s cannot retry from %s", ErrConflict, runID, run.status)
	}
	thread := r.threads[run.threadID]
	if run.parentRunID == "" {
		// Root runs may only be retried if no later user-initiated run has arrived.
		// Child runs that were added to the same thread by delegation do not count.
		lastRootID := ""
		for i := len(thread.runIDs) - 1; i >= 0; i-- {
			if r.runs[thread.runIDs[i]] != nil && r.runs[thread.runIDs[i]].parentRunID == "" {
				lastRootID = thread.runIDs[i]
				break
			}
		}
		if lastRootID == "" || lastRootID != run.id {
			r.mu.Unlock()
			return RunSnapshot{}, fmt.Errorf("%w: only the latest thread run can be retried", ErrConflict)
		}
	}
	// Allow cascade retry of a child while its parent holds activeRunID.
	if thread.activeRunID != "" && thread.activeRunID != run.id &&
		(run.parentRunID == "" || thread.activeRunID != run.parentRunID) {
		r.mu.Unlock()
		return RunSnapshot{}, fmt.Errorf("%w: thread already has active run %s", ErrConflict, thread.activeRunID)
	}

	if mode == RetryRestart {
		// Hard restart: always fork from the beginning (the agent.input step),
		// giving the brain a completely fresh revision with no shared prefix.
		r.forkJournalLocked(run, 0, RetryRestart)
	} else if run.status == RunYielded || run.status == RunWaitingTask {
		// Resume from a park: no fork. The journal's open intent at the tail is
		// re-driven by replay under its original idempotency key; a resolved
		// task's stored authorization is injected by the task layer. When the
		// park was a delegated child's approval, enable cascade reconnection so
		// the re-executed delegation call reuses the now-finished child.
		if run.reconnectChildren {
			run.cascade = true
			run.cascadeMode = RetryResume
			run.cascadeCursor = childrenBefore(run.childSpawnOffsets, run.journal.Length())
		} else {
			run.cascade = false
		}
	} else {
		// Failed/stopped/interrupted resume: fork at the end of the journal and
		// let the brain continue, replaying every recorded outcome including
		// soft failures. A failed run only forks earlier when the brain
		// explicitly left a savepoint open: we fork right after the outermost
		// still-open sys.begin so its whole body re-executes live under the
		// bumped revision.
		forkOffset := run.journal.Length()
		if run.status == RunFailed {
			if off, ok := run.journal.outermostOpenBegin(); ok {
				forkOffset = off
			}
		}
		r.forkJournalLocked(run, forkOffset, RetryResume)
	}
	run.status = RunQueued
	run.attempt++
	run.answer = ""
	run.err = ""
	run.failure = nil
	run.stopRequested = false
	run.startedAt = nil
	run.completedAt = nil
	run.updatedAt = r.now().UTC()
	thread.activeRunID = run.id
	thread.updatedAt = run.updatedAt
	if err := r.appendRun(run); err != nil {
		r.mu.Unlock()
		return RunSnapshot{}, err
	}
	snapshot := r.runSnapshotLocked(run)
	r.mu.Unlock()

	r.publish(run.threadID, Event{Type: "run.updated", Data: snapshot})
	r.wg.Add(1)
	go r.execute(runID)
	return snapshot, nil
}

// forkJournalLocked re-forks run's journal at forkOffset as a new revision,
// records the retry mode for downstream cascade children, and positions the
// cascade cursor. Must be called with the runtime mutex held.
func (r *Runtime) forkJournalLocked(run *runState, forkOffset int, mode RetryMode) {
	parent := run.journal
	run.revision++
	run.forkOffset = forkOffset
	run.journal = newLogJournal(
		parent.log, parent.scope, parent.run, run.revision,
		parent.history, forkOffset,
		parent.now, parent.onAppend,
	)
	// Reuse the existing child subtree in spawn order (deep cascade resume).
	// Children whose delegation call is replayed from the shared prefix are
	// skipped; the cursor starts at the first child re-executed past the fork.
	run.cascade = true
	run.cascadeMode = mode
	run.cascadeCursor = childrenBefore(run.childSpawnOffsets, forkOffset)
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

func (r *Runtime) Subscribe(threadID string) (Event, <-chan Event, func(), error) {
	r.mu.Lock()
	thread := r.threads[threadID]
	if thread == nil {
		r.mu.Unlock()
		return Event{}, nil, nil, fmt.Errorf("%w: thread %s", ErrNotFound, threadID)
	}
	r.nextSubID++
	id := r.nextSubID
	ch := make(chan Event, r.eventSize)
	if r.subscribers[threadID] == nil {
		r.subscribers[threadID] = make(map[uint64]chan Event)
	}
	r.subscribers[threadID][id] = ch
	snapshot := Event{Type: "snapshot", Data: r.threadSnapshotLocked(thread)}
	r.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subscribers[threadID], id)
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
	for _, run := range r.runs {
		if run.stop != nil && (run.status == RunRunning || run.status == RunStopping || run.status == RunQueued) {
			stops = append(stops, run.stop)
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
