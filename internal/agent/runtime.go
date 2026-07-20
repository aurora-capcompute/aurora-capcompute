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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"

	internalhost "github.com/aurora-capcompute/aurora-capcompute/internal/agent/host"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"

	extism "github.com/extism/go-sdk"
)

const (
	defaultMaxConcurrentProcesses = 16
	defaultMaxResidentProcesses   = 64
	// defaultProcessMemoryPages caps a guest's linear memory at 256 MiB by
	// default, so no single guest can walk the runtime toward the 4 GiB wasm
	// ceiling. defaultResumeQuantumTimeout stops a guest that spins without
	// yielding after two minutes of wall-clock. Both are host-safety floors the
	// distribution can raise, lower, or disable via Config.
	defaultProcessMemoryPages   = 4096
	defaultResumeQuantumTimeout = 2 * time.Minute
)

// resolveGuestLimits maps the Config knobs to the kernel's per-process limits:
// zero requests the safe default, a positive value is used verbatim, and a
// negative value disables the limit (0 to the kernel = unbounded). Keeping this
// pure makes the "bounded by default, never accidentally unbounded" policy
// directly testable without compiling a guest.
func resolveGuestLimits(memoryPages int, timeout time.Duration) (uint32, time.Duration) {
	var pages uint32
	switch {
	case memoryPages < 0:
		pages = 0 // explicitly unbounded
	case memoryPages == 0:
		pages = defaultProcessMemoryPages
	default:
		pages = uint32(memoryPages)
	}
	var quantum time.Duration
	switch {
	case timeout < 0:
		quantum = 0 // explicitly unbounded
	case timeout == 0:
		quantum = defaultResumeQuantumTimeout
	default:
		quantum = timeout
	}
	return pages, quantum
}

// reconcileGrants fails closed when the dispatcher provider advertises a
// capability the manifest did not grant. The grant set the kernel Validator
// enforces is the assembled chain's advertised capabilities (Stack.Grants, wired
// in the host factory to the chain's own Capabilities()), so a provider that
// publishes more than the manifest declared would silently widen a process's
// authority beyond its manifest — the confused-deputy gap. Reconciling the
// provider's leaf output against the manifest here makes the manifest the
// enforced source of truth rather than a trusted input.
//
// Only the provider's own leaf capabilities are checked: the runtime layers its
// protocol capabilities (sys.input/output/log/compensate/abort/now/random and
// the manifest-gated sys.spawn/sys.timer) on top afterwards, so they never
// appear in `advertised` and need no exception here. Under-advertising (a leaf
// grant the provider chose not to serve) is not a leak — the guest simply cannot
// call it — so only over-advertising fails the check.
func reconcileGrants(advertised []sys.Capability, manifest Manifest) error {
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
			ErrInvalid, strings.Join(leaked, ", "))
	}
	return nil
}

// openIntentPolicy turns the operator's non-idempotent capability set into a
// replay open-intent policy: an open intent (a journaled effect with no recorded
// completion, met on crash-resume) for one of those capabilities is surfaced as
// indeterminate rather than silently re-executed, giving at-most-once for
// effects a driver cannot dedup. Empty set → nil → retry everything (the
// framework default, safe under idempotency keys).
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
		return nil, fmt.Errorf("%w: dispatcher provider is required", ErrInvalid)
	}
	if config.Log == nil {
		return nil, fmt.Errorf("%w: event log is required", ErrInvalid)
	}
	if config.Leases == nil {
		return nil, fmt.Errorf("%w: leases are required", ErrInvalid)
	}
	if len(config.TaskSecret) == 0 {
		return nil, fmt.Errorf("%w: task secret is required", ErrInvalid)
	}
	programs, err := loadPrograms(ctx, config.Programs)
	if err != nil {
		return nil, err
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	runtime := &Runtime{
		baseCtx:         baseCtx,
		cancel:          cancel,
		images:          make(map[string]*capcompute.Program),
		programs:        programs,
		taints:          monitor.NewTaints[string](),
		log:             config.Log,
		leases:          config.Leases,
		tenantID:        strings.TrimSpace(config.TenantID),
		sessions:        make(map[string]*sessionState),
		processes:       make(map[string]*processState),
		subscribers:     make(map[string]map[uint64]chan Event),
		idSource:        config.IDSource,
		now:             config.Now,
		eventSize:       config.EventSize,
		taskSecret:      append([]byte(nil), config.TaskSecret...),
		taskTTL:         config.TaskTTL,
		instanceID:      strings.TrimSpace(config.InstanceID),
		leaseTTL:        config.LeaseTTL,
		maxAbortRetries: config.MaxAbortRetries,
		dispatchers:     config.Dispatchers,
	}
	runtime.memoryPages, runtime.resumeTimeout = resolveGuestLimits(config.ProcessMemoryPages, config.ResumeQuantumTimeout)
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
	if runtime.maxAbortRetries <= 0 {
		runtime.maxAbortRetries = defaultMaxAbortRetries
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
		Drivers:     runtime.processDrivers,
		Wrap:        runtime.wrapProtocol,
		NewJournal:  runtime.journalFor,
		Header:      runtime.headerFor,
		Taints:      runtime.taints,
		OpenIntents: openIntentPolicy(config.NonIdempotentSyscalls),
		Now:         runtime.now,
		Tasks:       runtime.tasks,
		TaskSecret:  runtime.taskSecret,
		TaskTTL:     runtime.taskTTL,
		TaskScope:   ProcessContext.taskScope,
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
		image, err := runtime.compileProgram(ctx, artifact.ID, source.Wasm)
		if err != nil {
			for _, opened := range runtime.images {
				_ = opened.Close(context.Background())
			}
			return nil, err
		}
		runtime.images[artifact.ID] = image
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
	if err := reconcileGrants(base.Capabilities(), manifest); err != nil {
		return nil, err
	}
	if grant, ok := manifest.grant(TimerSyscall); ok {
		// sys.timer is the runtime's own, served below the task layer so its
		// yield becomes a durable timer task.
		base = newTimerDispatcher(base, grant)
	}
	return newProgressDispatcher(base, r.publish, cred.SessionID, cred.ProcessID), nil
}

// wrapProtocol stacks the runtime's protocol layers above the task layer:
// the delegation router (above tasks, so a delegated child's park suspends
// the parent transparently instead of becoming a human-approvable task), then
// the agent lifecycle outermost — its sys.input payload advertises every
// capability beneath it, spawn grants included.
func (r *Runtime) wrapProtocol(cred ProcessContext, next sys.Dispatcher[ProcessContext]) (sys.Dispatcher[ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	var manifest Manifest
	var input string
	var inputLabels []string
	var history []HistoryMessage
	var attempt int
	if proc != nil {
		manifest = cloneManifest(proc.manifest)
		input = proc.input
		// The input's provenance (a delegated child's parent-taint snapshot)
		// rides sys.input regardless of history sharing: history:false isolates
		// the conversation, not the flow policy.
		inputLabels = append([]string(nil), proc.inputLabels...)
		// A child spawned with history:false serves no session history on its
		// sys.input — it sees only its own input. The capability menu is gated
		// separately, by hidden grants in the child's own manifest.
		if !proc.hideHistory {
			history = append([]HistoryMessage(nil), proc.history...)
		}
		attempt = proc.attempt
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", ErrNotFound, cred.ProcessID)
	}
	if grant, ok := manifest.grant(SpawnSyscall); ok {
		next = newSpawnRouter(next, grant, r)
	}
	return newLifecycleDispatcher(next, input, inputLabels, history, manifest, attempt, r.programs.answerValidator(manifest.Program)), nil
}

// programBinding checks that the process's program is loaded with the exact
// identity the process was created from — the same wasm bytes and the same
// interface manifest. A process is an audit target: its journal, effects, and
// conclusions attest to one program under one contract, so it never resumes or
// restarts under changed code or a changed interface. The new program runs in
// new processes, bound by their own manifest.
func (r *Runtime) programBinding(proc *processState) error {
	artifact, err := r.programs.Resolve(proc.manifest.Program)
	if err != nil {
		return fmt.Errorf("program %q is not loaded", proc.manifest.Program)
	}
	if artifact.Digest != proc.programDigest {
		return fmt.Errorf(
			"program %q changed (loaded %s, process bound to %s): a process is immutable — its code and interface are fixed; spawn a new process from the new program, or kill this one to settle its effects",
			proc.manifest.Program, shortDigest(artifact.Digest), shortDigest(proc.programDigest))
	}
	return nil
}

func shortDigest(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
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
// tape refuses to replay a journal whose recorded header differs — the
// versioned-replay law.
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
// preparing a SetPrograms swap. The wasm engine gets the bytes' own sha256 for
// integrity (not the program identity, which also covers the interface).
func (r *Runtime) compileProgram(ctx context.Context, id string, wasm []byte) (*capcompute.Program, error) {
	image, err := capcompute.NewProgram(ctx, capcompute.Config{
		Image: extism.Manifest{
			Wasm: []extism.Wasm{extism.WasmData{Data: wasm, Hash: digestOf(wasm), Name: id}},
		},
		PluginConfig:   extism.PluginConfig{EnableWasi: true},
		MaxMemoryPages: r.memoryPages,
	})
	if err != nil {
		return nil, fmt.Errorf("compile program %q: %w", id, err)
	}
	return image, nil
}

// SetPrograms declaratively reconciles the registered programs to the given set:
// programs absent from the set are removed, new or changed programs are
// (re)compiled, and unchanged programs are left running. A program counts as
// changed when either its wasm bytes or its interface manifest differ (identity
// covers both). It is safe to call at any time; the control plane uses it to
// hot-load programs from Program CRDs without a restart. Compilation happens
// outside the runtime mutex so dispatch is only briefly paused for the swap. If
// any program fails to compile, no change is applied. Processes are immutably
// bound to the (name, identity) they were created from: replacing or removing an
// artifact — or editing its interface — strands its processes: retries are
// refused and any execution attempt fails, while they remain auditable and can
// be killed to settle their effects. The new artifact runs in new processes.
func (r *Runtime) SetPrograms(ctx context.Context, sources []ProgramSource) error {
	current := r.programs.digests()
	desired := make(map[string]struct{}, len(sources))

	// Load (describe + schema compile) and compile additions/replacements
	// outside the lock; fail atomically.
	type compiled struct {
		record programRecord
		image  *capcompute.Program
	}
	var fresh []compiled
	shutdownFresh := func() {
		for _, c := range fresh {
			_ = c.image.Close(context.Background())
		}
	}
	for _, src := range sources {
		id := strings.TrimSpace(src.ID)
		if id == "" || len(src.Wasm) == 0 {
			return fmt.Errorf("%w: program id and wasm bytes are required", ErrInvalid)
		}
		if _, dup := desired[id]; dup {
			return fmt.Errorf("%w: duplicate program %q", ErrInvalid, id)
		}
		desired[id] = struct{}{}
		if cur, ok := current[id]; ok && cur == programIdentity(src.Wasm, src.Interface) {
			continue // unchanged: same bytes and same interface
		}
		record, err := loadProgram(id, src.Wasm, src.Interface)
		if err != nil {
			shutdownFresh()
			return err
		}
		image, err := r.compileProgram(ctx, id, record.source.Wasm)
		if err != nil {
			shutdownFresh()
			return err
		}
		fresh = append(fresh, compiled{record: record, image: image})
	}

	// Swap under the runtime mutex (which guards r.kernels), collecting the
	// kernels that are being replaced or removed so they can be shut down
	// after the lock is released.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		shutdownFresh()
		return fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	var retired []*capcompute.Program
	for _, c := range fresh {
		id := c.record.artifact.ID
		if old := r.images[id]; old != nil {
			retired = append(retired, old)
		}
		r.images[id] = c.image
		r.programs.put(c.record)
	}
	for id := range current {
		if _, keep := desired[id]; keep {
			continue
		}
		if old := r.images[id]; old != nil {
			retired = append(retired, old)
		}
		delete(r.images, id)
		r.programs.remove(id)
	}
	r.mu.Unlock()

	for _, old := range retired {
		_ = old.Close(context.Background())
	}
	return nil
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
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	if err := r.checkSessionNameFreeLocked(name, ""); err != nil {
		return SessionSnapshot{}, err
	}
	session := &sessionState{id: id, name: name, title: defaultSessionTitle, createdAt: now, updatedAt: now, tags: cloneTags(tags)}
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
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		return SessionSnapshot{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
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
			return fmt.Errorf("%w: a session named %q already exists", ErrConflict, name)
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

func (r *Runtime) CreateProcess(sessionID string, input string, manifest Manifest) (ProcessSnapshot, error) {
	if input == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: input is required", ErrInvalid)
	}
	if strings.TrimSpace(manifest.Program) == "" {
		manifest.Program = r.programs.DefaultID()
	}
	manifest, err := ValidateManifest(manifest, r.dispatchers)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	// A root that opts out of capability sharing keeps its grants off its own
	// sys.input menu (it still holds them) — the same effect a spawned child gets
	// through buildChildManifest. ValidateManifest returned a clone, so this is
	// local. History is applied below via hideHistory.
	if !manifest.sharesCapabilities() {
		for i := range manifest.Syscalls {
			manifest.Syscalls[i].Hidden = true
		}
	}
	program, err := r.programs.Resolve(manifest.Program)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	if err := r.programs.ValidateInput(manifest.Program, input); err != nil {
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
		input:         input,
		history:       append([]HistoryMessage(nil), session.history...),
		status:        ProcessQueued,
		attempt:       1,
		createdAt:     now,
		updatedAt:     now,
		manifest:      manifest,
		revision:      1,
		programDigest: program.Digest,
		// A root manifest with history:false opts out of session-history sharing —
		// each run sees only its own input and inherits no cross-run taint. Reuses
		// the hideHistory delivery gate (and its persistence).
		hideHistory: !manifest.sharesHistory(),
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	r.processes[processID] = proc
	session.processIDs = append(session.processIDs, processID)
	if len(session.processIDs) == 1 {
		session.title = sessionTitle(input)
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
	// Enroll in the wait group before releasing r.mu: Close sets r.closed under
	// r.mu and then waits, so an Add that landed after the closed-check but after
	// the unlock could race a returning Wait and panic. Under the lock it cannot.
	r.wg.Add(1)
	r.mu.Unlock()

	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
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
	case ProcessQueued, ProcessRunning:
		proc.stopRequested = true
		proc.status = ProcessStopping
		proc.updatedAt = r.now().UTC()
		if proc.stop != nil {
			proc.stop()
		}
	case ProcessYielded, ProcessWaitingTask:
		_, started, unsettled := proc.unsettledRollback()
		_, open := proc.journal.outermostOpenBegin()
		switch {
		case unsettled:
			// A rollback is parked on its pending task; walking away would
			// leave external state undefined. Deny the task instead — that
			// fails the rollback with the report — or resolve it to finish.
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf(
				"%w: process %s is mid-rollback; resolve or deny its pending task instead", ErrConflict, processID)
		case !started && open:
			// Parked inside an open section: roll it back before stopping — a
			// stop is an abandonment without a retry. The settle dispatches
			// drivers, so it runs off-lock; Stopping guards concurrent retries.
			return r.spawnSettleLocked(proc, ProcessStopping, func() {
				r.stopProcess(processID, context.Canceled)
			}), nil
		default:
			// No open section — or a settled rollback, which already ran (the
			// park is its retry timer, now moot): stop plainly.
			r.finishLocked(proc, ProcessStopped, "", context.Canceled)
		}
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

	state, started, unsettled := proc.unsettledRollback()
	if unsettled {
		// A rollback is in flight — an abandonment not yet concluded, or a
		// guest abort whose settlement a crash or a failed compensation cut
		// short. Resume the rollback — never the guest: replaying past a
		// rolled-back tail is refused by the tape, and restarting would walk
		// away from live effects. Running marks the settlement in flight and
		// refuses concurrent retries.
		if mode == RetryRestart {
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf("%w: process %s has an unfinished rollback; resume it first", ErrConflict, processID)
		}
		if proc.abandoning != abandonFailure {
			proc.err = ""
		}
		return r.spawnSettleLocked(proc, ProcessRunning, func() {
			r.settleRollback(processID)
		}), nil
	}

	// Every branch below relaunches the guest; the settlement above stays
	// available regardless of the binding. A process is an audit target: it
	// never resumes or restarts under different program bytes.
	if err := r.programBinding(proc); err != nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: %v", ErrConflict, err)
	}

	if mode == RetryRestart {
		// Hard restart: fork from the beginning, giving the program a
		// completely fresh revision with no shared prefix. Restarting is
		// abandoning the current revision, so everything it registered and
		// never committed rolls back first (revision law 2) — the settle runs
		// off-lock and re-runs the process from scratch when it completes.
		// A completed process committed its whole-process zone by finishing:
		// nothing is uncommitted, so it restarts directly.
		if proc.status != ProcessCompleted {
			proc.err = ""
			return r.spawnSettleLocked(proc, ProcessRunning, func() {
				r.restartProcess(processID)
			}), nil
		}
		r.forkJournalLocked(proc, 0, RetryRestart)
	} else if started || proc.abandoning != "" {
		// A settled rollback — the retry timer fired, or a human retried a
		// failed/stopped process whose scope was rolled back: the abandoned
		// attempt stays in the log; the scope re-runs fresh from its start,
		// over compensated state. The standing abandonment stamp licenses the
		// fork even when the scope had nothing registered and the rollback
		// left no journal trace: the revision hit its wall and can never run
		// again, so a retry must re-mint it, not replay it.
		r.forkJournalLocked(proc, state.ScopeStart, RetryResume)
	} else if proc.status == ProcessYielded || proc.status == ProcessWaitingTask {
		// Resume from a park: no fork. The journal's open intent at the tail is
		// re-driven by replay under its original idempotency key; a resolved
		// task's stored authorization is injected by the task layer. When the
		// park was a delegated child's approval, enable cascade reconnection so
		// the re-executed delegation call reuses the now-finished child.
		if proc.reconnectChildren {
			proc.resumeCascade()
		} else {
			proc.cascade = false
		}
	} else {
		// Failed/stopped/interrupted resume: same revision, no fork. A resume
		// continues the attempt — replay serves everything recorded (an open
		// intent at the tail re-drives under its original key) and the guest
		// proceeds mid-flight, so an interruption never touches effects and
		// never opens a new key space. Only a rollback mints a new revision.
		// Reuse the whole child subtree: every delegation call is served or
		// re-driven from the recorded prefix.
		proc.resumeCascade()
	}
	return r.relaunchLocked(proc)
}

// spawnSettleLocked launches a rollback settlement off-lock: it marks the
// process's transition, makes it durable and visible, then runs settle on the
// runtime's wait group. The status it stamps (Running for a resumed
// settlement, Stopping for a stop's rollback) is also the concurrency guard —
// Retry and Stop refuse both. Called with r.mu held; unlocks it.
func (r *Runtime) spawnSettleLocked(proc *processState, status ProcessStatus, settle func()) ProcessSnapshot {
	// Don't enroll a settlement goroutine once shutdown has begun (same WaitGroup
	// race as relaunchLocked). The open compensation intent stays on the journal,
	// so a restart resumes the rollback — nothing is lost by deferring it.
	if r.closed {
		snapshot := r.processSnapshotLocked(proc)
		r.mu.Unlock()
		return snapshot
	}
	proc.status = status
	proc.updatedAt = r.now().UTC()
	_ = r.appendProcess(proc)
	snapshot := r.processSnapshotLocked(proc)
	sessionID := proc.sessionID
	r.wg.Add(1) // enroll before releasing r.mu (see CreateProcess) so Close cannot race Wait
	r.mu.Unlock()
	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	go func() {
		defer r.wg.Done()
		settle()
	}()
	return snapshot
}

// relaunchLocked resets a process for a fresh quantum and starts it: queued,
// attempt bumped, terminal fields cleared, its session made active, and the
// transition appended and published. Called with r.mu held; unlocks it.
func (r *Runtime) relaunchLocked(proc *processState) (ProcessSnapshot, error) {
	// Refuse to enroll a new quantum once shutdown has begun: Close sets closed
	// under r.mu then waits on r.wg, so a Retry/ResolveTask/child-finish racing
	// Close must not wg.Add after the counter may already be draining (a reuse of
	// the WaitGroup would panic) — mirrors CreateProcess.
	if r.closed {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	proc.status = ProcessQueued
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
	sessionID, processID := proc.sessionID, proc.id
	r.wg.Add(1) // enroll before releasing r.mu (see CreateProcess) so Close cannot race Wait
	r.mu.Unlock()

	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	go r.execute(processID)
	return snapshot, nil
}

// forkJournalLocked re-forks process's journal at forkOffset as a new revision,
// records the retry mode for downstream cascade children, and positions the
// cascade cursor. Forks happen only where an attempt boundary is real — a
// settled rollback re-running its section, or an explicit restart — never for
// a plain resume, which continues the same revision. Must be called with the
// runtime mutex held.
func (r *Runtime) forkJournalLocked(proc *processState, forkOffset int, mode RetryMode) {
	parent := proc.journal
	// The outgoing revision can never run again — this fork is its abandonment —
	// so release its taint. Otherwise the shared taint map accumulates one dead
	// entry per abort-retry/restart fork for the runtime's lifetime; the new
	// revision rebuilds its own taint by replaying the shared prefix's labels.
	r.taints.ForgetProcess(processPID(proc.id, proc.revision))
	proc.revision++
	proc.forkOffset = forkOffset
	proc.lastFailureLength = 0
	proc.abandoning = "" // the fork is the abandonment's conclusion
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

// resumeCascade arms cascade reconnection for a resume at the same revision:
// the delegation router reuses the recorded children in spawn order, the
// cursor starting past those whose delegation call replay serves from the
// journal. Called with the runtime mutex held.
func (p *processState) resumeCascade() {
	p.cascade = true
	p.cascadeMode = RetryResume
	p.cascadeCursor = childrenBefore(p.childSpawnOffsets, p.journal.Length())
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
	// Cancel long-running background work (rollback compensations run under
	// baseCtx) so an in-flight driver call is interrupted rather than waited out
	// to its own timeout — bounding shutdown latency. A cancelled compensation
	// leaves its intent open on the journal, so a restart resumes the rollback.
	r.cancel()

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
	for _, image := range r.images {
		closeErrors = append(closeErrors, image.Close(context.Background()))
	}
	return errors.Join(closeErrors...)
}
