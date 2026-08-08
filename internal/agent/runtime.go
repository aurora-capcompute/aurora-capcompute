// Package agent is the runtime: it owns session and process lifecycle, the
// scheduler-driven quanta that resume Wasm programs on the capcompute processor,
// durable approval tasks, retries, event subscriptions, and the read
// projections (snapshots, journal, call graph) the public API exposes. All
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
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"
	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	internalhost "github.com/aurora-capcompute/aurora-capcompute/internal/agent/host"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
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
func reconcileGrants(advertised []sys.Capability, manifest manifest.Manifest) error {
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
		return nil, fmt.Errorf("%w: dispatcher provider is required", errs.Invalid)
	}
	if config.Log == nil {
		return nil, fmt.Errorf("%w: event log is required", errs.Invalid)
	}
	if config.Leases == nil {
		return nil, fmt.Errorf("%w: leases are required", errs.Invalid)
	}
	if len(config.TaskSecret) == 0 {
		return nil, fmt.Errorf("%w: task secret is required", errs.Invalid)
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	var err error
	runtime := &Runtime{
		baseCtx:         baseCtx,
		cancel:          cancel,
		programs:        direct.NewRegistry(),
		taints:          monitor.NewTaints[processKey](),
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
	runtime.memoryPages, runtime.quantumCeiling = resolveGuestLimits(config.ProcessMemoryPages, config.MaxQuantumDuration)
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

	runtime.factory, err = internalhost.New(internalhost.Config[processKey, ProcessContext]{
		Environment: runtime,
		Taints:      runtime.taints,
		Tasks:       runtime.tasks,
		TaskSecret:  runtime.taskSecret,
		TaskTTL:     runtime.taskTTL,
		Wrap:        runtime.wrapProtocol,
		OpenIntents: openIntentPolicy(config.NonIdempotentSyscalls),
		Now:         runtime.now,
		OnTaskCreated: func(record task.Record) {
			runtime.publish(record.Scope.SessionID, Event{
				Type: "task.created",
				Data: runtime.taskSnapshot(record),
			})
		},
	})
	if err != nil {
		return nil, err
	}

	maxConcurrent := config.MaxConcurrentProcesses
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentProcesses
	}
	runtime.scheduler, err = sched.New(sched.Config[processKey, *capcompute.Process[ProcessContext]]{
		Activator: processActivator{runtime: runtime},
		Machine:   processMachine{},
		// Quanta hang off the runtime's own lifetime rather than a root the queue
		// invents, so shutdown has one tree to cancel and not two.
		Parent:        baseCtx,
		MaxConcurrent: maxConcurrent,
	})
	if err != nil {
		return nil, err
	}

	return runtime, nil
}

// Drivers builds the driver chain below the task layer for one process: the
// application's capability dispatcher wrapped with progress reporting.
func (r *Runtime) Drivers(resolveCtx context.Context, cred ProcessContext) (sys.Dispatcher[ProcessContext], error) {
	r.mu.Lock()
	proc := r.processes[cred.ProcessID]
	var spec manifest.Manifest
	if proc != nil {
		spec = proc.manifest.Clone()
	}
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", errs.NotFound, cred.ProcessID)
	}
	base, err := r.dispatchers.NewDispatcher(resolveCtx, cred, spec)
	if err != nil {
		return nil, err
	}
	if err := reconcileGrants(base.Capabilities(), spec); err != nil {
		return nil, err
	}
	if grant, ok := spec.Grant(manifest.TimerSyscall); ok {
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
	var spec manifest.Manifest
	var input string
	var inputLabels []string
	var history []HistoryMessage
	var attempt int
	if proc != nil {
		spec = proc.manifest.Clone()
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
		return nil, fmt.Errorf("%w: process %s", errs.NotFound, cred.ProcessID)
	}
	if grant, ok := spec.Grant(manifest.SpawnSyscall); ok {
		next = newSpawnRouter(next, grant, r)
	}
	return newLifecycleDispatcher(
		next,
		input,
		inputLabels,
		history,
		spec,
		attempt,
		func(answer json.RawMessage) error {
			a, err := r.programs.Resolve(spec.Program)
			if err != nil {
				return err
			}
			if err = a.Output.validateJSON(answer); err != nil {
				return err
			}
			return nil
		},
	), nil
}

func (r *Runtime) programBinding(proc *processState) error {
	artifact, err := r.programs.Resolve(proc.manifest.Program)
	if err != nil {
		return fmt.Errorf("program %q is not loaded", proc.manifest.Program)
	}
	if artifact.Digest != proc.programDigest {
		return fmt.Errorf(
			"program %q changed (loaded %s, process bound to %s): a process is immutable — its code and interface are fixed; spawn a new process from the new program, or kill this one to settle its effects",
			proc.manifest.Program, artifact.Digest, proc.programDigest)
	}
	return nil
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
func (r *Runtime) TaskScope(cred ProcessContext) task.Scope { return cred.taskScope() }

// Header is the journal writer identity for one process revision: the
// syscall ABI, the program digest as the program, and the process id. The
// tape refuses to replay a journal whose recorded header differs — the
// versioned-replay law.
func (r *Runtime) Header(cred ProcessContext) journaled.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	program := ""
	if proc := r.processes[cred.ProcessID]; proc != nil {
		program = proc.programDigest
	}
	return journaled.Header{ABI: sys.ABIVersion, Program: program, Process: cred.ProcessID}
}

// AddProgram registers one program and compiles its wasm. The id is the app's to
// choose and it must be free: a program is never replaced in place, because
// processes are immutably bound to the (name, identity) they were created from.
// Re-adding the byte-identical program under the same id is a no-op, so a control
// plane can re-assert its desired set on a ticker without disturbing anything; the
// same id with a different identity is refused (errs.Conflict) and the caller removes
// the old program first, which settles the processes bound to it. Compilation
// happens outside the runtime mutex, so dispatch is only briefly paused for the
// swap.
func (r *Runtime) AddProgram(ctx context.Context, data direct.Data) error {
	// Preparing the program is the cheap half — interface normalization and
	// schema compilation — and it pins the digest, so an unchanged program is
	// settled without compiling any wasm.
	artifact, err := direct.Load(data)
	if err != nil {
		return err
	}
	if existing, err := r.programs.Resolve(artifact.ID); err == nil && existing.Digest == artifact.Digest {
		return nil
	}
	image, err := r.compileProgram(ctx, artifact.ID, data.SourceCode)
	if err != nil {
		return err
	}
	artifact.Image = image
	added, err := r.programs.Add(artifact)
	if err != nil || !added {
		_ = image.Close(context.Background())
		return err
	}
	// A Close that raced this registration has already drained the registry, so
	// check after publishing and undo: otherwise the image this call compiled
	// would stay open with nothing left to close it.
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		r.programs.Remove(artifact.ID)
		_ = image.Close(context.Background())
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
	removed, ok := r.programs.Remove(id)
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
	if image := removed.Image; image != nil {
		_ = image.Close(context.Background())
	}
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

func (r *Runtime) Programs() []direct.artifact {
	return r.programs.List()
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
// it delegates inside that quantum. Zero takes the host default; anything above
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
	// A root that opts out of capability sharing keeps its grants off its own
	// sys.input menu (it still holds them) — the same effect a spawned child gets
	// through buildChildManifest. manifest.Validate returned a clone, so this is
	// local. History is applied below via hideHistory.
	if !spec.SharesCapabilities() {
		for i := range spec.Syscalls {
			spec.Syscalls[i].Hidden = true
		}
	}
	artifact, err := r.programs.Resolve(spec.Program)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	if err := r.programs.ValidateInput(spec.Program, input); err != nil {
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
		id:            processID,
		sessionID:     sessionID,
		input:         input,
		history:       append([]HistoryMessage(nil), session.history...),
		status:        durable.ProcessQueued,
		attempt:       1,
		createdAt:     now,
		updatedAt:     now,
		manifest:      spec,
		revision:      1,
		programDigest: artifact.Digest,
		deadline:      r.clampDeadline(deadline),
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

	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	go r.execute(context.Background(), processID)
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

// Journal returns the process's current-revision journal as per-syscall entries:
// each intent folded together with its completion, open intents rendered as
// in-flight. Entry positions are intent-record positions in the hash-chained
// journal.
func (r *Runtime) Journal(processID string) ([]JournalEntry, error) {
	r.mu.Lock()
	proc := r.processes[processID]
	r.mu.Unlock()
	if proc == nil {
		return nil, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	if proc.journal == nil {
		return nil, fmt.Errorf("%w: process %s has no readable journal", errs.NotFound, processID)
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
		return nil, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	if proc.journal == nil {
		return nil, fmt.Errorf("%w: process %s has no readable journal", errs.NotFound, processID)
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
		return nil, fmt.Errorf("%w: process %s", errs.NotFound, processID)
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
		return TaskSnapshot{}, fmt.Errorf("%w: unsupported task decision %q", errs.Invalid, resolution.Decision)
	}
	if resolution.Decision == task.StateCompleted && !json.Valid(resolution.Data) {
		return TaskSnapshot{}, fmt.Errorf("%w: completed task data must be valid JSON", errs.Invalid)
	}
	acquired, err := r.leases.Acquire(
		context.Background(), r.tenantID, "task", taskID,
		r.instanceID, r.now().UTC(), time.Minute,
	)
	if err != nil {
		return TaskSnapshot{}, err
	}
	if !acquired {
		return TaskSnapshot{}, fmt.Errorf("%w: task is being resolved", errs.Conflict)
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
	shouldResume := proc != nil && proc.status == durable.ProcessWaitingTask
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
		_, started, unsettled := proc.unsettledRollback()
		_, open := proc.journal.outermostOpenBegin()
		switch {
		case unsettled:
			// A rollback is parked on its pending task; walking away would
			// leave external state undefined. Deny the task instead — that
			// fails the rollback with the report — or resolve it to finish.
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf(
				"%w: process %s is mid-rollback; resolve or deny its pending task instead", errs.Conflict, processID)
		case !started && open:
			// Parked inside an open section: roll it back before stopping — a
			// stop is an abandonment without a retry. The settle dispatches
			// drivers, so it runs off-lock; Stopping guards concurrent retries.
			return r.spawnSettleLocked(proc, durable.ProcessStopping, func() {
				r.stopProcess(processID, context.Canceled)
			}), nil
		default:
			// No open section — or a settled rollback, which already ran (the
			// park is its retry timer, now moot): stop plainly.
			r.finishLocked(proc, durable.ProcessStopped, "", context.Canceled)
		}
	case durable.ProcessStopping, durable.ProcessStopped:
	default:
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot be stopped from %s", errs.Conflict, processID, proc.status)
	}
	snapshot := r.processSnapshotLocked(proc)
	_ = r.appendProcess(proc)
	r.mu.Unlock()
	r.publish(proc.sessionID, Event{Type: "process.updated", Data: snapshot})
	return snapshot, nil
}

// Retry re-drives a process on a fresh quantum of its own.
func (r *Runtime) Retry(processID string, mode RetryMode) (ProcessSnapshot, error) {
	return r.retryUnder(context.Background(), processID, mode)
}

// retryUnder is Retry with the quantum context of a parent that is delegating to
// quantum, and the child must inherit its remaining budget rather than start a
// this process: the cascade path re-drives a child from inside the parent's
// fresh one. A host-initiated retry passes context.Background() and the process
// falls back to its own deadline.
func (r *Runtime) retryUnder(ctx context.Context, processID string, mode RetryMode) (ProcessSnapshot, error) {
	if mode != RetryResume && mode != RetryRestart {
		return ProcessSnapshot{}, fmt.Errorf("%w: retry mode must be resume or restart", errs.Invalid)
	}

	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	switch proc.status {
	case durable.ProcessYielded, durable.ProcessWaitingTask, durable.ProcessStopped, durable.ProcessFailed, durable.ProcessInterrupted:
	case durable.ProcessCompleted:
		// A completed process has nothing to resume, but it can be restarted from
		// scratch (re-run as a new copy-on-write revision). This also lets a
		// parent restart cascade into already-completed children.
		if mode != RetryRestart {
			r.mu.Unlock()
			return ProcessSnapshot{}, fmt.Errorf("%w: completed process %s can only be restarted, not resumed", errs.Conflict, processID)
		}
	default:
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: process %s cannot retry from %s", errs.Conflict, processID, proc.status)
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
			return ProcessSnapshot{}, fmt.Errorf("%w: only the latest session process can be retried", errs.Conflict)
		}
	}
	// Allow cascade retry of a child while its parent holds activeProcessID.
	if session.activeProcessID != "" && session.activeProcessID != proc.id &&
		(proc.parentProcessID == "" || session.activeProcessID != proc.parentProcessID) {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", errs.Conflict, session.activeProcessID)
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
			return ProcessSnapshot{}, fmt.Errorf("%w: process %s has an unfinished rollback; resume it first", errs.Conflict, processID)
		}
		if proc.abandoning != abandonFailure {
			proc.err = ""
		}
		return r.spawnSettleLocked(proc, durable.ProcessRunning, func() {
			r.settleRollback(processID)
		}), nil
	}

	// Every branch below relaunches the guest; the settlement above stays
	// available regardless of the binding. A process is an audit target: it
	// never resumes or restarts under different program bytes.
	if err := r.programBinding(proc); err != nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: %v", errs.Conflict, err)
	}

	if mode == RetryRestart {
		// Hard restart: fork from the beginning, giving the program a
		// completely fresh revision with no shared prefix. Restarting is
		// abandoning the current revision, so everything it registered and
		// never committed rolls back first (revision law 2) — the settle runs
		// off-lock and re-runs the process from scratch when it completes.
		// A completed process committed its whole-process zone by finishing:
		// nothing is uncommitted, so it restarts directly.
		if proc.status != durable.ProcessCompleted {
			proc.err = ""
			return r.spawnSettleLocked(proc, durable.ProcessRunning, func() {
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
	} else if proc.status == durable.ProcessYielded || proc.status == durable.ProcessWaitingTask {
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
	return r.relaunchLocked(context.Background(), proc)
}

// spawnSettleLocked launches a rollback settlement off-lock: it marks the
// process's transition, makes it durable and visible, then runs settle on the
// runtime's wait group. The status it stamps (Running for a resumed
// settlement, Stopping for a stop's rollback) is also the concurrency guard —
// Retry and Stop refuse both. Called with r.mu held; unlocks it.
func (r *Runtime) spawnSettleLocked(proc *processState, status durable.ProcessStatus, settle func()) ProcessSnapshot {
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
	r.enrollLocked()
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
func (r *Runtime) relaunchLocked(ctx context.Context, proc *processState) (ProcessSnapshot, error) {
	// Refuse to enroll a new quantum once shutdown has begun: Close sets closed
	// under r.mu then waits on r.wg, so a Retry/ResolveTask/child-finish racing
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
	sessionID, processID := proc.sessionID, proc.id
	r.enrollLocked()
	r.mu.Unlock()

	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	go r.execute(ctx, processID)
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
	r.taints.ForgetProcess(proc.key())
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
		return Event{}, nil, nil, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
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
		if proc.stop != nil && (proc.status == durable.ProcessRunning || proc.status == durable.ProcessStopping || proc.status == durable.ProcessQueued) {
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
	for _, artifact := range r.programs.Close() {
		image := artifact.Image
		if image == nil {
			continue
		}
		closeErrors = append(closeErrors, image.Close(context.Background()))
	}
	return errors.Join(closeErrors...)
}
