// Package agent is the runtime. It owns sessions and processes, runs each
// process's quanta on the capcompute processor, parks processes on durable
// tasks (approvals and timers), and retries them. All durable state is a fold
// of one append-only event stream per session: restore rebuilds memory by
// replaying each stream from the beginning.
//
// It owns no capability implementations, program bytes or concrete store: the
// application injects the dispatchers, the programs and the event log. The
// aurora package re-exports this package's types as the public surface.
//
// Where to read what:
//
//	runtime.go    Config, the Runtime, start and shutdown
//	sessions.go   the session API
//	processes.go  the process API: create, stop, retry
//	tasks.go      the task API, and the sweep that fires timers and wakes processes
//	executor.go   one quantum: run the guest, then record how it ended
//	recovery.go   what follows a guest abort or a failure
//	chain.go      the dispatcher chain a process runs under, and its layers:
//	              savepoint.go, world.go, lifecycle.go, progress.go, timer.go
//	journal.go    the per-process journal over the event log
//	state.go      in-memory session and process state, and how it is logged
//	restore.go    rebuilding that state from the log at boot
//	snapshots.go  the read projections the API returns (api.go)
//	taskstore.go  durable task records over the event log
//	programs.go   the compiled program registry
//	pool.go       the bounded pool quanta run on
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// Config wires a Runtime. The application supplies everything concrete:
// programs, capability drivers and the event log.
type Config struct {
	Dispatchers DispatcherProvider
	// Programs are compiled once, at boot. A process restored from an earlier
	// boot runs only if its program comes back with the same identity.
	Programs []ProgramData
	Log      eventlog.Log
	// Now is the clock (default time.Now).
	Now func() time.Time
	// TaskSecret derives the tokens that resolve tasks. Required.
	TaskSecret []byte
	// TaskTTL is how long an approval waits for a human (default 24h).
	TaskTTL time.Duration
	// MaxConcurrentProcesses bounds the quanta running at once (default 16).
	MaxConcurrentProcesses int
	// QuantumDeadline bounds one quantum's wall-clock time (default 30
	// minutes). A quantum runs until the guest yields or ends, driver calls
	// included, so this bounds a whole run between two yields. A quantum still
	// running at the deadline is stopped and the process is interrupted, not
	// failed: a retry resumes it by replay.
	QuantumDeadline time.Duration
}

// DispatcherProvider builds the grant table a process runs under, and checks
// the grant configs a manifest declares (manifest.ConfigValidator).
//
// It returns the table rather than a dispatcher: one table answers what
// routes, what the Validator admits and what flow policy applies, so the three
// cannot disagree.
type DispatcherProvider interface {
	ValidateConfig(syscall string, config json.RawMessage) error
	NewDispatcher(context.Context, durable.ProcessContext, manifest.Manifest) (*capability.Table, error)
}

type Runtime struct {
	// Wiring, fixed after NewRuntime.
	dispatchers     DispatcherProvider
	programs        programRegistry
	log             eventlog.Log
	now             func() time.Time
	taskSecret      []byte
	taskTTL         time.Duration
	quantumDeadline time.Duration

	// Shared services with their own locks.
	tasks  *eventTaskStore
	taints *monitor.Taints[durable.ProcessContext]
	pool   *pool

	// mu guards the session and process maps and closed. Every state change
	// happens under it, together with the event that records it.
	mu        sync.Mutex
	sessions  map[string]*sessionState
	processes map[string]*processState
	closed    bool

	// Shutdown. Close cancels baseCtx, which background work derives from, so an
	// in-flight driver call is interrupted rather than waited out. wg counts the
	// running execute goroutines.
	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

const (
	defaultMaxConcurrentProcesses = 16
	defaultTaskTTL                = 24 * time.Hour
	// defaultQuantumDeadline is long because a quantum includes its driver
	// calls: it must hold an agent run of many LLM and tool calls.
	defaultQuantumDeadline = 30 * time.Minute
)

// NewRuntime restores the runtime's state from the log, compiles the programs,
// and starts the task sweep.
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
		dispatchers:     config.Dispatchers,
		log:             config.Log,
		now:             config.Now,
		taskSecret:      append([]byte(nil), config.TaskSecret...),
		taskTTL:         config.TaskTTL,
		quantumDeadline: config.QuantumDeadline,
		taints:          monitor.NewTaints[durable.ProcessContext](),
		sessions:        make(map[string]*sessionState),
		processes:       make(map[string]*processState),
		baseCtx:         baseCtx,
		cancel:          cancel,
	}
	if runtime.now == nil {
		runtime.now = time.Now
	}
	if runtime.taskTTL <= 0 {
		runtime.taskTTL = defaultTaskTTL
	}
	if runtime.quantumDeadline <= 0 {
		runtime.quantumDeadline = defaultQuantumDeadline
	}
	runtime.tasks = newEventTaskStore(runtime.log, runtime.now)
	if err := runtime.restore(ctx); err != nil {
		return nil, fmt.Errorf("restore runtime: %w", err)
	}

	programs, err := newProgramRegistry(ctx, config.Programs)
	if err != nil {
		return nil, err
	}
	runtime.programs = programs
	maxConcurrent := config.MaxConcurrentProcesses
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentProcesses
	}
	runtime.pool = newPool(baseCtx, maxConcurrent)

	go runtime.sweepLoop()
	return runtime, nil
}

// Close stops every running quantum, waits for the processes to record how
// they ended (bounded by ctx), and releases the pool and the programs. An
// interrupted call leaves its intent open on the journal, so the next boot runs
// it again.
func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	// A process holds a stop function only while a quantum runs it.
	var stops []func()
	for _, proc := range r.processes {
		if proc.stop != nil {
			stops = append(stops, proc.stop)
		}
	}
	r.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
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

	r.pool.close()
	return errors.Join(r.programs.close(context.Background())...)
}
