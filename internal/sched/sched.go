// Package sched is a bounded run queue: it decides *when* a submitted process
// runs, and nothing else. An Activator decides *what* runs (for a durable
// process, journal-replay wiring) and a Machine decides *how*.
//
// Those two interfaces are the whole seam, and they point in opposite
// directions: Activator up at the application, which alone can rebuild a
// process from its journal; Machine down at the execution hardware. The queue
// itself is hardware-agnostic — an instance is opaque to it between Activate
// and Release — so nothing here knows what a guest is.
//
// It is deliberately not a scheduler in the fair-share sense: no priorities, no
// quotas, no owners. Submissions run first-come-first-served, bounded by
// MaxConcurrent, which exists to cap live instances rather than to apportion
// them.
//
// There is no residency. Every quantum activates a fresh instance and releases
// it when the quantum ends, whatever the outcome. Keeping an instance warm
// across quanta would be the one piece of process state living outside the
// journal — guest globals and allocator state would cross a boundary that
// syscalls are supposed to be the only path through — so the queue does not
// offer it. The cost is one instantiation per quantum; the gain is that a cold
// start is the only start, and there is no warm-vs-cold behaviour to reason
// about.
package sched

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrClosed           = errors.New("sched: scheduler is closed")
	ErrAlreadyScheduled = errors.New("sched: process is already scheduled")
	ErrStopped          = errors.New("sched: stopped before running")
)

// Status is how one quantum ended.
type Status string

const (
	// Completed: the instance ran to the end of its entrypoint.
	Completed Status = "completed"
	// Yielded: the instance parked awaiting something outside itself.
	Yielded Status = "yielded"
	// Stopped: the quantum was cancelled or ran out of wall-clock time.
	Stopped Status = "stopped"
	// Failed: the quantum could not run, or the instance faulted.
	Failed Status = "failed"
)

// Result is one quantum's outcome.
type Result struct {
	Status Status
	Err    error
}

// Activator materialises the instance a pid names. Only the application can do
// this: for a durable process it is journal-replay wiring, which lives above
// the hardware.
//
// Activate runs when the quantum starts, not when it was submitted, and that
// ordering is load-bearing: a process whose program is withdrawn while its
// submission sits in the queue must fail activation and never run.
type Activator[ID comparable, T any] interface {
	Activate(ctx context.Context, pid ID) (T, error)
}

// Machine is the execution hardware: it gives an activated instance one quantum
// and disposes of it afterwards.
type Machine[T any] interface {
	// Resume runs the instance for one quantum and reports how it ended. An
	// error means the quantum could not start at all; a quantum that started and
	// went wrong is a Failed Result, not an error.
	Resume(ctx context.Context, instance T) (Result, error)
	// Release disposes of the instance once its quantum has ended. Called
	// exactly once per successful Activate, whatever the outcome.
	Release(instance T)
}

// Config wires a Scheduler.
type Config[ID comparable, T any] struct {
	// Activator and Machine are the two halves of the seam. Both are required.
	Activator Activator[ID, T]
	Machine   Machine[T]

	// Parent is the lifetime every quantum derives from (nil = Background).
	// Submit takes no context of its own — tying a quantum to its submitter
	// would let one caller's cancellation kill unrelated queued work — so this
	// is the one place a caller bounds the queue's work. A Parent that carries a
	// deadline of its own overrides every per-quantum deadline, by the rule in
	// quantumContext.
	Parent context.Context

	// MaxConcurrent bounds simultaneously running quanta. 0 = 1: uniprocessing
	// is the default posture, concurrency is opt-in. This is a resource bound —
	// each running quantum holds a live instance — not a fairness knob.
	MaxConcurrent int
}

type entry[ID comparable] struct {
	pid    ID
	result chan Result
	// deadline bounds the quantum's wall-clock time once it starts. Queue time
	// does not count against it: the clock starts when the instance does.
	deadline time.Duration
	// cancel aborts the running quantum; nil while queued.
	cancel context.CancelFunc
}

// Scheduler is a bounded FIFO run queue.
type Scheduler[ID comparable, T any] struct {
	config Config[ID, T]
	// root is the lifetime every quantum derives from, held separately from
	// Config.Parent so Close can cancel it without touching the caller's tree.
	root     context.Context
	stopRoot context.CancelFunc

	mu      sync.Mutex
	closed  bool
	entries map[ID]*entry[ID]
	// queue holds the pending submissions in arrival order, front first. A slice
	// rather than container/list because that list is untyped — every read of it
	// would be a type assertion for nothing — and the queue is short: it drains
	// as fast as MaxConcurrent allows, so the shift on removal does not matter.
	queue   []*entry[ID]
	running int
	quanta  sync.WaitGroup
}

func New[ID comparable, T any](config Config[ID, T]) (*Scheduler[ID, T], error) {
	if config.Activator == nil || config.Machine == nil {
		return nil, errors.New("sched: Activator and Machine are required")
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 1
	}
	if config.Parent == nil {
		config.Parent = context.Background()
	}
	root, stopRoot := context.WithCancel(config.Parent)
	return &Scheduler[ID, T]{
		config:   config,
		root:     root,
		stopRoot: stopRoot,
		entries:  make(map[ID]*entry[ID]),
	}, nil
}

// Submit queues one quantum for pid and returns the channel its result will
// arrive on. deadline bounds the quantum once it starts (0 = unbounded); time
// spent queued does not count against it. A PID has at most one outstanding
// submission — two concurrent quanta on one process would double-drive its
// journal — so waking a process that is already queued or running is
// ErrAlreadyScheduled.
func (s *Scheduler[ID, T]) Submit(pid ID, deadline time.Duration) (<-chan Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if _, scheduled := s.entries[pid]; scheduled {
		return nil, ErrAlreadyScheduled
	}

	submitted := &entry[ID]{
		pid:      pid,
		result:   make(chan Result, 1),
		deadline: deadline,
	}
	s.entries[pid] = submitted
	s.queue = append(s.queue, submitted)
	s.schedule()
	return submitted.result, nil
}

// Run executes one quantum for pid off the queue: it takes no slot and is not
// tracked as a submission, so it neither waits for capacity nor conflicts with
// one. It is the path for work delegated from inside a running quantum, which
// would deadlock against MaxConcurrent if it queued for a slot the delegating
// quantum is already holding.
//
// ctx is the delegating quantum's context, so the work inherits that quantum's
// remaining budget; deadline applies only when ctx carries none. The returned
// CancelFunc aborts the quantum and is also called once it ends. Close does not
// wait for quanta started here — the caller owns their lifetime.
func (s *Scheduler[ID, T]) Run(ctx context.Context, pid ID, deadline time.Duration) (<-chan Result, context.CancelFunc) {
	quantum, cancel := quantumContext(ctx, deadline)
	result := make(chan Result, 1)
	go func() {
		defer cancel()
		result <- s.run(quantum, pid)
	}()
	return result, cancel
}

// Close stops admission and waits for running quanta to finish. Queued work
// that never ran receives a stopped result.
func (s *Scheduler[ID, T]) Close() {
	s.mu.Lock()
	s.closed = true
	for _, queued := range s.queue {
		queued.result <- Result{Status: Stopped, Err: ErrClosed}
		delete(s.entries, queued.pid)
	}
	s.queue = nil
	s.mu.Unlock()
	s.quanta.Wait()
	s.stopRoot()
}

// Stop aborts pid's outstanding submission: a queued quantum is dequeued and
// delivered a stopped result; a running one has its context cancelled — the
// machine stops the instance and the stopped result flows out the normal way.
// Returns false when pid has no outstanding submission.
func (s *Scheduler[ID, T]) Stop(pid ID) bool {
	s.mu.Lock()
	scheduled, ok := s.entries[pid]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if scheduled.cancel != nil {
		cancel := scheduled.cancel
		s.mu.Unlock()
		cancel()
		return true
	}
	s.dequeue(scheduled)
	delete(s.entries, pid)
	s.mu.Unlock()
	scheduled.result <- Result{Status: Stopped, Err: ErrStopped}
	return true
}

// dequeue removes one queued entry, wherever it sits. Caller holds the lock.
func (s *Scheduler[ID, T]) dequeue(queued *entry[ID]) {
	for i, waiting := range s.queue {
		if waiting == queued {
			s.take(i)
			return
		}
	}
}

// take removes the entry at index i and returns it — the one way anything
// leaves the queue, whether it is being run or abandoned. Caller holds the lock.
func (s *Scheduler[ID, T]) take(i int) *entry[ID] {
	taken := s.queue[i]
	copy(s.queue[i:], s.queue[i+1:])
	// Clear the slot the shift vacated, so a dropped entry is not kept alive by
	// the queue's backing array.
	s.queue[len(s.queue)-1] = nil
	s.queue = s.queue[:len(s.queue)-1]
	return taken
}

// schedule starts quanta while capacity remains, in submission order. Every
// quantum derives from the scheduler's root lifetime, never from a caller's
// context. Caller holds the lock.
func (s *Scheduler[ID, T]) schedule() {
	for s.running < s.config.MaxConcurrent {
		if len(s.queue) == 0 {
			return
		}
		next := s.take(0)
		s.running++
		// The context is derived here, under the lock, so the entry carries its
		// canceller before the quantum can start: a Stop that lands in between
		// must cancel the run, not mistake it for one still queued.
		quantum, cancel := quantumContext(s.root, next.deadline)
		next.cancel = cancel
		s.quanta.Add(1)
		go s.runQuantum(quantum, next)
	}
}

// quantumContext derives one quantum's lifetime from parent and applies its
// deadline. A parent that already bounds its own time keeps that bound: work
// delegated inside another quantum inherits the parent's *remaining* budget
// rather than a fresh copy of the same duration — a spawn tree is one parent
// split into pieces, and one deadline bounds all of it. The deadline lives on
// the context rather than on the process for exactly that reason.
func quantumContext(parent context.Context, deadline time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if _, bounded := parent.Deadline(); !bounded && deadline > 0 {
		return context.WithTimeout(parent, deadline)
	}
	return context.WithCancel(parent)
}

// runQuantum owns one queued quantum end to end and hands back its slot.
func (s *Scheduler[ID, T]) runQuantum(ctx context.Context, running *entry[ID]) {
	defer s.quanta.Done()
	defer running.cancel()
	s.finish(running, s.run(ctx, running.pid))
}

// run drives one quantum to its result: activate, resume, release. The instance
// is released before the result is returned — and so, on the queued path,
// before the slot is — so nothing of one quantum's instance survives into the
// next.
func (s *Scheduler[ID, T]) run(ctx context.Context, pid ID) Result {
	instance, err := s.config.Activator.Activate(ctx, pid)
	if err != nil {
		return Result{Status: Failed, Err: fmt.Errorf("activate %v: %w", pid, err)}
	}
	defer s.config.Machine.Release(instance)
	result, err := s.config.Machine.Resume(ctx, instance)
	if err != nil {
		return Result{Status: Failed, Err: err}
	}
	return result
}

// finish releases the quantum's slot, lets the next one start, and delivers the
// result.
func (s *Scheduler[ID, T]) finish(ran *entry[ID], result Result) {
	s.mu.Lock()
	s.running--
	delete(s.entries, ran.pid)
	if !s.closed {
		s.schedule()
	}
	s.mu.Unlock()

	ran.result <- result
}
