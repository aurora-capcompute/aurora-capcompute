// Package sched is a bounded run queue: it decides *when* a submitted process
// runs, and nothing else. The app decides *what* runs (Activate — for a durable
// process, journal-replay wiring) and the processor decides *how* (Resume).
//
// It is deliberately not a scheduler in the fair-share sense: no priorities, no
// quotas, no owners. Submissions run first-come-first-served, bounded by
// MaxConcurrent, which exists to cap live guest instances rather than to
// apportion them.
//
// There is no residency. Every quantum activates a fresh instance and closes it
// when the quantum ends, whatever the outcome. Keeping an instance warm across
// quanta would be the one piece of process state living outside the journal —
// guest globals and allocator state would cross a boundary that syscalls are
// supposed to be the only path through — so the queue does not offer it. The
// cost is one instantiation per quantum; the gain is that a cold start is the
// only start, and there is no warm-vs-cold behaviour to reason about.
package sched

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aurora-capcompute/capcompute"
)

var (
	ErrClosed           = errors.New("sched: scheduler is closed")
	ErrAlreadyScheduled = errors.New("sched: process is already scheduled")
	ErrStopped          = errors.New("sched: stopped before running")
)

// Config wires a Scheduler. All three callbacks are required.
type Config[ID comparable, K capcompute.PID[ID]] struct {
	// Activate builds the process for a PID — for a durable process,
	// CreateProcess plus journal replay wiring. Called once per quantum: there
	// is no warm instance to reuse.
	Activate func(ctx context.Context, pid ID) (*capcompute.Process[K], error)
	// Resume gives the process its quantum and returns its result stream —
	// usually a thin wrapper over the processor's Resume.
	Resume func(ctx context.Context, process *capcompute.Process[K]) (<-chan capcompute.ResumeResult, error)
	// Release disposes of an instance once its quantum has ended — closing the
	// guest, keeping the journal. Called exactly once per successful Activate,
	// whatever the quantum's outcome.
	Release func(process *capcompute.Process[K])

	// MaxConcurrent bounds simultaneously running quanta. 0 = 1: uniprocessing
	// is the default posture, concurrency is opt-in. This is a resource bound —
	// each running quantum holds a live guest instance — not a fairness knob.
	MaxConcurrent int
}

type entry[ID comparable, K capcompute.PID[ID]] struct {
	pid    ID
	result chan capcompute.ResumeResult
	// deadline bounds the quantum's wall-clock time once it starts. Queue time
	// does not count against it: the clock starts when the guest does.
	deadline time.Duration
	// cancel aborts the running quantum; nil while queued.
	cancel context.CancelFunc
}

// Scheduler is a bounded FIFO run queue.
type Scheduler[ID comparable, K capcompute.PID[ID]] struct {
	config Config[ID, K]
	// root is the lifetime every quantum derives from. A Submit's context
	// governs admission only — tying a quantum to its submitter's context
	// would let one caller's cancellation kill unrelated queued work.
	root     context.Context
	stopRoot context.CancelFunc

	mu      sync.Mutex
	closed  bool
	entries map[ID]*entry[ID, K]
	queue   *list.List // of *entry, front = next to run
	running int
	quanta  sync.WaitGroup
}

func New[ID comparable, K capcompute.PID[ID]](config Config[ID, K]) (*Scheduler[ID, K], error) {
	if config.Activate == nil || config.Resume == nil || config.Release == nil {
		return nil, errors.New("sched: Activate, Resume and Release are required")
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 1
	}
	root, stopRoot := context.WithCancel(context.Background())
	return &Scheduler[ID, K]{
		config:   config,
		root:     root,
		stopRoot: stopRoot,
		entries:  make(map[ID]*entry[ID, K]),
		queue:    list.New(),
	}, nil
}

// Submit queues one quantum for pid and returns the channel its result will
// arrive on. deadline bounds the quantum once it starts (0 = unbounded); time
// spent queued does not count against it. A PID has at most one outstanding
// submission — two concurrent quanta on one process would double-drive its
// journal — so waking a process that is already queued or running is
// ErrAlreadyScheduled.
func (s *Scheduler[ID, K]) Submit(ctx context.Context, pid ID, deadline time.Duration) (<-chan capcompute.ResumeResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if _, scheduled := s.entries[pid]; scheduled {
		return nil, ErrAlreadyScheduled
	}

	submitted := &entry[ID, K]{
		pid:      pid,
		result:   make(chan capcompute.ResumeResult, 1),
		deadline: deadline,
	}
	s.entries[pid] = submitted
	s.queue.PushBack(submitted)
	s.schedule()
	return submitted.result, nil
}

// Close stops admission and waits for running quanta to finish. Queued work
// that never ran receives a stopped result.
func (s *Scheduler[ID, K]) Close() {
	s.mu.Lock()
	s.closed = true
	for element := s.queue.Front(); element != nil; element = element.Next() {
		queued := element.Value.(*entry[ID, K])
		queued.result <- capcompute.ResumeResult{Status: capcompute.ResumeStopped, Err: ErrClosed}
		delete(s.entries, queued.pid)
	}
	s.queue.Init()
	s.mu.Unlock()
	s.quanta.Wait()
	s.stopRoot()
}

// Stop aborts pid's outstanding submission: a queued quantum is dequeued and
// delivered a stopped result; a running one has its context cancelled — the
// processor kills the guest and the stopped result flows out the normal way.
// Returns false when pid has no outstanding submission.
func (s *Scheduler[ID, K]) Stop(pid ID) bool {
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
	scheduled.result <- capcompute.ResumeResult{Status: capcompute.ResumeStopped, Err: ErrStopped}
	return true
}

// dequeue removes a queued entry. Caller holds the lock.
func (s *Scheduler[ID, K]) dequeue(queued *entry[ID, K]) {
	for element := s.queue.Front(); element != nil; element = element.Next() {
		if element.Value.(*entry[ID, K]) == queued {
			s.queue.Remove(element)
			return
		}
	}
}

// schedule starts quanta while capacity remains, in submission order. Every
// quantum derives from the scheduler's root lifetime, never from a caller's
// context. Caller holds the lock.
func (s *Scheduler[ID, K]) schedule() {
	for s.running < s.config.MaxConcurrent {
		element := s.queue.Front()
		if element == nil {
			return
		}
		s.queue.Remove(element)
		next := element.Value.(*entry[ID, K])
		s.running++
		quantumCtx, cancel := s.quantumContext(next.deadline)
		next.cancel = cancel
		s.quanta.Add(1)
		go s.runQuantum(quantumCtx, next)
	}
}

// quantumContext derives one quantum's lifetime from the scheduler root and
// applies its deadline. The deadline lives on the context rather than on the
// process so that work the quantum delegates — a spawned child driven inside
// it — inherits the parent's *remaining* budget rather than a fresh copy of the
// same duration.
func (s *Scheduler[ID, K]) quantumContext(deadline time.Duration) (context.Context, context.CancelFunc) {
	if deadline > 0 {
		return context.WithTimeout(s.root, deadline)
	}
	return context.WithCancel(s.root)
}

// runQuantum owns one process quantum end to end: activate, resume, deliver the
// result, and release the instance — always, whatever the outcome. An instance
// never outlives its quantum.
func (s *Scheduler[ID, K]) runQuantum(ctx context.Context, running *entry[ID, K]) {
	defer s.quanta.Done()
	defer running.cancel()

	process, err := s.config.Activate(ctx, running.pid)
	if err != nil {
		s.finish(running, capcompute.ResumeResult{
			Status: capcompute.ResumeFailed,
			Err:    fmt.Errorf("activate %v: %w", running.pid, err),
		})
		return
	}
	// The instance is released before the slot is, so the next quantum never
	// overlaps this one's guest memory.
	s.finish(running, s.runOn(ctx, process))
}

// runOn resumes one instance and releases it, however the quantum ends. A
// stopped guest leaves its instance unusable anyway (the processor marks it
// terminated), and a cleanly returned one is not reused by policy.
func (s *Scheduler[ID, K]) runOn(ctx context.Context, process *capcompute.Process[K]) capcompute.ResumeResult {
	defer s.config.Release(process)
	results, err := s.config.Resume(ctx, process)
	if err != nil {
		return capcompute.ResumeResult{Status: capcompute.ResumeFailed, Err: err}
	}
	return <-results
}

// finish releases the quantum's slot, lets the next one start, and delivers the
// result.
func (s *Scheduler[ID, K]) finish(ran *entry[ID, K], result capcompute.ResumeResult) {
	s.mu.Lock()
	s.running--
	delete(s.entries, ran.pid)
	if !s.closed {
		s.schedule()
	}
	s.mu.Unlock()

	ran.result <- result
}
