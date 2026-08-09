// Package sched bounds how many guests run at once. It is a direct.Registry
// wrapped around another: everything but Spawn passes straight through, and
// Spawn queues, waits for a slot, bounds the quantum's wall-clock, and hands
// back a handle the caller cannot tell from an unqueued one.
package sched

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/process"
	"github.com/aurora-capcompute/capcompute/sys"
)

var (
	ErrClosed  = errors.New("sched: scheduler is closed")
	ErrStopped = errors.New("sched: stopped before running")
)

// Process is what the scheduler needs of a credential beyond what direct does.
// It lives here rather than on direct.ProcessEntry because queueing is this
// package's concern: direct spawns whatever it is handed, immediately.
type Process interface {
	direct.ProcessEntry
	// Deadline bounds the quantum's wall-clock once it starts (0 = unbounded).
	// Queue time does not count against it — the clock starts with the guest.
	Deadline() time.Duration
}

type Config struct {
	// Parent is the lifetime every quantum derives from (nil = Background).
	// Spawn takes no lifetime of its own for a queued guest — tying a quantum to
	// its submitter would let one caller's cancellation kill unrelated queued
	// work — so this is the one place a caller bounds the queue's work.
	Parent context.Context
	// MaxConcurrent bounds simultaneously running quanta. 0 = 1: uniprocessing
	// is the default posture, concurrency is opt-in. This is a resource bound —
	// each running quantum holds a live guest — not a fairness knob.
	MaxConcurrent int
}

type Scheduler[T direct.ProgramID, P Process] struct {
	inner    direct.Registry[T, P]
	config   Config
	root     context.Context
	stopRoot context.CancelFunc

	mu      sync.Mutex
	closed  bool
	queue   []*pending[T, P]
	running int
	quanta  sync.WaitGroup
}

func New[T direct.ProgramID, P Process](inner direct.Registry[T, P], config Config) (*Scheduler[T, P], error) {
	if inner == nil {
		return nil, errors.New("sched: a registry is required")
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 1
	}
	if config.Parent == nil {
		config.Parent = context.Background()
	}
	root, stopRoot := context.WithCancel(config.Parent)
	return &Scheduler[T, P]{inner: inner, config: config, root: root, stopRoot: stopRoot}, nil
}

func (s *Scheduler[T, P]) Add(ctx context.Context, data direct.Data[T]) (direct.Digest, error) {
	return s.inner.Add(ctx, data)
}
func (s *Scheduler[T, P]) Exists(id T) bool                    { return s.inner.Exists(id) }
func (s *Scheduler[T, P]) Get(id T) (direct.View[T], bool)     { return s.inner.Get(id) }
func (s *Scheduler[T, P]) List() []direct.View[T]              { return s.inner.List() }
func (s *Scheduler[T, P]) ValidateInput(id T, in string) error { return s.inner.ValidateInput(id, in) }
func (s *Scheduler[T, P]) ValidateOutput(id T, a string) error { return s.inner.ValidateOutput(id, a) }

func (s *Scheduler[T, P]) Remove(id T) (func(context.Context) error, bool) {
	return s.inner.Remove(id)
}

// Close drains the queue, waits out the quanta already running, and closes the
// registry underneath.
func (s *Scheduler[T, P]) Close(ctx context.Context) []error {
	s.mu.Lock()
	s.closed = true
	for _, queued := range s.queue {
		queued.settle(process.Result{Status: process.Stopped, Error: ErrClosed})
	}
	s.queue = nil
	s.mu.Unlock()
	s.quanta.Wait()
	s.stopRoot()
	return s.inner.Close(ctx)
}

// Spawn runs a guest once a slot is free. It returns before the guest starts:
// the handle's result arrives when the quantum ends, and cancelling it drops the
// submission if it is still waiting.
func (s *Scheduler[T, P]) Spawn(
	_ context.Context,
	id T,
	entry P,
	mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error),
) (process.Handle, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	submitted := &pending[T, P]{
		scheduler: s,
		id:        id,
		entry:     entry,
		mk:        mkDispatcher,
		results:   make(chan process.Result, 1),
	}
	s.queue = append(s.queue, submitted)
	s.schedule()
	s.mu.Unlock()
	return submitted, nil
}

// schedule starts submissions while capacity remains, in arrival order. Caller
// holds the lock.
func (s *Scheduler[T, P]) schedule() {
	for s.running < s.config.MaxConcurrent && len(s.queue) > 0 {
		next := s.queue[0]
		copy(s.queue, s.queue[1:])
		s.queue[len(s.queue)-1] = nil
		s.queue = s.queue[:len(s.queue)-1]
		s.running++
		// Derived under the lock so the submission carries its canceller before
		// the quantum can start: a Cancel landing in between must cancel the run,
		// not mistake it for one still waiting.
		quantum, cancel := quantumContext(s.root, next.entry.Deadline())
		next.quantum, next.cancel = quantum, cancel
		s.quanta.Add(1)
		go s.run(next)
	}
}

func (s *Scheduler[T, P]) run(p *pending[T, P]) {
	defer s.quanta.Done()
	defer p.cancel()
	result := process.Result{Status: process.Completed}
	handle, err := s.inner.Spawn(p.quantum, p.id, p.entry, p.mk)
	if err != nil {
		result = process.Result{Status: process.Failed, Error: err}
	} else {
		result = <-handle.Result()
	}
	s.mu.Lock()
	s.running--
	if !s.closed {
		s.schedule()
	}
	s.mu.Unlock()
	p.settle(result)
}

// drop removes a submission that has not started. Reports false when it already
// has, in which case cancelling its quantum is the way to stop it.
func (s *Scheduler[T, P]) drop(p *pending[T, P]) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, waiting := range s.queue {
		if waiting == p {
			copy(s.queue[i:], s.queue[i+1:])
			s.queue[len(s.queue)-1] = nil
			s.queue = s.queue[:len(s.queue)-1]
			return true
		}
	}
	return false
}

func quantumContext(parent context.Context, deadline time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if _, bounded := parent.Deadline(); !bounded && deadline > 0 {
		return context.WithTimeout(parent, deadline)
	}
	return context.WithCancel(parent)
}

// pending is one queued spawn, and the handle the caller holds for it.
type pending[T direct.ProgramID, P Process] struct {
	scheduler *Scheduler[T, P]
	id        T
	entry     P
	mk        func(context.Context, P) (sys.Dispatcher[P], error)
	results   chan process.Result

	quantum context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func (p *pending[T, P]) Result() <-chan process.Result { return p.results }

func (p *pending[T, P]) Cancel() {
	if p.scheduler.drop(p) {
		p.settle(process.Result{Status: process.Stopped, Error: ErrStopped})
		return
	}
	p.scheduler.mu.Lock()
	cancel := p.cancel
	p.scheduler.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (p *pending[T, P]) settle(result process.Result) {
	p.once.Do(func() {
		p.results <- result
		close(p.results)
	})
}
