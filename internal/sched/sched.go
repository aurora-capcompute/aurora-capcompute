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
	Completed Status = "completed"
	Yielded   Status = "yielded"
	Stopped   Status = "stopped"
	Failed    Status = "failed"
)

// Result is one quantum's outcome.
type Result struct {
	Status Status
	Err    error
}

type Activator[ID comparable, T any] interface {
	Execute(ctx context.Context, pid ID) (T, error)
}

type Machine[T any] interface {
	Resume(ctx context.Context, instance T) (Result, error)
	Release(instance T)
}

// Config wires a Scheduler.
type Config[ID comparable, T any] struct {
	Activator     Activator[ID, T]
	Machine       Machine[T]
	Parent        context.Context
	MaxConcurrent int
}

type entry[ID comparable] struct {
	pid      ID
	result   chan Result
	deadline time.Duration
	cancel   context.CancelFunc
}

// Scheduler is a bounded FIFO run queue.
type Scheduler[ID comparable, T any] struct {
	config   Config[ID, T]
	root     context.Context
	stopRoot context.CancelFunc

	mu      sync.Mutex
	closed  bool
	entries map[ID]*entry[ID]
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

func (s *Scheduler[ID, T]) Run(ctx context.Context, pid ID, deadline time.Duration) (<-chan Result, context.CancelFunc) {
	quantum, cancel := quantumContext(ctx, deadline)
	result := make(chan Result, 1)
	go func() {
		defer cancel()
		result <- s.run(quantum, pid)
	}()
	return result, cancel
}

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

func quantumContext(parent context.Context, deadline time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if _, bounded := parent.Deadline(); !bounded && deadline > 0 {
		return context.WithTimeout(parent, deadline)
	}
	return context.WithCancel(parent)
}

func (s *Scheduler[ID, T]) runQuantum(ctx context.Context, running *entry[ID]) {
	defer s.quanta.Done()
	defer running.cancel()
	s.finish(running, s.run(ctx, running.pid))
}

func (s *Scheduler[ID, T]) run(ctx context.Context, pid ID) Result {
	instance, err := s.config.Activator.Execute(ctx, pid)
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
