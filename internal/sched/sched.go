// Package sched bounds how many guests run at once. It is a direct.Registry
// wrapped around another: everything but Spawn passes straight through, and
// Spawn waits for a slot, bounds the quantum's wall-clock, and hands back a
// handle the caller cannot tell from an unqueued one.
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
	// Spawn takes no lifetime of its own — tying a quantum to its submitter would
	// let one caller's cancellation kill unrelated queued work — so this is the
	// one place a caller bounds the queue's work.
	Parent context.Context
	// MaxConcurrent bounds simultaneously running quanta. 0 = 1: uniprocessing
	// is the default posture, concurrency is opt-in. This is a resource bound —
	// each running quantum holds a live guest — not a fairness knob.
	MaxConcurrent int
}

// Scheduler is direct.Registry with a bound on concurrent guests. The bound is
// a slot channel: a submission holds one for as long as its guest runs.
type Scheduler[T direct.ProgramID, P Process] struct {
	inner     direct.Registry[T, P]
	slots     chan submittedTask[T, P]
	root      context.Context
	stopRoot  context.CancelFunc
	closeOnce sync.Once
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
	slots := make(chan submittedTask[T, P], config.MaxConcurrent)
	go func() {
		for task := range slots {
			task := task
			go func() {
				deadlineCtx, _ := context.WithTimeoutCause(task.ctx, task.timeoutDuration, errors.New("sched: deadline exceeded"))
				handle, err := inner.Spawn(deadlineCtx, task.id, task.entry, task.mkDispatcher)
				if err != nil {
					task.result <- process.Result{Status: process.Failed, Error: err}
					return
				}
				res := <-handle.Result()
				task.result <- res
			}()
		}
	}()
	return &Scheduler[T, P]{
		inner:     inner,
		slots:     slots,
		root:      root,
		stopRoot:  stopRoot,
		closeOnce: sync.Once{},
	}, nil
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

// Close releases everything still waiting for a slot, stops the guests already
// running, and closes the registry underneath.
func (s *Scheduler[T, P]) Close(ctx context.Context) []error {
	s.closeOnce.Do(func() {
		close(s.slots)
		s.stopRoot()
		for task := range s.slots {
			task.stop()
		}
	})

	return s.inner.Close(ctx)
}

// Spawn runs a guest once a slot is free. It returns before the guest starts:
// the handle's result arrives when the quantum ends, and cancelling it drops the
// submission if it is still waiting.
func (s *Scheduler[T, P]) Spawn(
	id T,
	entry P,
	timeout time.Duration,
	mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error),
) (process.Handle, error) {
	select {
	case <-s.root.Done():
		return nil, ErrClosed
	default:
	}

	result := make(chan process.Result)
	taskCtx, stopTask := context.WithCancel(s.root)
	task := submittedTask[T, P]{
		ctx:             taskCtx,
		stop:            stopTask,
		id:              id,
		entry:           entry,
		mkDispatcher:    mkDispatcher,
		result:          result,
		timeoutDuration: timeout,
	}
	s.slots <- task
	submitted := &submissionHandle{
		result: result,
		stop:   stopTask,
	}
	return submitted, nil
}

type submittedTask[T direct.ProgramID, P Process] struct {
	ctx             context.Context
	stop            context.CancelFunc
	id              T
	entry           P
	mkDispatcher    func(context.Context, P) (sys.Dispatcher[P], error)
	result          chan<- process.Result
	timeoutDuration time.Duration
}

type submissionHandle struct {
	result <-chan process.Result
	stop   context.CancelFunc
}

func (s *submissionHandle) Result() <-chan process.Result {
	return s.result
}

func (s *submissionHandle) Cancel() {
	s.stop()
}
