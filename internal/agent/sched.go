// Package agent Package sched bounds how many guests run at once. It is a direct.Registry
// wrapped around another: everything but Spawn passes straight through, and
// Spawn waits for a worker, bounds the quantum's wall-clock, and hands back a
// handle the caller cannot tell from an unqueued one.
package agent

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
	// ErrDeadline is the cause a quantum's context carries when its wall-clock
	// bound expires, so a caller can tell a timeout from a stop.
	ErrDeadline = errors.New("sched: quantum deadline exceeded")
)

// Handle is a submission: its outcome, and the one lever that stops it. Closing
// drops the submission while it waits for a worker, or stops the guest once it
// has started.
type Handle interface {
	process.Handle
	Close()
}

// schedulerImpl is direct.Registry with a bound on concurrent guests. The bound is
// the worker count: MaxConcurrent goroutines each run one guest to completion
// before taking the next, so nothing counts slots and nothing can overrun.
type schedulerImpl[T direct.ProgramID, P any] struct {
	inner    direct.Registry[T, P]
	tasks    chan submittedTask[T, P]
	root     context.Context
	stopRoot context.CancelFunc
	// live counts the workers, and only them: they are started in New, so no Add
	// can ever race the Wait in Close.
	live sync.WaitGroup
}

func New[T direct.ProgramID, P any](
	inner direct.Registry[T, P],
	maxConcurrent int,
	parent context.Context,
) (Scheduler[T, P], error) {
	if inner == nil {
		return nil, errors.New("sched: a registry is required")
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	if parent == nil {
		parent = context.Background()
	}
	root, stopRoot := context.WithCancel(parent)
	s := &schedulerImpl[T, P]{
		inner:    inner,
		tasks:    make(chan submittedTask[T, P]),
		root:     root,
		stopRoot: stopRoot,
	}
	for range maxConcurrent {
		s.live.Go(s.work)
	}
	return s, nil
}

func (s *schedulerImpl[T, P]) Add(ctx context.Context, data direct.Data[T]) (direct.Digest, error) {
	return s.inner.Add(ctx, data)
}
func (s *schedulerImpl[T, P]) Exists(id T) bool                { return s.inner.Exists(id) }
func (s *schedulerImpl[T, P]) Get(id T) (direct.View[T], bool) { return s.inner.Get(id) }
func (s *schedulerImpl[T, P]) List() []direct.View[T]          { return s.inner.List() }
func (s *schedulerImpl[T, P]) ValidateInput(id T, in string) error {
	return s.inner.ValidateInput(id, in)
}
func (s *schedulerImpl[T, P]) ValidateOutput(id T, a string) error {
	return s.inner.ValidateOutput(id, a)
}
func (s *schedulerImpl[T, P]) Remove(id T) (func(context.Context) error, bool) {
	return s.inner.Remove(id)
}

// Close releases everything still waiting for a worker, stops the guests already
// running, waits them out, and closes the registry underneath. Shutdown is the
// root's cancellation, never the task channel's close, so a Spawn racing Close
// settles its submission instead of panicking on a closed send. Safe to call
// more than once, and a cancelled Config.Parent shuts the schedulerImpl down the
// same way.
func (s *schedulerImpl[T, P]) Close(ctx context.Context) []error {
	s.stopRoot()
	s.live.Wait()
	return s.inner.Close(ctx)
}

// Spawn runs a guest as soon as a worker is free. It returns before the guest
// starts: the outcome arrives on the handle, and closing the handle drops the
// submission while it waits, or stops the guest once it has started. deadline
// bounds the quantum's wall-clock once it starts (0 = unbounded) — queue time
// never counts against it.
//
// The quantum's lifetime originates here, hanging off the schedulerImpl's root: no
// caller's context reaches it, so one caller can never cancel work it did not
// submit. The handle is the only lever.
func (s *schedulerImpl[T, P]) Spawn(
	id T,
	digest direct.Digest,
	entry P,
	deadline time.Duration,
	mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error),
) (Handle, error) {
	select {
	case <-s.root.Done():
		return nil, ErrClosed
	default:
	}

	taskCtx, stop := context.WithCancel(s.root)
	task := submittedTask[T, P]{
		ctx:          taskCtx,
		id:           id,
		digest:       digest,
		entry:        entry,
		deadline:     deadline,
		mkDispatcher: mkDispatcher,
		// Buffered: the outcome lands whether or not anyone reads it, so a
		// dropped handle strands no goroutine.
		result: make(chan process.Result, 1),
	}

	// Off the caller's goroutine, because the send blocks until a worker is free
	// and Spawn must hand back the handle first: a submission still waiting for a
	// worker has to be closable. Deliberately not in s.live — that counts the
	// fixed workers, added before any Wait, and a Spawn racing Close would
	// otherwise add to a WaitGroup whose Wait has already returned. This
	// goroutine needs no waiting: every arm below is a closed channel at
	// shutdown, so it exits at once.
	go func() {
		select {
		case s.tasks <- task:
			// A worker owns it now; closing the handle reaches the guest through
			// taskCtx, which its quantum derives from.
		case <-s.root.Done():
			stop()
			task.settle(process.Result{Status: process.Stopped, Error: ErrClosed})
		case <-taskCtx.Done():
			task.settle(process.Result{Status: process.Stopped, Error: ErrStopped})
		}
	}()
	return submissionHandle{result: task.result, close: stop}, nil
}

// work runs one guest at a time, for as long as the schedulerImpl is open. The
// number of these is the concurrency bound.
func (s *schedulerImpl[T, P]) work() {
	for {
		select {
		case task := <-s.tasks:
			s.run(task)
		case <-s.root.Done():
			return
		}
	}
}

func (s *schedulerImpl[T, P]) run(task submittedTask[T, P]) {
	// The worker is held, so the wall-clock bound starts now: queue time never
	// counts against a guest's deadline. A zero deadline is the host's opt-out
	// (Config.MaxQuantumDuration negative) and must stay unbounded — a zero
	// timeout would expire before the guest ran.
	quantum, done := context.WithCancel(task.ctx)
	if task.deadline > 0 {
		quantum, done = context.WithTimeoutCause(task.ctx, task.deadline, ErrDeadline)
	}
	defer done()

	// FIXME: there should come digest maybe
	handle, err := s.inner.Spawn(quantum, task.id, task.digest, task.entry, task.mkDispatcher)
	if err != nil {
		task.settle(process.Result{Status: process.Failed, Error: err})
		return
	}
	task.settle(<-handle.Result())
}

type submittedTask[T direct.ProgramID, P any] struct {
	ctx          context.Context
	id           T
	entry        P
	digest       direct.Digest
	deadline     time.Duration
	mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error)
	result       chan process.Result
}

// settle delivers the one outcome. Exactly one path reaches it: a submission is
// either handed to a worker, which runs it, or dropped before it ever was.
func (t submittedTask[T, P]) settle(result process.Result) {
	t.result <- result
	close(t.result)
}

type submissionHandle struct {
	result <-chan process.Result
	close  context.CancelFunc
}

func (s submissionHandle) Result() <-chan process.Result { return s.result }

// Close is idempotent: it cancels the submission's lifetime, dropping it if it
// is still waiting and stopping the guest if it has started.
func (s submissionHandle) Close() { s.close() }

type Scheduler[T direct.ProgramID, P any] interface {
	Add(ctx context.Context, data direct.Data[T]) (direct.Digest, error)
	Exists(id T) bool
	Get(id T) (direct.View[T], bool)
	List() []direct.View[T]
	ValidateInput(id T, in string) error
	ValidateOutput(id T, a string) error
	Remove(id T) (func(context.Context) error, bool)
	Close(ctx context.Context) []error
	Spawn(
		id T,
		digest direct.Digest,
		entry P,
		deadline time.Duration,
		mkDispatcher func(context.Context, P) (sys.Dispatcher[P], error),
	) (Handle, error)
}
