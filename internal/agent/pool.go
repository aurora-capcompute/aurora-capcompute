package agent

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/aurora-capcompute/capcompute"
)

var (
	errPoolClosed = errors.New("pool: closed")
	errDropped    = errors.New("pool: stopped before running")
)

// quantumResult is how one quantum ended.
type quantumResult struct {
	status capcompute.ResumeStatus
	err    error
}

// pool bounds how many guest quanta run at once. The bound is the worker count:
// that many goroutines each run one quantum to its end before taking the next,
// so nothing counts slots and nothing can overrun.
type pool struct {
	queue chan quantum
	root  context.Context
	stop  context.CancelFunc
	// workers counts the workers, and only them: they are started in newPool,
	// so no Add can ever race the Wait in close.
	workers sync.WaitGroup
}

type quantum struct {
	ctx      context.Context
	deadline time.Duration
	run      func(context.Context) quantumResult
	// result is buffered: the outcome lands whether or not anyone reads it, so
	// a dropped submission strands no goroutine.
	result chan quantumResult
}

func newPool(parent context.Context, size int) *pool {
	root, stop := context.WithCancel(parent)
	p := &pool{queue: make(chan quantum), root: root, stop: stop}
	for range size {
		p.workers.Go(p.work)
	}
	return p
}

// submit runs a quantum as soon as a worker is free. It returns before the
// quantum starts: the outcome arrives on the channel, and cancel drops the
// submission while it waits or stops the quantum once it has started. deadline
// bounds the quantum's wall-clock once it starts — queue time never counts
// against it.
//
// The quantum's lifetime hangs off the pool's root: no caller's context reaches
// it, so one caller can never cancel work it did not submit. cancel is the only
// lever.
func (p *pool) submit(deadline time.Duration, run func(context.Context) quantumResult) (<-chan quantumResult, context.CancelFunc, error) {
	if p.root.Err() != nil {
		return nil, nil, errPoolClosed
	}
	ctx, cancel := context.WithCancel(p.root)
	q := quantum{ctx: ctx, deadline: deadline, run: run, result: make(chan quantumResult, 1)}
	// Off the caller's goroutine, because the send blocks until a worker is free
	// and the caller needs cancel first: a submission still waiting has to be
	// droppable. Not in p.workers — ctx is done at shutdown, so this exits at
	// once and needs no waiting.
	go func() {
		select {
		case p.queue <- q:
		case <-ctx.Done():
			q.result <- p.dropped()
		}
	}()
	return q.result, cancel, nil
}

// work runs one quantum at a time, for as long as the pool is open.
func (p *pool) work() {
	for {
		select {
		case q := <-p.queue:
			q.result <- p.runOne(q)
		case <-p.root.Done():
			return
		}
	}
}

func (p *pool) runOne(q quantum) quantumResult {
	// A submission cancelled while it waited — by its caller or by shutdown —
	// never starts.
	if q.ctx.Err() != nil {
		return p.dropped()
	}
	// The worker is held, so the wall-clock bound starts now.
	ctx, done := context.WithTimeout(q.ctx, q.deadline)
	defer done()
	return q.run(ctx)
}

// dropped is the result of a submission that never started.
func (p *pool) dropped() quantumResult {
	if p.root.Err() != nil {
		return quantumResult{status: capcompute.ResumeStopped, err: errPoolClosed}
	}
	return quantumResult{status: capcompute.ResumeStopped, err: errDropped}
}

// close stops the quanta still waiting and the ones running, and waits for the
// workers. Shutdown is the root's cancellation, never the queue's close, so a
// submit racing close settles its submission instead of panicking on a closed
// send.
func (p *pool) close() {
	p.stop()
	p.workers.Wait()
}
