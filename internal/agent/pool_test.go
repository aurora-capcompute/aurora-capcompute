package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute"
)

// guests stands in for the quanta a pool runs: it counts how many are alive at
// once and records what each one's context carried.
type guests struct {
	mu      sync.Mutex
	started int
	live    int
	peak    int
	bounded []bool
	// hold keeps each guest alive that long; block, when set, holds it until
	// the test closes the channel.
	hold  time.Duration
	block chan struct{}
}

func (g *guests) run(ctx context.Context) quantumResult {
	_, bounded := ctx.Deadline()
	g.mu.Lock()
	g.started++
	g.live++
	g.peak = max(g.peak, g.live)
	g.bounded = append(g.bounded, bounded)
	g.mu.Unlock()
	// A guest counts as alive until it returns — the moment its worker is free
	// to take the next one.
	defer func() {
		g.mu.Lock()
		g.live--
		g.mu.Unlock()
	}()
	time.Sleep(g.hold)
	if g.block != nil {
		select {
		case <-g.block:
		case <-ctx.Done():
		}
	}
	if ctx.Err() != nil {
		return quantumResult{status: capcompute.ResumeStopped, err: ctx.Err()}
	}
	return quantumResult{status: capcompute.ResumeCompleted}
}

func (g *guests) count() (started, peak int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.started, g.peak
}

// waitStarted blocks until n guests have started, so a test knows which
// submission holds a worker before it adds the next.
func (g *guests) waitStarted(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if started, _ := g.count(); started >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fewer than %d guests started", n)
}

func newTestPool(t *testing.T, size int) *pool {
	t.Helper()
	p := newPool(context.Background(), size)
	t.Cleanup(p.close)
	return p
}

func submit(t *testing.T, p *pool, deadline time.Duration, run func(context.Context) quantumResult) (<-chan quantumResult, context.CancelFunc) {
	t.Helper()
	result, cancel, err := p.submit(deadline, run)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return result, cancel
}

func await(t *testing.T, result <-chan quantumResult) quantumResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no result delivered")
		return quantumResult{}
	}
}

// The bound is the whole point: with one worker, a second guest waits for the
// first to finish.
func TestPoolRunsOneGuestPerWorker(t *testing.T) {
	g := &guests{hold: 20 * time.Millisecond}
	p := newTestPool(t, 1)
	first, _ := submit(t, p, time.Minute, g.run)
	second, _ := submit(t, p, time.Minute, g.run)
	await(t, first)
	await(t, second)
	if started, peak := g.count(); started != 2 || peak != 1 {
		t.Fatalf("started %d, peak %d; want 2 guests, one at a time", started, peak)
	}
}

// Every submission runs, however many wait at once.
func TestPoolRunsEverySubmission(t *testing.T) {
	g := &guests{}
	p := newTestPool(t, 2)
	var results []<-chan quantumResult
	for range 10 {
		result, _ := submit(t, p, time.Minute, g.run)
		results = append(results, result)
	}
	for _, result := range results {
		if r := await(t, result); r.status != capcompute.ResumeCompleted {
			t.Fatalf("submission = %+v, want completed", r)
		}
	}
	if started, _ := g.count(); started != 10 {
		t.Fatalf("%d guests ran, want 10", started)
	}
}

// The deadline bounds the quantum, and queue time does not count against it:
// the clock starts when the guest does.
func TestPoolDeadlineStartsWithTheGuest(t *testing.T) {
	slow := &guests{hold: 50 * time.Millisecond}
	queued := &guests{}
	p := newTestPool(t, 1)
	first, _ := submit(t, p, time.Minute, slow.run)
	slow.waitStarted(t, 1)
	queuedResult, _ := submit(t, p, 20*time.Millisecond, queued.run)
	await(t, first)
	if r := await(t, queuedResult); r.status != capcompute.ResumeCompleted {
		t.Fatalf("a guest that queued past its deadline = %+v, want completed", r)
	}
	if !queued.bounded[0] {
		t.Fatal("the quantum carried no deadline")
	}
}

// Cancelling a submission that has not started drops it: it never runs, and
// its result says so.
func TestPoolCancelDropsAQueuedSubmission(t *testing.T) {
	g := &guests{block: make(chan struct{})}
	p := newTestPool(t, 1)
	running, _ := submit(t, p, time.Minute, g.run)
	g.waitStarted(t, 1)
	queued, cancel := submit(t, p, time.Minute, g.run)
	cancel()
	if r := await(t, queued); r.status != capcompute.ResumeStopped || !errors.Is(r.err, errDropped) {
		t.Fatalf("cancelled submission = %+v, want stopped and dropped", r)
	}
	close(g.block)
	await(t, running)
	if started, _ := g.count(); started != 1 {
		t.Fatalf("%d guests ran, want only the first", started)
	}
}

// Cancelling a running guest stops it.
func TestPoolCancelStopsARunningGuest(t *testing.T) {
	g := &guests{block: make(chan struct{})}
	p := newTestPool(t, 1)
	running, cancel := submit(t, p, time.Minute, g.run)
	g.waitStarted(t, 1)
	cancel()
	if r := await(t, running); r.status != capcompute.ResumeStopped {
		t.Fatalf("cancelled running guest = %+v, want stopped", r)
	}
}

// Closing settles everything still waiting rather than stranding it, and a
// closed pool refuses new work.
func TestPoolCloseSettlesQueuedWork(t *testing.T) {
	g := &guests{block: make(chan struct{})}
	p := newPool(context.Background(), 1)
	running, _ := submit(t, p, time.Minute, g.run)
	g.waitStarted(t, 1)
	queued, _ := submit(t, p, time.Minute, g.run)
	p.close()
	if r := await(t, running); r.status != capcompute.ResumeStopped {
		t.Fatalf("running at close = %+v, want stopped", r)
	}
	if r := await(t, queued); r.status != capcompute.ResumeStopped || !errors.Is(r.err, errPoolClosed) {
		t.Fatalf("queued at close = %+v, want stopped and closed", r)
	}
	if _, _, err := p.submit(time.Minute, g.run); !errors.Is(err, errPoolClosed) {
		t.Fatalf("submit after close = %v, want closed", err)
	}
}
