package sched_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/capcompute"
)

type schedPID struct{ id string }

func (p schedPID) PID() string { return p.id }

// quantum is one in-flight Resume the test controls: the scheduler is blocked
// on `done` until the test finishes the quantum with a result.
type quantum struct {
	pid  string
	ctx  context.Context
	done chan capcompute.ResumeResult
}

// harness fakes the app side of the seam: activation is recorded, resumes
// register on a channel and block until the test resolves them.
type harness struct {
	mu          sync.Mutex
	activations map[string]int
	releases    []string // pids released, in order
	running     chan quantum
}

func newHarness() *harness {
	return &harness{
		activations: make(map[string]int),
		running:     make(chan quantum, 16),
	}
}

func (h *harness) config() sched.Config[string, schedPID] {
	return sched.Config[string, schedPID]{
		Activate: func(_ context.Context, pid string) (*capcompute.Process[schedPID], error) {
			h.mu.Lock()
			h.activations[pid]++
			h.mu.Unlock()
			return &capcompute.Process[schedPID]{Cred: schedPID{id: pid}}, nil
		},
		Resume: func(ctx context.Context, process *capcompute.Process[schedPID]) (<-chan capcompute.ResumeResult, error) {
			started := quantum{pid: process.Cred.PID(), ctx: ctx, done: make(chan capcompute.ResumeResult, 1)}
			results := make(chan capcompute.ResumeResult, 1)
			go func() {
				select {
				case result := <-started.done:
					results <- result
				case <-ctx.Done():
					results <- capcompute.ResumeResult{Status: capcompute.ResumeStopped, Err: ctx.Err()}
				}
			}()
			h.running <- started
			return results, nil
		},
		Release: func(process *capcompute.Process[schedPID]) {
			h.mu.Lock()
			h.releases = append(h.releases, process.Cred.PID())
			h.mu.Unlock()
		},
	}
}

func (h *harness) next(t *testing.T) quantum {
	t.Helper()
	select {
	case started := <-h.running:
		return started
	case <-time.After(5 * time.Second):
		t.Fatal("no quantum started")
		panic("unreachable")
	}
}

func (h *harness) activationsOf(pid string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.activations[pid]
}

func (h *harness) released() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.releases...)
}

func completed() capcompute.ResumeResult {
	return capcompute.ResumeResult{Status: capcompute.ResumeCompleted}
}

func yielded() capcompute.ResumeResult {
	return capcompute.ResumeResult{Status: capcompute.ResumeYielded}
}
func await(t *testing.T, results <-chan capcompute.ResumeResult) capcompute.ResumeResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("no result delivered")
		panic("unreachable")
	}
}

// One quantum end to end: activate, resume, deliver, release.
func TestQuantumLifecycle(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	results, err := scheduler.Submit(context.Background(), "p1", 0)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	started := h.next(t)
	started.done <- completed()
	if got := await(t, results).Status; got != capcompute.ResumeCompleted {
		t.Fatalf("status = %s, want completed", got)
	}
	if h.activationsOf("p1") != 1 {
		t.Fatalf("activations = %d, want 1", h.activationsOf("p1"))
	}
	if released := h.released(); len(released) != 1 || released[0] != "p1" {
		t.Fatalf("released = %v, want [p1]", released)
	}
}

// There is no residency: a process that yields is not kept warm, so its next
// quantum activates a fresh instance. This is the law that makes guest state
// unable to cross a quantum boundary — the journal is the only thing that does.
func TestEveryQuantumGetsAFreshInstance(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		results, err := scheduler.Submit(context.Background(), "p1", 0)
		if err != nil {
			t.Fatalf("submit %d: %v", attempt, err)
		}
		started := h.next(t)
		started.done <- yielded()
		await(t, results)
		if got := h.activationsOf("p1"); got != attempt {
			t.Fatalf("after quantum %d: activations = %d, want %d (a yield must not keep an instance warm)", attempt, got, attempt)
		}
		if got := len(h.released()); got != attempt {
			t.Fatalf("after quantum %d: releases = %d, want %d (an instance must not outlive its quantum)", attempt, got, attempt)
		}
	}
}

// The deadline bounds the quantum once it starts, and surfaces as a stopped
// result carrying context.DeadlineExceeded — which the runtime above reads to
// tell "ran out of time" (resumable) from "was told to stop" (an abort).
func TestDeadlineBoundsTheQuantum(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	results, err := scheduler.Submit(context.Background(), "p1", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	h.next(t) // never finished: the deadline must end it
	result := await(t, results)
	if result.Status != capcompute.ResumeStopped {
		t.Fatalf("status = %s, want stopped", result.Status)
	}
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", result.Err)
	}
	if released := h.released(); len(released) != 1 {
		t.Fatalf("released = %v, want the instance released after a deadline abort", released)
	}
}

// Queue time is not charged against a quantum's deadline: the clock starts when
// the guest does. A submission that waits behind a blocker still gets its full
// budget.
func TestDeadlineExcludesQueueTime(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(context.Background(), "queued", time.Minute)

	// Hold the slot well past a short budget, then let the queued work run.
	time.Sleep(100 * time.Millisecond)
	blocker.done <- completed()
	await(t, blockerResults)

	started := h.next(t)
	if deadline, ok := started.ctx.Deadline(); !ok || time.Until(deadline) < 30*time.Second {
		t.Fatalf("queued quantum began with %v remaining, want its full budget", time.Until(deadline))
	}
	started.done <- completed()
	await(t, queuedResults)
}

// Submissions run in submission order — first come, first served, with no
// priority or owner fairness to reorder them.
func TestQueueIsFIFO(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config()) // MaxConcurrent defaults to 1
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	var pending []<-chan capcompute.ResumeResult
	for _, pid := range []string{"first", "second", "third"} {
		results, err := scheduler.Submit(context.Background(), pid, 0)
		if err != nil {
			t.Fatalf("submit %s: %v", pid, err)
		}
		pending = append(pending, results)
	}
	for i, want := range []string{"first", "second", "third"} {
		started := h.next(t)
		if started.pid != want {
			t.Fatalf("quantum %d ran %q, want %q", i, started.pid, want)
		}
		started.done <- completed()
		await(t, pending[i])
	}
}

func TestDuplicateSubmitRefused(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	results, _ := scheduler.Submit(context.Background(), "p1", 0)
	if _, err := scheduler.Submit(context.Background(), "p1", 0); !errors.Is(err, sched.ErrAlreadyScheduled) {
		t.Fatalf("duplicate submit err = %v, want ErrAlreadyScheduled", err)
	}
	h.next(t).done <- completed()
	await(t, results)

	// After the quantum finishes the PID is submittable again.
	if _, err := scheduler.Submit(context.Background(), "p1", 0); err != nil {
		t.Fatalf("resubmit: %v", err)
	}
	h.next(t).done <- completed()
}

func TestCloseStopsQueuedWork(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(context.Background(), "queued", 0)

	closed := make(chan struct{})
	go func() {
		scheduler.Close()
		close(closed)
	}()
	if result := await(t, queuedResults); result.Status != capcompute.ResumeStopped || !errors.Is(result.Err, sched.ErrClosed) {
		t.Fatalf("queued result = %+v, want stopped/ErrClosed", result)
	}
	blocker.done <- yielded()
	await(t, blockerResults)
	<-closed

	if _, err := scheduler.Submit(context.Background(), "p2", 0); !errors.Is(err, sched.ErrClosed) {
		t.Fatalf("submit after close err = %v, want ErrClosed", err)
	}
	// The blocker's own quantum ended, which released its instance; Close waited
	// for that before returning, so nothing is left running behind it.
	if got := h.released(); len(got) != 1 || got[0] != "blocker" {
		t.Fatalf("released = %v, want [blocker]", got)
	}
}

func TestStopDequeuesQueuedWork(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(context.Background(), "queued", 0)

	if !scheduler.Stop("queued") {
		t.Fatal("Stop(queued) = false")
	}
	if result := await(t, queuedResults); result.Status != capcompute.ResumeStopped || !errors.Is(result.Err, sched.ErrStopped) {
		t.Fatalf("stopped result = %+v", result)
	}
	if scheduler.Stop("unknown") {
		t.Fatal("Stop(unknown) = true")
	}

	blocker.done <- completed()
	await(t, blockerResults)
	if h.activationsOf("queued") != 0 {
		t.Fatal("dequeued work was activated")
	}
	// The stopped PID is submittable again.
	if _, err := scheduler.Submit(context.Background(), "queued", 0); err != nil {
		t.Fatalf("resubmit after stop: %v", err)
	}
	h.next(t).done <- completed()
}

func TestStopCancelsRunningQuantum(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	results, _ := scheduler.Submit(context.Background(), "p1", 0)
	h.next(t) // running, never finished by the test
	if !scheduler.Stop("p1") {
		t.Fatal("Stop(p1) = false")
	}
	result := await(t, results)
	if result.Status != capcompute.ResumeStopped || !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("cancelled result = %+v", result)
	}
}

// Regression: a quantum started by a *finishing* quantum's reschedule (or by
// a since-cancelled Submit context) must not inherit a dead context — quanta
// derive from the scheduler's own lifetime.
func TestQuantumContextOutlivesItsTrigger(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	submitCtx, cancelSubmit := context.WithCancel(context.Background())
	blockerResults, _ := scheduler.Submit(submitCtx, "blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(submitCtx, "queued", 0)
	cancelSubmit() // the submitter goes away; its work must not

	blocker.done <- completed()
	await(t, blockerResults)

	queued := h.next(t) // started by the blocker's finish()
	time.Sleep(20 * time.Millisecond)
	if queued.ctx.Err() != nil {
		t.Fatalf("chained quantum's context died with its trigger: %v", queued.ctx.Err())
	}
	queued.done <- completed()
	if result := await(t, queuedResults); result.Status != capcompute.ResumeCompleted {
		t.Fatalf("chained quantum result = %+v, want completed", result)
	}
}
