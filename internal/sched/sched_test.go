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
	mu            sync.Mutex
	activations   map[string]int
	deactivations []string
	running       chan quantum
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
		Deactivate: func(pid string, _ *capcompute.Process[schedPID]) {
			h.mu.Lock()
			h.deactivations = append(h.deactivations, pid)
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

func (h *harness) deactivated() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.deactivations...)
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

func TestQuantumLifecycle(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	results, err := scheduler.Submit(context.Background(), "p1", "acme", sched.Normal)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	h.next(t).done <- completed()
	if result := await(t, results); result.Status != capcompute.ResumeCompleted {
		t.Fatalf("result = %+v", result)
	}
	if h.activationsOf("p1") != 1 {
		t.Fatalf("activations = %d, want 1", h.activationsOf("p1"))
	}
	// A terminated run deactivates immediately — the journal is the process.
	if got := h.deactivated(); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("deactivations = %v, want [p1]", got)
	}
	if scheduler.Resident() != 0 {
		t.Fatalf("resident = %d, want 0", scheduler.Resident())
	}
}

func TestFairShareAcrossOwners(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	// Hold the single slot so the queue builds up in submission order:
	// three for acme, one each for beta and gamma.
	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", "acme", sched.Normal)
	blocker := h.next(t)
	for _, submission := range []struct{ pid, owner string }{
		{"a1", "acme"}, {"a2", "acme"}, {"a3", "acme"}, {"b1", "beta"}, {"c1", "gamma"},
	} {
		if _, err := scheduler.Submit(context.Background(), submission.pid, submission.owner, sched.Normal); err != nil {
			t.Fatalf("submit %s: %v", submission.pid, err)
		}
	}
	blocker.done <- completed()
	await(t, blockerResults)

	// Round-robin across owners, FIFO within: not a1,a2,a3 first.
	want := []string{"a1", "b1", "c1", "a2", "a3"}
	for _, expected := range want {
		started := h.next(t)
		if started.pid != expected {
			t.Fatalf("run order got %s, want %s (fair share violated)", started.pid, expected)
		}
		started.done <- completed()
	}
}

func TestPriorityBandsAreStrict(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", "acme", sched.Normal)
	blocker := h.next(t)
	scheduler.Submit(context.Background(), "low", "acme", sched.Low)
	scheduler.Submit(context.Background(), "normal", "acme", sched.Normal)
	scheduler.Submit(context.Background(), "high", "acme", sched.High)
	blocker.done <- completed()
	await(t, blockerResults)

	for _, expected := range []string{"high", "normal", "low"} {
		started := h.next(t)
		if started.pid != expected {
			t.Fatalf("run order got %s, want %s (priority violated)", started.pid, expected)
		}
		started.done <- completed()
	}
}

func TestOwnerQuotaIsBackpressure(t *testing.T) {
	h := newHarness()
	config := h.config()
	config.MaxConcurrent = 2
	config.QuotaOf = func(owner string) sched.Quota {
		if owner == "acme" {
			return sched.Quota{MaxConcurrent: 1}
		}
		return sched.Quota{}
	}
	scheduler, err := sched.New(config)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	scheduler.Submit(context.Background(), "a1", "acme", sched.Normal)
	first := h.next(t)
	if first.pid != "a1" {
		t.Fatalf("first quantum = %s", first.pid)
	}

	// acme is at quota: a2 must wait even though a slot is free; beta rides it.
	a2Results, _ := scheduler.Submit(context.Background(), "a2", "acme", sched.Normal)
	scheduler.Submit(context.Background(), "b1", "beta", sched.Normal)
	second := h.next(t)
	if second.pid != "b1" {
		t.Fatalf("free slot went to %s, want b1 (quota not enforced)", second.pid)
	}
	select {
	case started := <-h.running:
		t.Fatalf("quantum %s started past acme's quota", started.pid)
	case <-time.After(50 * time.Millisecond):
	}

	// a1 finishing releases acme's quota; a2 runs.
	first.done <- completed()
	third := h.next(t)
	if third.pid != "a2" {
		t.Fatalf("after release got %s, want a2", third.pid)
	}
	second.done <- completed()
	third.done <- completed()
	await(t, a2Results)
}

func TestVirtualActorEvictionAndReactivation(t *testing.T) {
	h := newHarness()
	config := h.config()
	config.MaxResident = 1
	scheduler, err := sched.New(config)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	run := func(pid string, result capcompute.ResumeResult) {
		t.Helper()
		results, err := scheduler.Submit(context.Background(), pid, "acme", sched.Normal)
		if err != nil {
			t.Fatalf("submit %s: %v", pid, err)
		}
		h.next(t).done <- result
		await(t, results)
	}

	// p1 yields: it stays warm, waiting to wake again.
	run("p1", yielded())
	if scheduler.Resident() != 1 {
		t.Fatalf("resident = %d, want 1", scheduler.Resident())
	}

	// p2 yields too: residency overflows and idle p1 is evicted, LRU-first.
	run("p2", yielded())
	if got := h.deactivated(); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("deactivations = %v, want [p1]", got)
	}
	if scheduler.Resident() != 1 {
		t.Fatalf("resident = %d, want 1", scheduler.Resident())
	}

	// Waking p1 re-activates it from its journal; warm p2 is reused as-is.
	run("p1", completed())
	if h.activationsOf("p1") != 2 {
		t.Fatalf("p1 activations = %d, want 2 (reactivation)", h.activationsOf("p1"))
	}
	run("p2", completed())
	if h.activationsOf("p2") != 1 {
		t.Fatalf("p2 activations = %d, want 1 (stayed warm)", h.activationsOf("p2"))
	}
}

func TestDuplicateSubmitRefused(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	results, _ := scheduler.Submit(context.Background(), "p1", "acme", sched.Normal)
	if _, err := scheduler.Submit(context.Background(), "p1", "acme", sched.Normal); !errors.Is(err, sched.ErrAlreadyScheduled) {
		t.Fatalf("duplicate submit err = %v, want ErrAlreadyScheduled", err)
	}
	h.next(t).done <- completed()
	await(t, results)

	// After the quantum finishes the PID is submittable again.
	if _, err := scheduler.Submit(context.Background(), "p1", "acme", sched.Normal); err != nil {
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

	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", "acme", sched.Normal)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(context.Background(), "queued", "acme", sched.Normal)

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

	if _, err := scheduler.Submit(context.Background(), "p2", "acme", sched.Normal); !errors.Is(err, sched.ErrClosed) {
		t.Fatalf("submit after close err = %v, want ErrClosed", err)
	}
	// The blocker yielded warm; Close deactivated it on the way out.
	if got := h.deactivated(); len(got) != 1 || got[0] != "blocker" {
		t.Fatalf("deactivations = %v, want [blocker]", got)
	}
}

func TestStopDequeuesQueuedWork(t *testing.T) {
	h := newHarness()
	scheduler, err := sched.New(h.config())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit(context.Background(), "blocker", "acme", sched.Normal)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(context.Background(), "queued", "acme", sched.Normal)

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
	if _, err := scheduler.Submit(context.Background(), "queued", "acme", sched.Normal); err != nil {
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

	results, _ := scheduler.Submit(context.Background(), "p1", "acme", sched.Normal)
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
	blockerResults, _ := scheduler.Submit(submitCtx, "blocker", "acme", sched.Normal)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit(submitCtx, "queued", "acme", sched.Normal)
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
