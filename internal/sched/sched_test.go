package sched_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
)

// instance stands in for whatever the machine runs. That the queue's tests can
// name it with a two-field struct — no processor, no guest, no wasm — is the
// point of the Machine seam: the queue never looks inside an instance.
type instance struct{ pid string }

// quantum is one in-flight Resume the test controls: the machine is blocked on
// `done` until the test finishes the quantum with a result.
type quantum struct {
	pid  string
	ctx  context.Context
	done chan sched.Result
}

// harness plays both halves of the seam: it activates on demand, and its
// machine parks each quantum on a channel until the test resolves it.
type harness struct {
	mu            sync.Mutex
	activations   map[string]int
	activationErr map[string]error
	releases      []string // pids released, in order
	running       chan quantum
}

func newHarness() *harness {
	return &harness{
		activations:   make(map[string]int),
		activationErr: make(map[string]error),
		running:       make(chan quantum, 16),
	}
}

func (h *harness) config() sched.Config[string, *instance] {
	return sched.Config[string, *instance]{Activator: h, Machine: h}
}

func (h *harness) Activate(_ context.Context, pid string) (*instance, error) {
	h.mu.Lock()
	h.activations[pid]++
	err := h.activationErr[pid]
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &instance{pid: pid}, nil
}

func (h *harness) Resume(ctx context.Context, running *instance) (sched.Result, error) {
	started := quantum{pid: running.pid, ctx: ctx, done: make(chan sched.Result, 1)}
	h.running <- started
	select {
	case result := <-started.done:
		return result, nil
	case <-ctx.Done():
		return sched.Result{Status: sched.Stopped, Err: ctx.Err()}, nil
	}
}

func (h *harness) Release(released *instance) {
	h.mu.Lock()
	h.releases = append(h.releases, released.pid)
	h.mu.Unlock()
}

func (h *harness) failActivation(pid string, err error) {
	h.mu.Lock()
	h.activationErr[pid] = err
	h.mu.Unlock()
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

func completed() sched.Result { return sched.Result{Status: sched.Completed} }

func yielded() sched.Result { return sched.Result{Status: sched.Yielded} }

func await(t *testing.T, results <-chan sched.Result) sched.Result {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("no result delivered")
		panic("unreachable")
	}
}

func newScheduler(t *testing.T, config sched.Config[string, *instance]) *sched.Scheduler[string, *instance] {
	t.Helper()
	scheduler, err := sched.New(config)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return scheduler
}

// Both halves of the seam are required: a queue with no machine has nothing to
// run on, and one with no activator has nothing to run.
func TestBothHalvesOfTheSeamRequired(t *testing.T) {
	h := newHarness()
	for name, config := range map[string]sched.Config[string, *instance]{
		"no activator": {Machine: h},
		"no machine":   {Activator: h},
	} {
		if _, err := sched.New(config); err == nil {
			t.Fatalf("%s: New succeeded, want an error", name)
		}
	}
}

// One quantum end to end: activate, resume, deliver, release.
func TestQuantumLifecycle(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	results, err := scheduler.Submit("p1", 0)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	started := h.next(t)
	started.done <- completed()
	if got := await(t, results).Status; got != sched.Completed {
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
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		results, err := scheduler.Submit("p1", 0)
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

// An activation that fails ends the quantum the same way any other outcome
// does — a result on the submission's channel, not a lost submission. Nothing
// is released, because nothing was made.
func TestActivationFailureIsAFailedResult(t *testing.T) {
	h := newHarness()
	h.failActivation("p1", errors.New("program withdrawn"))
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	results, err := scheduler.Submit("p1", 0)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	result := await(t, results)
	if result.Status != sched.Failed {
		t.Fatalf("status = %s, want failed", result.Status)
	}
	if !strings.Contains(result.Err.Error(), "program withdrawn") {
		t.Fatalf("err = %v, want the activation's cause", result.Err)
	}
	if released := h.released(); len(released) != 0 {
		t.Fatalf("released = %v, want nothing released for an instance that was never made", released)
	}
	// The slot was handed back, so the queue keeps moving.
	if _, err := scheduler.Submit("p2", 0); err != nil {
		t.Fatalf("submit after a failed activation: %v", err)
	}
	h.next(t).done <- completed()
}

// The deadline bounds the quantum once it starts, and surfaces as a stopped
// result carrying context.DeadlineExceeded — which the runtime above reads to
// tell "ran out of time" (resumable) from "was told to stop" (an abort).
func TestDeadlineBoundsTheQuantum(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	results, err := scheduler.Submit("p1", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	h.next(t) // never finished: the deadline must end it
	result := await(t, results)
	if result.Status != sched.Stopped {
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
// the instance does. A submission that waits behind a blocker still gets its
// full budget.
func TestDeadlineExcludesQueueTime(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit("blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit("queued", time.Minute)

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
	scheduler := newScheduler(t, h.config()) // MaxConcurrent defaults to 1
	defer scheduler.Close()

	var pending []<-chan sched.Result
	for _, pid := range []string{"first", "second", "third"} {
		results, err := scheduler.Submit(pid, 0)
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
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	results, _ := scheduler.Submit("p1", 0)
	if _, err := scheduler.Submit("p1", 0); !errors.Is(err, sched.ErrAlreadyScheduled) {
		t.Fatalf("duplicate submit err = %v, want ErrAlreadyScheduled", err)
	}
	h.next(t).done <- completed()
	await(t, results)

	// After the quantum finishes the PID is submittable again.
	if _, err := scheduler.Submit("p1", 0); err != nil {
		t.Fatalf("resubmit: %v", err)
	}
	h.next(t).done <- completed()
}

func TestCloseStopsQueuedWork(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())

	blockerResults, _ := scheduler.Submit("blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit("queued", 0)

	closed := make(chan struct{})
	go func() {
		scheduler.Close()
		close(closed)
	}()
	if result := await(t, queuedResults); result.Status != sched.Stopped || !errors.Is(result.Err, sched.ErrClosed) {
		t.Fatalf("queued result = %+v, want stopped/ErrClosed", result)
	}
	blocker.done <- yielded()
	await(t, blockerResults)
	<-closed

	if _, err := scheduler.Submit("p2", 0); !errors.Is(err, sched.ErrClosed) {
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
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit("blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit("queued", 0)

	if !scheduler.Stop("queued") {
		t.Fatal("Stop(queued) = false")
	}
	if result := await(t, queuedResults); result.Status != sched.Stopped || !errors.Is(result.Err, sched.ErrStopped) {
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
	if _, err := scheduler.Submit("queued", 0); err != nil {
		t.Fatalf("resubmit after stop: %v", err)
	}
	h.next(t).done <- completed()
}

func TestStopCancelsRunningQuantum(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	results, _ := scheduler.Submit("p1", 0)
	h.next(t) // running, never finished by the test
	if !scheduler.Stop("p1") {
		t.Fatal("Stop(p1) = false")
	}
	result := await(t, results)
	if result.Status != sched.Stopped || !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("cancelled result = %+v", result)
	}
}

// Regression: a quantum started by a *finishing* quantum's reschedule must not
// inherit that quantum's dying context — every queued quantum derives from the
// scheduler's root, not from whatever happened to trigger it.
func TestQuantumContextOutlivesItsTrigger(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	blockerResults, _ := scheduler.Submit("blocker", 0)
	blocker := h.next(t)
	queuedResults, _ := scheduler.Submit("queued", 0)

	blocker.done <- completed()
	await(t, blockerResults)

	queued := h.next(t) // started by the blocker's finish()
	time.Sleep(20 * time.Millisecond)
	if queued.ctx.Err() != nil {
		t.Fatalf("chained quantum's context died with its trigger: %v", queued.ctx.Err())
	}
	queued.done <- completed()
	if result := await(t, queuedResults); result.Status != sched.Completed {
		t.Fatalf("chained quantum result = %+v, want completed", result)
	}
}

// Quanta hang off Config.Parent, so the owner bounds the queue's work with the
// same lifetime it uses for everything else instead of the queue inventing one.
func TestParentContextBoundsQuanta(t *testing.T) {
	h := newHarness()
	parent, cancelParent := context.WithCancel(context.Background())
	config := h.config()
	config.Parent = parent
	scheduler := newScheduler(t, config)
	defer scheduler.Close()

	results, _ := scheduler.Submit("p1", 0)
	h.next(t)
	cancelParent()

	result := await(t, results)
	if result.Status != sched.Stopped || !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("result after the parent was cancelled = %+v, want stopped/Canceled", result)
	}
}

// Work delegated from inside a running quantum runs off the queue: Run neither
// waits for a slot nor occupies one, so a parent blocked on a child cannot
// deadlock against MaxConcurrent.
func TestRunTakesNoSlot(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config()) // MaxConcurrent defaults to 1
	defer scheduler.Close()

	parentResults, _ := scheduler.Submit("parent", 0)
	parent := h.next(t) // holds the only slot

	childResults, cancel := scheduler.Run(parent.ctx, "child", 0)
	defer cancel()
	child := h.next(t)
	if child.pid != "child" {
		t.Fatalf("ran %q, want the delegated child", child.pid)
	}
	child.done <- completed()
	if got := await(t, childResults).Status; got != sched.Completed {
		t.Fatalf("child status = %s, want completed", got)
	}
	if released := h.released(); len(released) != 1 || released[0] != "child" {
		t.Fatalf("released = %v, want the child's instance released with its quantum", released)
	}

	parent.done <- completed()
	await(t, parentResults)
}

// A delegated quantum inherits its parent's *remaining* budget rather than a
// fresh copy of its own: a spawn tree is one parent split into pieces, and one
// deadline bounds all of it. With no parent budget in flight — a rollback
// re-drive — it falls back to its own, so a quantum is never unbounded.
func TestRunInheritsTheParentBudget(t *testing.T) {
	h := newHarness()
	scheduler := newScheduler(t, h.config())
	defer scheduler.Close()

	parentResults, _ := scheduler.Submit("parent", time.Minute)
	parent := h.next(t)

	_, cancelChild := scheduler.Run(parent.ctx, "child", time.Hour)
	child := h.next(t)
	deadline, ok := child.ctx.Deadline()
	if !ok || time.Until(deadline) > time.Minute {
		t.Fatalf("child budget = %v, want the parent's remaining minute, not its own hour", time.Until(deadline))
	}
	cancelChild()

	_, cancelOrphan := scheduler.Run(context.Background(), "orphan", 30*time.Second)
	orphan := h.next(t)
	if deadline, ok := orphan.ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
		t.Fatal("a re-drive with no parent budget must fall back to its own deadline")
	}
	cancelOrphan()

	parent.done <- completed()
	await(t, parentResults)
}
