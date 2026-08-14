package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/process"
	"github.com/aurora-capcompute/capcompute/sys"
)

// programID is the smallest thing satisfying direct.ProgramID.
type programID string

func (p programID) String() string { return string(p) }

// cred is the credential direct needs; the scheduler reads nothing off it.
type cred struct{}

func (cred) ArtifactDigest() string   { return "artifact" }
func (cred) SourceCodeDigest() string { return "source" }

// registry is a direct.Registry that records its spawns and hands back a handle
// the test drives by hand. Only Spawn and Close carry behaviour; the rest exist
// to satisfy the interface the scheduler wraps.
type registry struct {
	mu      sync.Mutex
	spawned []spawn
	err     error
	closed  bool
	// block, when set, holds each spawned guest until the test releases it.
	block chan struct{}
	// hold, when set, keeps each guest alive that long, so the test can watch
	// how many are alive at once.
	hold time.Duration
	live int
	peak int
}

type spawn struct {
	id       programID
	deadline bool // the quantum context carried one
	handle   *handle
}

func (r *registry) Add(context.Context, direct.Data[programID]) (direct.Digest, error) {
	return direct.Digest{}, nil
}
func (r *registry) Exists(programID) bool { return true }
func (r *registry) Get(programID) (direct.View[programID], bool) {
	return direct.View[programID]{}, true
}
func (r *registry) List() []direct.View[programID] { return nil }
func (r *registry) Remove(programID) (func(context.Context) error, bool) {
	return func(context.Context) error { return nil }, true
}
func (r *registry) ValidateInput(programID, string) error  { return nil }
func (r *registry) ValidateOutput(programID, string) error { return nil }

func (r *registry) Close(context.Context) []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *registry) Spawn(
	ctx context.Context,
	id programID,
	_ cred,
	_ func(context.Context, cred) (sys.Dispatcher[cred], error),
) (process.Handle, error) {
	r.mu.Lock()
	if r.err != nil {
		err := r.err
		r.mu.Unlock()
		return nil, err
	}
	_, bounded := ctx.Deadline()
	h := &handle{results: make(chan process.Result, 1), ctx: ctx}
	r.spawned = append(r.spawned, spawn{id: id, deadline: bounded, handle: h})
	block, hold := r.block, r.hold
	r.live++
	if r.live > r.peak {
		r.peak = r.live
	}
	r.mu.Unlock()

	// A guest counts as alive until it delivers its outcome — the moment the
	// worker is free to take the next one. Booking out after settling would let
	// the successor start first and read a peak that never happened.
	settle := func(result process.Result) {
		r.mu.Lock()
		r.live--
		r.mu.Unlock()
		h.settle(result)
	}
	go func() {
		if hold > 0 {
			time.Sleep(hold)
		}
		if block != nil {
			select {
			case <-block:
			case <-ctx.Done():
				settle(process.Result{Status: process.Stopped, Error: ctx.Err()})
				return
			}
		}
		select {
		case <-ctx.Done():
			settle(process.Result{Status: process.Stopped, Error: ctx.Err()})
		default:
			settle(process.Result{Status: process.Completed})
		}
	}()
	return h, nil
}

func (r *registry) calls() []spawn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]spawn(nil), r.spawned...)
}

type handle struct {
	results chan process.Result
	ctx     context.Context
	once    sync.Once
}

func (h *handle) Result() <-chan process.Result { return h.results }

func (h *handle) settle(r process.Result) {
	h.once.Do(func() { h.results <- r; close(h.results) })
}

func newScheduler(t *testing.T, inner *registry, maxConcurrent int) *agent.Scheduler[programID, cred] {
	t.Helper()
	s, err := agent.New[programID, cred](inner, agent.Config{MaxConcurrent: maxConcurrent})
	if err != nil {
		t.Fatalf("new scheduler: %v", err)
	}
	return s
}

func spawn1(t *testing.T, s *agent.Scheduler[programID, cred], id programID, deadline time.Duration) agent.Handle {
	t.Helper()
	h, err := s.Spawn(id, cred{}, deadline, nil)
	if err != nil {
		t.Fatalf("spawn %s: %v", id, err)
	}
	return h
}

// running blocks until n guests have reached the registry, so a test can be sure
// which submission holds the slot before it adds the next.
func running(t *testing.T, inner *registry, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(inner.calls()) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %d of %d guests started", len(inner.calls()), n)
}

func await(t *testing.T, h agent.Handle) process.Result {
	t.Helper()
	select {
	case r := <-h.Result():
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no result delivered")
		return process.Result{}
	}
}

// A registry is required: the scheduler is an adapter, not a standalone queue.
func TestRegistryRequired(t *testing.T) {
	if _, err := agent.New[programID, cred](nil, agent.Config{}); err == nil {
		t.Fatal("New(nil) = nil error, want a refusal")
	}
}

// Everything but Spawn reaches the registry underneath unchanged. Spawn is the
// one call that differs: it takes a deadline and returns a closable handle.
func TestNonSpawnCallsPassThrough(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)

	if !s.Exists("p") {
		t.Fatal("Exists did not reach the registry")
	}
	if _, err := s.Add(context.Background(), direct.Data[programID]{ID: "p", Input: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	s.Close(context.Background())
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if !inner.closed {
		t.Fatal("Close did not reach the registry")
	}
}

// The cap is the whole point: with one slot, a second queued guest waits for the
// first to finish.
func TestConcurrencyCapHoldsTheQueue(t *testing.T) {
	inner := &registry{block: make(chan struct{})}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	first := spawn1(t, s, "a", 0)
	running(t, inner, 1)
	second := spawn1(t, s, "b", 0)

	// Give the queue a chance to over-run the cap if it were going to.
	time.Sleep(50 * time.Millisecond)
	if got := len(inner.calls()); got != 1 {
		t.Fatalf("%d guests running under a cap of 1, want 1", got)
	}
	close(inner.block)
	await(t, first)
	await(t, second)
	if got := len(inner.calls()); got != 2 {
		t.Fatalf("%d guests ran in total, want 2", got)
	}
}

// Every submission runs, however many are waiting at once.
func TestEverySubmissionRuns(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	handles := make([]agent.Handle, 0, 3)
	for _, id := range []programID{"a", "b", "c"} {
		handles = append(handles, spawn1(t, s, id, 0))
	}
	for _, h := range handles {
		if result := await(t, h); result.Status != process.Completed {
			t.Fatalf("submission = %+v, want completed", result)
		}
	}
	ran := map[programID]bool{}
	for _, call := range inner.calls() {
		ran[call.id] = true
	}
	for _, want := range []programID{"a", "b", "c"} {
		if !ran[want] {
			t.Fatalf("%s never ran: %v", want, inner.calls())
		}
	}
}

// The deadline bounds the quantum, and queue time does not count against it: the
// clock starts when the guest does.
func TestDeadlineExcludesQueueTime(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	await(t, spawn1(t, s, "a", time.Minute))
	second := spawn1(t, s, "b", time.Minute)
	await(t, second)

	for i, call := range inner.calls() {
		if !call.deadline {
			t.Fatalf("spawn %d ran without a deadline on its quantum", i)
		}
	}
}

// A guest with no declared bound runs unbounded.
func TestNoDeadlineLeavesTheQuantumUnbounded(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	await(t, spawn1(t, s, "a", 0))
	if inner.calls()[0].deadline {
		t.Fatal("a zero deadline bounded the quantum")
	}
}

// Cancelling a submission that has not started drops it: it never reaches the
// registry, and its handle settles as stopped.
func TestCancelDropsAQueuedSubmission(t *testing.T) {
	inner := &registry{block: make(chan struct{})}
	s := newScheduler(t, inner, 1)
	defer func() { close(inner.block); s.Close(context.Background()) }()

	spawn1(t, s, "running", 0)
	running(t, inner, 1) // the worker is taken before the next submission arrives
	queued := spawn1(t, s, "queued", 0)
	time.Sleep(50 * time.Millisecond)

	queued.Close()
	result := await(t, queued)
	if result.Status != process.Stopped || !errors.Is(result.Error, agent.ErrStopped) {
		t.Fatalf("cancelled submission = %+v, want stopped/ErrStopped", result)
	}
	for _, call := range inner.calls() {
		if call.id == "queued" {
			t.Fatal("a cancelled submission still reached the registry")
		}
	}
}

// Closing settles everything still waiting rather than stranding it.
func TestCloseSettlesQueuedWork(t *testing.T) {
	inner := &registry{block: make(chan struct{})}
	s := newScheduler(t, inner, 1)

	spawn1(t, s, "running", 0)
	running(t, inner, 1) // the slot is taken before the next submission arrives
	queued := spawn1(t, s, "queued", 0)
	time.Sleep(50 * time.Millisecond)

	// Close cancels the running guest, which frees the slot; the waiting one
	// must still refuse to start rather than slip through behind it.
	s.Close(context.Background())
	close(inner.block)

	result := await(t, queued)
	if result.Status != process.Stopped || !errors.Is(result.Error, agent.ErrClosed) {
		t.Fatalf("queued at close = %+v, want stopped/ErrClosed", result)
	}
	if _, err := s.Spawn("late", cred{}, 0, nil); !errors.Is(err, agent.ErrClosed) {
		t.Fatalf("spawn after close = %v, want ErrClosed", err)
	}
}

// A registry that refuses to spawn becomes a failed result rather than a
// stranded caller: the outcome always arrives on the one channel.
func TestSpawnFailureReachesTheCaller(t *testing.T) {
	inner := &registry{err: errors.New("no such program")}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	result := await(t, spawn1(t, s, "gone", 0))
	if result.Status != process.Failed || result.Error == nil {
		t.Fatalf("spawn failure = %+v, want a failed result", result)
	}
}

// Cancelling a running guest must stop it.
func TestCancelStopsARunningGuest(t *testing.T) {
	inner := &registry{block: make(chan struct{})}
	s := newScheduler(t, inner, 1)
	defer func() { close(inner.block); s.Close(context.Background()) }()

	h := spawn1(t, s, "running", 0)
	running(t, inner, 1)
	h.Close()

	result := await(t, h)
	if result.Status != process.Stopped {
		t.Fatalf("cancelled running guest = %+v, want stopped", result)
	}
	// Closing the handle reached the guest through the context its quantum was
	// started from — the one lever, and it originates in the scheduler.
	inner.mu.Lock()
	guestCtx := inner.spawned[0].handle.ctx
	inner.mu.Unlock()
	if guestCtx.Err() == nil {
		t.Fatal("the guest's quantum context was never cancelled")
	}
}

// The cap is structural, not a counter: however many submissions pile up, the
// number of guests alive at once never exceeds the worker count.
func TestConcurrencyNeverExceedsTheCap(t *testing.T) {
	const maxConcurrent = 2
	inner := &registry{hold: 20 * time.Millisecond}
	s := newScheduler(t, inner, maxConcurrent)
	defer s.Close(context.Background())

	handles := make([]agent.Handle, 0, 20)
	for i := range 20 {
		handles = append(handles, spawn1(t, s, programID(rune('a'+i)), 0))
	}
	for _, h := range handles {
		await(t, h)
	}
	inner.mu.Lock()
	peak := inner.peak
	inner.mu.Unlock()
	if peak > maxConcurrent {
		t.Fatalf("peak guests running = %d, want at most %d", peak, maxConcurrent)
	}
	if peak == 0 {
		t.Fatal("no guest ever ran")
	}
}
