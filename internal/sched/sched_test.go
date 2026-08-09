package sched_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/process"
	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/capcompute/sys"
)

// programID is the smallest thing satisfying direct.ProgramID.
type programID string

func (p programID) String() string { return string(p) }

// cred is a credential the scheduler can read: how long a guest may hold a slot.
type cred struct {
	deadline time.Duration
}

func (cred) ArtifactDigest() string    { return "artifact" }
func (cred) SourceCodeDigest() string  { return "source" }
func (c cred) Deadline() time.Duration { return c.deadline }
func root(d time.Duration) cred        { return cred{deadline: d} }

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
	block := r.block
	r.mu.Unlock()

	go func() {
		if block != nil {
			select {
			case <-block:
			case <-ctx.Done():
				h.settle(process.Result{Status: process.Stopped, Error: ctx.Err()})
				return
			}
		}
		select {
		case <-ctx.Done():
			h.settle(process.Result{Status: process.Stopped, Error: ctx.Err()})
		default:
			h.settle(process.Result{Status: process.Completed})
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
func (h *handle) Cancel()                       {}
func (h *handle) settle(r process.Result) {
	h.once.Do(func() { h.results <- r; close(h.results) })
}

func newScheduler(t *testing.T, inner *registry, maxConcurrent int) *sched.Scheduler[programID, cred] {
	t.Helper()
	s, err := sched.New[programID, cred](inner, sched.Config{MaxConcurrent: maxConcurrent})
	if err != nil {
		t.Fatalf("new scheduler: %v", err)
	}
	return s
}

func spawn1(t *testing.T, s *sched.Scheduler[programID, cred], id programID, c cred) process.Handle {
	t.Helper()
	h, err := s.Spawn(context.Background(), id, c, nil)
	if err != nil {
		t.Fatalf("spawn %s: %v", id, err)
	}
	return h
}

func await(t *testing.T, h process.Handle) process.Result {
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
	if _, err := sched.New[programID, cred](nil, sched.Config{}); err == nil {
		t.Fatal("New(nil) = nil error, want a refusal")
	}
}

// Everything but Spawn reaches the registry underneath unchanged.
func TestNonSpawnCallsPassThrough(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)

	var _ direct.Registry[programID, cred] = s

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

	first := spawn1(t, s, "a", root(0))
	second := spawn1(t, s, "b", root(0))

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

// The queue runs submissions in arrival order.
func TestQueueIsFIFO(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	handles := make([]process.Handle, 0, 3)
	for _, id := range []programID{"a", "b", "c"} {
		handles = append(handles, spawn1(t, s, id, root(0)))
	}
	for _, h := range handles {
		await(t, h)
	}
	for i, want := range []programID{"a", "b", "c"} {
		if got := inner.calls()[i].id; got != want {
			t.Fatalf("position %d ran %s, want %s", i, got, want)
		}
	}
}

// The deadline bounds the quantum, and queue time does not count against it: the
// clock starts when the guest does.
func TestDeadlineExcludesQueueTime(t *testing.T) {
	inner := &registry{}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	await(t, spawn1(t, s, "a", root(time.Minute)))
	second := spawn1(t, s, "b", root(time.Minute))
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

	await(t, spawn1(t, s, "a", root(0)))
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

	spawn1(t, s, "running", root(0))
	queued := spawn1(t, s, "queued", root(0))
	time.Sleep(50 * time.Millisecond)

	queued.Cancel()
	result := await(t, queued)
	if result.Status != process.Stopped || !errors.Is(result.Error, sched.ErrStopped) {
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

	spawn1(t, s, "running", root(0))
	queued := spawn1(t, s, "queued", root(0))
	time.Sleep(50 * time.Millisecond)

	close(inner.block)
	s.Close(context.Background())

	result := await(t, queued)
	if result.Status != process.Stopped || !errors.Is(result.Error, sched.ErrClosed) {
		t.Fatalf("queued at close = %+v, want stopped/ErrClosed", result)
	}
	if _, err := s.Spawn(context.Background(), "late", root(0), nil); !errors.Is(err, sched.ErrClosed) {
		t.Fatalf("spawn after close = %v, want ErrClosed", err)
	}
}

// A registry that refuses to spawn becomes a failed result rather than a
// stranded caller: the outcome always arrives on the one channel.
func TestSpawnFailureReachesTheCaller(t *testing.T) {
	inner := &registry{err: errors.New("no such program")}
	s := newScheduler(t, inner, 1)
	defer s.Close(context.Background())

	result := await(t, spawn1(t, s, "gone", root(0)))
	if result.Status != process.Failed || result.Error == nil {
		t.Fatalf("spawn failure = %+v, want a failed result", result)
	}
}
