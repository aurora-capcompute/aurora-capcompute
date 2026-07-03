package eventlog

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"
)

// memoryLog is this package's test double for the Log contract. The module
// deliberately ships no concrete log — durable and in-memory implementations
// are assembly ingredients owned by store modules — so the contract tests
// carry their own reference implementation.
type memoryLog struct {
	mu      sync.RWMutex
	streams map[Scope][]Event
}

func newMemoryLog() *memoryLog {
	return &memoryLog{streams: make(map[Scope][]Event)}
}

func (m *memoryLog) Append(_ context.Context, scope Scope, events ...Event) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := m.streams[scope]
	head := uint64(len(existing))
	if len(events) == 0 {
		return head, nil
	}
	appended := make([]Event, len(events))
	for i, ev := range events {
		head++
		ev.Seq = head
		ev.Data = append([]byte(nil), ev.Data...)
		appended[i] = ev
	}
	m.streams[scope] = append(existing, appended...)
	return head, nil
}

func (m *memoryLog) Read(_ context.Context, scope Scope, after uint64) ([]Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stream := m.streams[scope]
	if after >= uint64(len(stream)) {
		return nil, nil
	}
	out := make([]Event, 0, uint64(len(stream))-after)
	for _, ev := range stream[after:] {
		ev.Data = append([]byte(nil), ev.Data...)
		out = append(out, ev)
	}
	return out, nil
}

func (m *memoryLog) Streams(_ context.Context, tenantID string) ([]Scope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Scope
	for scope, stream := range m.streams {
		if scope.TenantID == tenantID && len(stream) > 0 {
			out = append(out, scope)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ThreadID < out[j].ThreadID })
	return out, nil
}

var _ Log = (*memoryLog)(nil)

func TestAppendAssignsContiguousSeq(t *testing.T) {
	log := newMemoryLog()
	ctx := context.Background()
	scope := Scope{TenantID: "t", ThreadID: "th"}

	head, err := log.Append(ctx, scope,
		Event{Kind: "run.created"},
		Event{Kind: "run.started"},
	)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if head != 2 {
		t.Fatalf("head = %d, want 2", head)
	}
	events, err := log.Read(ctx, scope, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 2 || events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("unexpected events %+v", events)
	}
	// A second append continues the sequence.
	head, err = log.Append(ctx, scope, Event{Kind: "run.finished"})
	if err != nil || head != 3 {
		t.Fatalf("second append head = %d, err = %v", head, err)
	}
}

func TestReadAfterIsExclusive(t *testing.T) {
	log := newMemoryLog()
	ctx := context.Background()
	scope := Scope{TenantID: "t", ThreadID: "th"}
	_, _ = log.Append(ctx, scope, Event{Kind: "a"}, Event{Kind: "b"}, Event{Kind: "c"})

	tail, err := log.Read(ctx, scope, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 || tail[0].Kind != "b" || tail[1].Kind != "c" {
		t.Fatalf("read after 1 = %+v", tail)
	}
	if rest, _ := log.Read(ctx, scope, 3); len(rest) != 0 {
		t.Fatalf("read past head returned %d events", len(rest))
	}
}

func TestStoredEventsAreIsolatedFromCallerMutation(t *testing.T) {
	log := newMemoryLog()
	ctx := context.Background()
	scope := Scope{TenantID: "t", ThreadID: "th"}
	data := json.RawMessage(`{"x":1}`)
	if _, err := log.Append(ctx, scope, Event{Kind: "a", Data: data}); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X' // mutate the caller's slice after appending

	got, _ := log.Read(ctx, scope, 0)
	if string(got[0].Data) != `{"x":1}` {
		t.Fatalf("stored event reflected caller mutation: %s", got[0].Data)
	}
	got[0].Data[0] = 'Y' // mutate the read copy
	again, _ := log.Read(ctx, scope, 0)
	if string(again[0].Data) != `{"x":1}` {
		t.Fatalf("read copy aliased stored event: %s", again[0].Data)
	}
}

func TestStreamsListsTenantThreads(t *testing.T) {
	log := newMemoryLog()
	ctx := context.Background()
	_, _ = log.Append(ctx, Scope{"t1", "b"}, Event{Kind: "x"})
	_, _ = log.Append(ctx, Scope{"t1", "a"}, Event{Kind: "x"})
	_, _ = log.Append(ctx, Scope{"t2", "c"}, Event{Kind: "x"})

	streams, err := log.Streams(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 2 || streams[0].ThreadID != "a" || streams[1].ThreadID != "b" {
		t.Fatalf("streams = %+v, want sorted [a b] for t1", streams)
	}
}
