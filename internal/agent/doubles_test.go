package agent

// Test doubles shared by this package's tests. The module ships no concrete
// stores — tests carry their own in-memory event log, lease table, and
// process table, mirroring the assembly ingredients a real application
// injects.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// cognitionGrants are the leaf grants a fake-provider process needs so the
// reconciliation guard (which makes the manifest authoritative over the chain's
// advertised capabilities) admits its chain. Every fake provider in these tests
// advertises the agent's own cognition tool — core.openaiApi, hidden, the tool
// the guest calls to think — and some also advertise domain tools; the manifest
// must grant that advertised set, exactly as a real assembly does. `extra` names
// the domain tools a given fake also advertises.
func cognitionGrants(extra ...string) []Syscall {
	grants := []Syscall{{Syscall: "core.openaiApi", Hidden: true}}
	for _, name := range extra {
		grants = append(grants, Syscall{Syscall: name})
	}
	return grants
}

// memLog is an in-memory eventlog.Log.
type memLog struct {
	mu      sync.RWMutex
	streams map[eventlog.Scope][]eventlog.Event
}

func newMemLog() *memLog {
	return &memLog{streams: make(map[eventlog.Scope][]eventlog.Event)}
}

func (m *memLog) Append(_ context.Context, scope eventlog.Scope, events ...eventlog.Event) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := m.streams[scope]
	head := uint64(len(existing))
	if len(events) == 0 {
		return head, nil
	}
	appended := make([]eventlog.Event, len(events))
	for i, ev := range events {
		head++
		ev.Seq = head
		ev.Data = append([]byte(nil), ev.Data...)
		appended[i] = ev
	}
	m.streams[scope] = append(existing, appended...)
	return head, nil
}

func (m *memLog) Read(_ context.Context, scope eventlog.Scope, after uint64) ([]eventlog.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stream := m.streams[scope]
	if after >= uint64(len(stream)) {
		return nil, nil
	}
	out := make([]eventlog.Event, 0, uint64(len(stream))-after)
	for _, ev := range stream[after:] {
		ev.Data = append([]byte(nil), ev.Data...)
		out = append(out, ev)
	}
	return out, nil
}

func (m *memLog) Streams(_ context.Context, tenantID string) ([]eventlog.Scope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []eventlog.Scope
	for scope, stream := range m.streams {
		if scope.TenantID == tenantID && len(stream) > 0 {
			out = append(out, scope)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out, nil
}

// Journal-building helpers: append records directly with the same hash chain
// the tape computes, so journals built here satisfy journaled.Verify.

type testingT interface {
	Helper()
	Fatalf(string, ...any)
}

func testHeader() journaled.Header {
	return journaled.Header{ABI: sys.ABIVersion, Program: "test-program", Process: "proc1"}
}

func ensureHeader(t testingT, journal journaled.Journal) {
	t.Helper()
	if _, ok, err := journal.Header(); err != nil {
		t.Fatalf("header: %v", err)
	} else if !ok {
		if err := journal.SetHeader(testHeader()); err != nil {
			t.Fatalf("set header: %v", err)
		}
	}
}

// appendPair appends one completed syscall — an intent/completion record pair.
func appendPair(t testingT, journal journaled.Journal, syscall sys.Syscall, result sys.SyscallResult) {
	t.Helper()
	appendIntent(t, journal, syscall)
	appendCompletion(t, journal, result)
}

func appendIntent(t testingT, journal journaled.Journal, syscall sys.Syscall) {
	t.Helper()
	ensureHeader(t, journal)
	position := journal.Length()
	recorded := syscall.Copy()
	appendRecord(t, journal, journaled.Record{
		Position: position,
		Kind:     journaled.KindIntent,
		Syscall:  &recorded,
	})
}

func appendCompletion(t testingT, journal journaled.Journal, result sys.SyscallResult) {
	t.Helper()
	position := journal.Length()
	recorded := result.Copy()
	appendRecord(t, journal, journaled.Record{
		Position: position,
		Kind:     journaled.KindCompletion,
		Result:   &recorded,
	})
}

func appendRecord(t testingT, journal journaled.Journal, rec journaled.Record) {
	t.Helper()
	prev, err := prevDigest(journal, rec.Position)
	if err != nil {
		t.Fatalf("prev hash at %d: %v", rec.Position, err)
	}
	rec.PrevHash = prev
	if err := journal.Append(rec); err != nil {
		t.Fatalf("append record %d: %v", rec.Position, err)
	}
}

// prevDigest mirrors the tape's chain computation: the digest of the previous
// record, or of the header at position 0.
func prevDigest(journal journaled.Journal, position int) (string, error) {
	if position == 0 {
		header, ok, err := journal.Header()
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("journal has no header")
		}
		return jsonDigest(header)
	}
	prev, err := journal.Load(position - 1)
	if err != nil {
		return "", err
	}
	return jsonDigest(prev)
}

func jsonDigest(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
