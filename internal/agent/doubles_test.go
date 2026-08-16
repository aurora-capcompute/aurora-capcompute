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
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// cognitionGrants are the leaf grants a fake-provider process needs so the
// reconciliation guard (which makes the manifest authoritative over the chain's
// advertised capabilities) admits its chain. Every fake provider in these tests
// advertises the agent's own cognition tool — core.openaiApi, hidden, the tool
// the guest calls to think — and some also advertise domain tools; the manifest
// must grant that advertised set, exactly as a real assembly does. `extra` names
// the domain tools a given fake also advertises.
func cognitionGrants(extra ...string) []manifest.Syscall {
	grants := []manifest.Syscall{{Syscall: "core.openaiApi", Hidden: true}}
	for _, name := range extra {
		grants = append(grants, manifest.Syscall{Syscall: name})
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

// Journal-building helpers: append records directly in the same shape the tape
// writes, so journals built here satisfy journaled.Verify.

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
	if err := journal.Append(rec); err != nil {
		t.Fatalf("append record %d: %v", rec.Position, err)
	}
}

func jsonDigest(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type testDispatchers struct {
	normalized []string
}

func (p *testDispatchers) ValidateConfig(syscall string, _ json.RawMessage) error {
	if syscall == "unknown" {
		return fmt.Errorf("unsupported syscall")
	}
	p.normalized = append(p.normalized, syscall)
	return nil
}

func (*testDispatchers) NewDispatcher(context.Context, ProcessContext, manifest.Manifest) (*capability.Table, error) {
	return capability.NewTable(), nil
}

// waitForTerminal blocks until a process reaches any final state.
func waitForTerminal(t *testing.T, runtime *Runtime, processID string) ProcessSnapshot {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := runtime.GetProcess(processID)
		if err != nil {
			t.Fatalf("get process: %v", err)
		}
		if isTerminal(snap.Status) {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("process did not reach a terminal status within timeout")
	return ProcessSnapshot{}
}

// tableOf indexes a test double's capabilities as single-operation families all
// served by the double itself — the shape registry.Build produces for a real
// assembly, without needing a registry. It exists because a provider now hands
// back the grant table rather than a dispatcher: the routing, the grant set and
// the flow policy all read from one index, so a test that wants a fake driver
// has to say what that index contains.
func tableOf(d sys.Dispatcher[ProcessContext], publish ...capability.Descriptor) *capability.Table {
	table := capability.NewTable()
	for _, published := range publish {
		family := capability.Family{
			Description: published.Description,
			Input:       published.InputSchema,
			Hidden:      published.Hidden,
			Entries: []capability.Entry{{
				Key:     capability.Key{Syscall: published.Name},
				Handler: dispatchAsHandler{d},
			}},
		}
		if err := table.Add(family); err != nil {
			panic(err)
		}
	}
	return table
}

// dispatchAsHandler lets an existing dispatcher double stand in as the handler
// for each of its own capabilities.
type dispatchAsHandler struct {
	d sys.Dispatcher[ProcessContext]
}

func (h dispatchAsHandler) DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	var cred ProcessContext
	return h.d.Dispatch(ctx, cred, call, auth)
}
