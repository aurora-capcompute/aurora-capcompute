package task_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

type proc struct{}

type taskStore struct {
	mu      sync.Mutex
	records map[string]durable.TaskRecord
}

func newTaskStore() *taskStore {
	return &taskStore{records: make(map[string]durable.TaskRecord)}
}

func (s *taskStore) Find(_ context.Context, scope durable.TaskScope, position int, hash string) (durable.TaskRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.Scope == scope && record.JournalPosition == position && record.CallHash == hash {
			return record, true, nil
		}
	}
	return durable.TaskRecord{}, false, nil
}

func (s *taskStore) Create(_ context.Context, record durable.TaskRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.ID]; ok {
		return durable.ErrTaskConflict
	}
	s.records[record.ID] = record
	return nil
}

func (s *taskStore) Get(_ context.Context, _ string, id string) (durable.TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return durable.TaskRecord{}, durable.ErrTaskNotFound
	}
	return record, nil
}

func (s *taskStore) List(_ context.Context, _ string, processID string) ([]durable.TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var records []durable.TaskRecord
	for _, record := range s.records {
		if processID == "" || record.Scope.ProcessID == processID {
			records = append(records, record)
		}
	}
	return records, nil
}

func (s *taskStore) Resolve(_ context.Context, _ string, id string, tokenHash []byte, resolution durable.TaskResolution, now time.Time) (durable.TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return durable.TaskRecord{}, durable.ErrTaskNotFound
	}
	if !hmac.Equal(record.TokenHash, tokenHash) {
		return durable.TaskRecord{}, durable.ErrTaskUnauthorized
	}
	record.State = resolution.Decision
	record.Resolution = resolution
	record.ResolvedAt = &now
	s.records[id] = record
	return record, nil
}

func (s *taskStore) MarkExecuted(_ context.Context, _ string, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return durable.ErrTaskNotFound
	}
	record.State = durable.TaskExecuted
	s.records[id] = record
	return nil
}

// journal is a minimal in-memory journaled.Journal double.
type journal struct {
	header  *journaled.Header
	records []journaled.Record
}

func (j *journal) Header() (journaled.Header, bool, error) {
	if j.header == nil {
		return journaled.Header{}, false, nil
	}
	return *j.header, true, nil
}

func (j *journal) SetHeader(header journaled.Header) error {
	j.header = &header
	return nil
}

func (j *journal) Load(index int) (journaled.Record, error) {
	if index < 0 || index >= len(j.records) {
		return journaled.Record{}, errors.New("record not found")
	}
	return j.records[index], nil
}

func (j *journal) Append(rec journaled.Record) error {
	if rec.Position != len(j.records) {
		return errors.New("invalid position")
	}
	j.records = append(j.records, rec)
	return nil
}

func (j *journal) Length() int { return len(j.records) }

// approvalDispatcher is a driver that requires approval: it yields until the
// dispatch carries an approved Authorization — the runtime's injection seam.
type approvalDispatcher struct {
	executions int
}

func (d *approvalDispatcher) Dispatch(_ context.Context, _ proc, _ sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if auth.Decision == "" {
		return sys.Yield("approve test operation"), nil
	}
	if auth.Decision != durable.TaskApproved {
		return sys.Fail("not approved"), nil
	}
	d.executions++
	return sys.Result(json.RawMessage(`{"ok":true}`)), nil
}

// TestDispatcherPersistsAndResumesYieldedTask drives the full approval cycle
// through the real replay layer: a yield becomes a durable task and leaves the
// intent open; approving the task and re-dispatching re-drives the same intent
// with the stored resolution as its Authorization; a further replay serves the
// committed result from the tape without re-executing the driver.
func TestDispatcherPersistsAndResumesYieldedTask(t *testing.T) {
	store := newTaskStore()
	journal := &journal{}
	next := &approvalDispatcher{}
	scope := durable.TaskScope{TenantID: "tenant", SessionID: "session", ProcessID: "proc", Revision: 1}
	secret := []byte("test-secret")
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Process: "proc"}
	build := func() sys.Dispatcher[proc] {
		taskDispatcher := &task.Dispatcher[proc]{
			Next:        next,
			Store:       store,
			Journal:     journal,
			Scope:       func(proc) durable.TaskScope { return scope },
			TokenSecret: secret,
			TaskTTL:     time.Hour,
		}
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return replay.NewDispatcher[proc](tape, taskDispatcher)
	}
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "net.http", Args: json.RawMessage(`{"url":"https://example.com"}`)}

	result, err := build().Dispatch(context.Background(), proc{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("initial dispatch: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("initial status = %s", result.Status())
	}
	records, err := store.List(context.Background(), scope.TenantID, scope.ProcessID)
	if err != nil || len(records) != 1 {
		t.Fatalf("tasks = %+v, err=%v", records, err)
	}
	// The task's identity is the journaled intent: position 0, the open tail.
	if records[0].JournalPosition != 0 || records[0].Syscall.Name != "net.http" {
		t.Fatalf("task record = %+v", records[0])
	}
	if journal.Length() != 1 {
		t.Fatalf("journal length = %d, want 1 (open intent)", journal.Length())
	}

	token := durable.TaskToken(secret, scope.TenantID, records[0].ID)
	sum := sha256.Sum256([]byte(token))
	if _, err := store.Resolve(context.Background(), scope.TenantID, records[0].ID, sum[:], durable.TaskResolution{
		Decision: durable.TaskApproved,
		Actor:    "tester",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	result, err = build().Dispatch(context.Background(), proc{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("resumed dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult || next.executions != 1 {
		t.Fatalf("resumed status = %s, executions=%d", result.Status(), next.executions)
	}
	if journal.Length() != 2 {
		t.Fatalf("journal length = %d, want 2 (intent + completion)", journal.Length())
	}

	result, err = build().Dispatch(context.Background(), proc{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("replayed dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult || next.executions != 1 {
		t.Fatalf("replayed status = %s, executions=%d", result.Status(), next.executions)
	}
}

type nextFunc func(context.Context, proc, sys.Syscall, sys.Authorization) (sys.SyscallResult, error)

func (f nextFunc) Dispatch(ctx context.Context, cred proc, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	return f(ctx, cred, call, auth)
}

// The TTL bounds waits on a decision; a timer's task carries none, because its
// fire time is its deadline and the timer service resolves it then — a TTL
// equal to the longest timer would expire it at the moment it should fire.
func TestTimerTaskHasNoTTL(t *testing.T) {
	store := newTaskStore()
	journal := &journal{}
	yield := func(context.Context, proc, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
		return sys.Yield("waiting"), nil
	}
	dispatcher := &task.Dispatcher[proc]{
		Next:        nextFunc(yield),
		Store:       store,
		Journal:     journal,
		Scope:       func(proc) durable.TaskScope { return durable.TaskScope{TenantID: "t", ProcessID: "p", Revision: 1} },
		TokenSecret: []byte("test-secret"),
		TaskTTL:     time.Hour,
	}
	for _, name := range []string{sys.SyscallTimer, "net.http"} {
		journal.records = append(journal.records, journaled.Record{Position: journal.Length(), Kind: journaled.KindIntent})
		if _, err := dispatcher.Dispatch(context.Background(), proc{}, sys.Syscall{Name: name, Args: json.RawMessage(`{"duration_seconds":86400}`)}, sys.Authorization{}); err != nil {
			t.Fatalf("dispatch %s: %v", name, err)
		}
	}
	records, _ := store.List(context.Background(), "t", "p")
	for _, record := range records {
		switch {
		case record.Syscall.Name == sys.SyscallTimer && record.ExpiresAt != nil:
			t.Fatalf("timer task expires at %v; its fire time is its deadline", record.ExpiresAt)
		case record.Syscall.Name != sys.SyscallTimer && record.ExpiresAt == nil:
			t.Fatal("an approval task has no deadline")
		}
	}
}

// A denied resolution replays as a classified failure, not an execution.
func TestDispatcherDeniedTask(t *testing.T) {
	store := newTaskStore()
	journal := &journal{}
	next := &approvalDispatcher{}
	scope := durable.TaskScope{TenantID: "tenant", SessionID: "session", ProcessID: "proc", Revision: 1}
	secret := []byte("test-secret")
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Process: "proc"}
	build := func() sys.Dispatcher[proc] {
		taskDispatcher := &task.Dispatcher[proc]{
			Next:        next,
			Store:       store,
			Journal:     journal,
			Scope:       func(proc) durable.TaskScope { return scope },
			TokenSecret: secret,
			TaskTTL:     time.Hour,
		}
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return replay.NewDispatcher[proc](tape, taskDispatcher)
	}
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "net.http", Args: json.RawMessage(`{"url":"https://example.com"}`)}

	if _, err := build().Dispatch(context.Background(), proc{}, call, sys.Authorization{}); err != nil {
		t.Fatalf("initial dispatch: %v", err)
	}
	records, _ := store.List(context.Background(), scope.TenantID, scope.ProcessID)
	token := durable.TaskToken(secret, scope.TenantID, records[0].ID)
	sum := sha256.Sum256([]byte(token))
	if _, err := store.Resolve(context.Background(), scope.TenantID, records[0].ID, sum[:], durable.TaskResolution{
		Decision: durable.TaskDenied,
		Reason:   "not on my watch",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	result, err := build().Dispatch(context.Background(), proc{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("denied dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("denied result = %s/%s, want failed/denied", result.Status(), result.Errno())
	}
	if result.Message() != "not on my watch" {
		t.Fatalf("denied message = %q", result.Message())
	}
	if next.executions != 0 {
		t.Fatalf("driver executed %d times on denial", next.executions)
	}
}
