package task_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"
)

type run struct{}

type taskStore struct {
	mu      sync.Mutex
	records map[string]task.Record
}

func newTaskStore() *taskStore {
	return &taskStore{records: make(map[string]task.Record)}
}

func (s *taskStore) Find(_ context.Context, scope task.Scope, position int, hash string) (task.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.Scope == scope && record.JournalPosition == position && record.CallHash == hash {
			return record, true, nil
		}
	}
	return task.Record{}, false, nil
}

func (s *taskStore) Create(_ context.Context, record task.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[record.ID]; ok {
		return task.ErrConflict
	}
	s.records[record.ID] = record
	return nil
}

func (s *taskStore) Get(_ context.Context, _ string, id string) (task.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return task.Record{}, task.ErrNotFound
	}
	return record, nil
}

func (s *taskStore) List(_ context.Context, _ string, runID string) ([]task.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var records []task.Record
	for _, record := range s.records {
		if runID == "" || record.Scope.RunID == runID {
			records = append(records, record)
		}
	}
	return records, nil
}

func (s *taskStore) Resolve(_ context.Context, _ string, id string, tokenHash []byte, resolution task.Resolution, now time.Time) (task.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return task.Record{}, task.ErrNotFound
	}
	if !task.VerifyToken(tokenHash, task.Token([]byte("test-secret"), record.Scope.TenantID, record.ID)) {
		return task.Record{}, task.ErrUnauthorized
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
		return task.ErrNotFound
	}
	record.State = task.StateExecuted
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

func (*approvalDispatcher) Capabilities() []sys.Capability { return nil }

func (d *approvalDispatcher) Dispatch(_ context.Context, _ run, _ sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if auth.Decision == "" {
		return sys.Yield("approve test operation"), nil
	}
	if auth.Decision != task.StateApproved {
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
	scope := task.Scope{TenantID: "tenant", ThreadID: "thread", RunID: "run", Revision: 1}
	secret := []byte("test-secret")
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Run: "run"}
	build := func() sys.Dispatcher[run] {
		taskDispatcher := &task.Dispatcher[run]{
			Next:        next,
			Store:       store,
			Journal:     journal,
			Scope:       func(run) task.Scope { return scope },
			TokenSecret: secret,
			TaskTTL:     time.Hour,
		}
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return replay.NewDispatcher[run](tape, taskDispatcher)
	}
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "internet.read", Args: json.RawMessage(`{"url":"https://example.com"}`)}

	result, err := build().Dispatch(context.Background(), run{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("initial dispatch: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("initial status = %s", result.Status())
	}
	records, err := store.List(context.Background(), scope.TenantID, scope.RunID)
	if err != nil || len(records) != 1 {
		t.Fatalf("tasks = %+v, err=%v", records, err)
	}
	// The task's identity is the journaled intent: position 0, the open tail.
	if records[0].JournalPosition != 0 || records[0].Syscall.Name != "internet.read" {
		t.Fatalf("task record = %+v", records[0])
	}
	if journal.Length() != 1 {
		t.Fatalf("journal length = %d, want 1 (open intent)", journal.Length())
	}

	token := task.Token(secret, scope.TenantID, records[0].ID)
	sum := sha256.Sum256([]byte(token))
	if _, err := store.Resolve(context.Background(), scope.TenantID, records[0].ID, sum[:], task.Resolution{
		Decision: task.StateApproved,
		Actor:    "tester",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	result, err = build().Dispatch(context.Background(), run{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("resumed dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult || next.executions != 1 {
		t.Fatalf("resumed status = %s, executions=%d", result.Status(), next.executions)
	}
	if journal.Length() != 2 {
		t.Fatalf("journal length = %d, want 2 (intent + completion)", journal.Length())
	}

	result, err = build().Dispatch(context.Background(), run{}, call, sys.Authorization{})
	if err != nil {
		t.Fatalf("replayed dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult || next.executions != 1 {
		t.Fatalf("replayed status = %s, executions=%d", result.Status(), next.executions)
	}
}

// A denied resolution replays as a classified failure, not an execution.
func TestDispatcherDeniedTask(t *testing.T) {
	store := newTaskStore()
	journal := &journal{}
	next := &approvalDispatcher{}
	scope := task.Scope{TenantID: "tenant", ThreadID: "thread", RunID: "run", Revision: 1}
	secret := []byte("test-secret")
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Run: "run"}
	build := func() sys.Dispatcher[run] {
		taskDispatcher := &task.Dispatcher[run]{
			Next:        next,
			Store:       store,
			Journal:     journal,
			Scope:       func(run) task.Scope { return scope },
			TokenSecret: secret,
			TaskTTL:     time.Hour,
		}
		tape, err := journaled.NewTape(journal, header)
		if err != nil {
			t.Fatalf("new tape: %v", err)
		}
		return replay.NewDispatcher[run](tape, taskDispatcher)
	}
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "internet.read", Args: json.RawMessage(`{"url":"https://example.com"}`)}

	if _, err := build().Dispatch(context.Background(), run{}, call, sys.Authorization{}); err != nil {
		t.Fatalf("initial dispatch: %v", err)
	}
	records, _ := store.List(context.Background(), scope.TenantID, scope.RunID)
	token := task.Token(secret, scope.TenantID, records[0].ID)
	sum := sha256.Sum256([]byte(token))
	if _, err := store.Resolve(context.Background(), scope.TenantID, records[0].ID, sum[:], task.Resolution{
		Decision: task.StateDenied,
		Reason:   "not on my watch",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	result, err := build().Dispatch(context.Background(), run{}, call, sys.Authorization{})
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
