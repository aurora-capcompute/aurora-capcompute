package agent

import (
	"context"
	"crypto/hmac"
	"sort"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// eventTaskStore implements durable.TaskStore over the append-only event log. It keeps
// an in-memory projection (seeded from the log on restore, updated on each op)
// and appends a task.created / task.resolved / task.executed event for every
// mutation, so durable task state lives only in the log.
type eventTaskStore struct {
	log eventlog.Log
	now func() time.Time

	mu      sync.Mutex
	records map[string]durable.TaskRecord // keyed by task id
}

func newEventTaskStore(log eventlog.Log, now func() time.Time) *eventTaskStore {
	return &eventTaskStore{log: log, now: now, records: make(map[string]durable.TaskRecord)}
}

// seed installs records folded from the log during restore.
func (s *eventTaskStore) seed(records []durable.TaskRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		s.records[record.ID] = cloneTaskRecord(record)
	}
}

func (s *eventTaskStore) Find(_ context.Context, scope durable.TaskScope, position int, callHash string) (durable.TaskRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.Scope == scope && record.JournalPosition == position && record.CallHash == callHash {
			return cloneTaskRecord(record), true, nil
		}
	}
	return durable.TaskRecord{}, false, nil
}

func (s *eventTaskStore) Create(ctx context.Context, record durable.TaskRecord) error {
	s.mu.Lock()
	key := record.ID
	if _, exists := s.records[key]; exists {
		s.mu.Unlock()
		return durable.ErrTaskConflict
	}
	ev, err := durable.TaskCreatedEvent(s.now().UTC(), record)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if _, err := s.log.Append(ctx, record.Scope.SessionID, ev); err != nil {
		s.mu.Unlock()
		return err
	}
	s.records[key] = cloneTaskRecord(record)
	s.mu.Unlock()
	return nil
}

// List returns a process's tasks, oldest first.
func (s *eventTaskStore) List(processID string) []durable.TaskRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []durable.TaskRecord
	for _, record := range s.records {
		if record.Scope.ProcessID == processID {
			out = append(out, cloneTaskRecord(record))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *eventTaskStore) Resolve(ctx context.Context, taskID string, tokenHash []byte, resolution durable.TaskResolution, now time.Time) (durable.TaskRecord, error) {
	s.mu.Lock()
	key := taskID
	record, ok := s.records[key]
	if !ok {
		s.mu.Unlock()
		return durable.TaskRecord{}, durable.ErrTaskNotFound
	}
	if !hmac.Equal(record.TokenHash, tokenHash) {
		s.mu.Unlock()
		return durable.TaskRecord{}, durable.ErrTaskUnauthorized
	}
	if record.State != durable.TaskPending {
		// Idempotent re-resolution with the same decision returns the existing
		// record; a conflicting decision is rejected.
		if record.Resolution.Decision == resolution.Decision &&
			string(record.Resolution.Data) == string(resolution.Data) &&
			record.Resolution.Reason == resolution.Reason {
			s.mu.Unlock()
			return cloneTaskRecord(record), nil
		}
		s.mu.Unlock()
		return durable.TaskRecord{}, durable.ErrTaskConflict
	}
	if record.ExpiresAt != nil && !now.Before(*record.ExpiresAt) {
		s.mu.Unlock()
		return durable.TaskRecord{}, durable.ErrTaskGone
	}
	record.State = resolution.Decision
	record.Resolution = resolution
	resolvedAt := now
	record.ResolvedAt = &resolvedAt
	ev, err := durable.TaskResolvedEvent(s.now().UTC(), record)
	if err != nil {
		s.mu.Unlock()
		return durable.TaskRecord{}, err
	}
	if _, err := s.log.Append(ctx, record.Scope.SessionID, ev); err != nil {
		s.mu.Unlock()
		return durable.TaskRecord{}, err
	}
	s.records[key] = cloneTaskRecord(record)
	s.mu.Unlock()
	return cloneTaskRecord(record), nil
}

// Due lists the ids of the pending tasks whose deadline is at or before now.
func (s *eventTaskStore) Due(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, record := range s.records {
		if due(record, now) {
			out = append(out, record.ID)
		}
	}
	return out
}

// Settle resolves one due task the way its deadline decides: a timer fires, and
// anything else expires. A task that is no longer pending — a resolution got
// there first — is left alone.
func (s *eventTaskStore) Settle(ctx context.Context, taskID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := taskID
	record, ok := s.records[key]
	if !ok {
		return durable.ErrTaskNotFound
	}
	if !due(record, now) {
		return nil
	}
	record.Resolution = durable.TaskResolution{Decision: durable.TaskExpired, Actor: "aurora", Reason: "no resolution before the task's deadline"}
	if fired, ok := timerFired(record); ok {
		record.Resolution = durable.TaskResolution{Decision: durable.TaskCompleted, Actor: "timer", Data: fired}
	}
	record.State = record.Resolution.Decision
	resolvedAt := now
	record.ResolvedAt = &resolvedAt
	ev, err := durable.TaskResolvedEvent(s.now().UTC(), record)
	if err != nil {
		return err
	}
	if _, err := s.log.Append(ctx, record.Scope.SessionID, ev); err != nil {
		return err
	}
	s.records[key] = cloneTaskRecord(record)
	return nil
}

// due reports whether a pending task's deadline has passed: a timer's fire
// time, or an approval's expiry.
func due(record durable.TaskRecord, now time.Time) bool {
	if record.State != durable.TaskPending {
		return false
	}
	if fireAt, ok := timerFireAt(record); ok {
		return !now.Before(fireAt)
	}
	return record.ExpiresAt != nil && !now.Before(*record.ExpiresAt)
}

func (s *eventTaskStore) MarkExecuted(ctx context.Context, taskID string, _ time.Time) error {
	s.mu.Lock()
	key := taskID
	record, ok := s.records[key]
	if !ok {
		s.mu.Unlock()
		return durable.ErrTaskNotFound
	}
	record.State = durable.TaskExecuted
	ev, err := durable.TaskExecutedEvent(s.now().UTC(), record.Scope.ProcessID, record.Scope.Revision, taskID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if _, err := s.log.Append(ctx, record.Scope.SessionID, ev); err != nil {
		s.mu.Unlock()
		return err
	}
	s.records[key] = cloneTaskRecord(record)
	s.mu.Unlock()
	return nil
}

func cloneTaskRecord(record durable.TaskRecord) durable.TaskRecord {
	clone := record
	clone.Syscall = record.Syscall.Copy()
	clone.TokenHash = append([]byte(nil), record.TokenHash...)
	clone.Resolution.Data = append([]byte(nil), record.Resolution.Data...)
	clone.ExpiresAt = copyTime(record.ExpiresAt)
	clone.ResolvedAt = copyTime(record.ResolvedAt)
	return clone
}
