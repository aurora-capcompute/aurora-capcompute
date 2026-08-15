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
	records map[string]durable.TaskRecord // keyed by tenant/taskID
}

func newEventTaskStore(log eventlog.Log, now func() time.Time) *eventTaskStore {
	return &eventTaskStore{log: log, now: now, records: make(map[string]durable.TaskRecord)}
}

func taskKey(tenantID, taskID string) string { return tenantID + "/" + taskID }

// seed installs records folded from the log during restore.
func (s *eventTaskStore) seed(records []durable.TaskRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		s.records[taskKey(record.Scope.TenantID, record.ID)] = cloneTaskRecord(record)
	}
}

func (s *eventTaskStore) scope(record durable.TaskRecord) eventlog.Scope {
	return eventlog.Scope{TenantID: record.Scope.TenantID, SessionID: record.Scope.SessionID}
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
	key := taskKey(record.Scope.TenantID, record.ID)
	if _, exists := s.records[key]; exists {
		s.mu.Unlock()
		return durable.ErrTaskConflict
	}
	ev, err := durable.TaskCreatedEvent(s.now().UTC(), record)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if _, err := s.log.Append(ctx, s.scope(record), ev); err != nil {
		s.mu.Unlock()
		return err
	}
	s.records[key] = cloneTaskRecord(record)
	s.mu.Unlock()
	return nil
}

func (s *eventTaskStore) Get(_ context.Context, tenantID, taskID string) (durable.TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[taskKey(tenantID, taskID)]
	if !ok {
		return durable.TaskRecord{}, durable.ErrTaskNotFound
	}
	return cloneTaskRecord(record), nil
}

func (s *eventTaskStore) List(_ context.Context, tenantID, processID string) ([]durable.TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []durable.TaskRecord
	for _, record := range s.records {
		if record.Scope.TenantID == tenantID && (processID == "" || record.Scope.ProcessID == processID) {
			out = append(out, cloneTaskRecord(record))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *eventTaskStore) Resolve(ctx context.Context, tenantID, taskID string, tokenHash []byte, resolution durable.TaskResolution, now time.Time) (durable.TaskRecord, error) {
	s.mu.Lock()
	key := taskKey(tenantID, taskID)
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
	if _, err := s.log.Append(ctx, s.scope(record), ev); err != nil {
		s.mu.Unlock()
		return durable.TaskRecord{}, err
	}
	s.records[key] = cloneTaskRecord(record)
	s.mu.Unlock()
	return cloneTaskRecord(record), nil
}

func (s *eventTaskStore) MarkExecuted(ctx context.Context, tenantID, taskID string, _ time.Time) error {
	s.mu.Lock()
	key := taskKey(tenantID, taskID)
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
	if _, err := s.log.Append(ctx, s.scope(record), ev); err != nil {
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
