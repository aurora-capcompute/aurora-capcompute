package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"slices"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// eventTaskStore is the task layer's store (task.Store) over the append-only
// event log. It keeps an in-memory projection, seeded from the log on restore,
// and appends a task.created or task.resolved event for every mutation, so
// durable task state lives only in the log.
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

func (s *eventTaskStore) Find(_ context.Context, scope durable.ProcessContext, position int) (durable.TaskRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		if record.Scope == scope && record.JournalPosition == position {
			return cloneTaskRecord(record), true, nil
		}
	}
	return durable.TaskRecord{}, false, nil
}

func (s *eventTaskStore) Create(ctx context.Context, record durable.TaskRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.ID]; exists {
		return durable.ErrTaskConflict
	}
	if err := s.appendLocked(ctx, durable.TaskCreatedEvent, record); err != nil {
		return err
	}
	s.records[record.ID] = cloneTaskRecord(record)
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
	slices.SortFunc(out, func(a, b durable.TaskRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

func (s *eventTaskStore) Resolve(ctx context.Context, taskID string, tokenHash []byte, resolution durable.TaskResolution, now time.Time) (durable.TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[taskID]
	switch {
	case !ok:
		return durable.TaskRecord{}, durable.ErrTaskNotFound
	case !hmac.Equal(record.TokenHash, tokenHash):
		return durable.TaskRecord{}, durable.ErrTaskUnauthorized
	case record.State != durable.TaskPending:
		// The same decision again returns the existing record. A different
		// decision is a conflict.
		if record.Resolution.Decision == resolution.Decision &&
			bytes.Equal(record.Resolution.Data, resolution.Data) &&
			record.Resolution.Reason == resolution.Reason {
			return cloneTaskRecord(record), nil
		}
		return durable.TaskRecord{}, durable.ErrTaskConflict
	case record.ExpiresAt != nil && !now.Before(*record.ExpiresAt):
		return durable.TaskRecord{}, durable.ErrTaskGone
	}
	record.State = resolution.Decision
	record.Resolution = resolution
	record.ResolvedAt = &now
	if err := s.appendLocked(ctx, durable.TaskResolvedEvent, record); err != nil {
		return durable.TaskRecord{}, err
	}
	s.records[taskID] = cloneTaskRecord(record)
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
	record := s.records[taskID]
	if !due(record, now) {
		return nil
	}
	record.Resolution = durable.TaskResolution{Decision: durable.TaskExpired, Actor: "aurora", Reason: "no resolution before the task's deadline"}
	if fired, ok := timerFired(record); ok {
		record.Resolution = durable.TaskResolution{Decision: durable.TaskCompleted, Actor: "timer", Data: fired}
	}
	record.State = record.Resolution.Decision
	record.ResolvedAt = &now
	if err := s.appendLocked(ctx, durable.TaskResolvedEvent, record); err != nil {
		return err
	}
	s.records[taskID] = cloneTaskRecord(record)
	return nil
}

// appendLocked records one task event on the task's session stream.
func (s *eventTaskStore) appendLocked(ctx context.Context, event func(time.Time, durable.TaskRecord) (eventlog.Event, error), record durable.TaskRecord) error {
	ev, err := event(s.now().UTC(), record)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, record.Scope.SessionID, ev)
	return err
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

func cloneTaskRecord(record durable.TaskRecord) durable.TaskRecord {
	clone := record
	clone.Syscall = record.Syscall.Copy()
	clone.TokenHash = append([]byte(nil), record.TokenHash...)
	clone.Resolution.Data = append([]byte(nil), record.Resolution.Data...)
	clone.ExpiresAt = copyTime(record.ExpiresAt)
	clone.ResolvedAt = copyTime(record.ResolvedAt)
	return clone
}
