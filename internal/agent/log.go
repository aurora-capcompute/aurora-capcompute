package agent

// The runtime has one outbound channel: the durable log. A session's event
// stream is its whole state of record — restore folds it from the beginning —
// and a subscription is a tap on that same stream, so there is no second
// channel that could disagree with it. Everything a watcher might want is
// already written there: process transitions, journalled syscalls, task
// lifecycle.
//
// For now the tap forwards only sys.log. That narrowing is subscriberVisible
// and nothing else; widening it is deleting a condition, not building a
// mechanism.

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// tappedLog is the injected log with a subscription tap: every event that
// reaches the stream reaches the watchers, and nothing that failed to.
type tappedLog struct {
	eventlog.Log
	subs *subscriptions
}

func (l *tappedLog) Append(ctx context.Context, scope eventlog.Scope, events ...eventlog.Event) (uint64, error) {
	head, err := l.Log.Append(ctx, scope, events...)
	if err != nil || len(events) == 0 {
		return head, err
	}
	// Seq is the log's to assign and it never reaches the caller's copies, so
	// it is recovered from the head: appends are contiguous per stream.
	first := head - uint64(len(events)) + 1
	for i, event := range events {
		event.Seq = first + uint64(i)
		l.subs.publish(scope.SessionID, event)
	}
	return head, nil
}

// subscriptions is the watcher side, and only that: it holds no runtime state,
// takes its own lock, and never blocks an append — a watcher that cannot keep
// up is skipped, not waited for.
type subscriptions struct {
	mu      sync.Mutex
	next    uint64
	size    int
	streams map[string]map[uint64]chan eventlog.Event
}

func newSubscriptions(size int) *subscriptions {
	return &subscriptions{size: size, streams: make(map[string]map[uint64]chan eventlog.Event)}
}

func (s *subscriptions) publish(sessionID string, event eventlog.Event) {
	if !subscriberVisible(event) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.streams[sessionID] {
		select {
		case ch <- event:
		default:
		}
	}
}

func (s *subscriptions) add(sessionID string) (uint64, <-chan eventlog.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	ch := make(chan eventlog.Event, s.size)
	if s.streams[sessionID] == nil {
		s.streams[sessionID] = make(map[uint64]chan eventlog.Event)
	}
	s.streams[sessionID][s.next] = ch
	return s.next, ch
}

func (s *subscriptions) remove(sessionID string, id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streams[sessionID], id)
}

// subscriberVisible is the whole of what a watcher currently sees: the guest's
// own progress reports, which are journalled like any other syscall and so
// arrive here without a channel of their own. Only the intent carries the
// message — its completion is the empty ack.
func subscriberVisible(event eventlog.Event) bool {
	if event.Kind != evSyscall {
		return false
	}
	var data syscallRecordData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return false
	}
	return data.Record.Syscall != nil && data.Record.Syscall.Name == callSysLog
}

// scope returns the event stream key for a session.
func (r *Runtime) scope(sessionID string) eventlog.Scope {
	return eventlog.Scope{TenantID: r.tenantID, SessionID: sessionID}
}

func (r *Runtime) journalNow() time.Time { return r.now().UTC() }

// appendProcess records a process's current state to its session's event stream.
//
// CONTRACT: this runs while r.mu (the single lock guarding all session/process
// maps) is held, and callers check its error to roll a partial mutation back —
// so the append stays synchronous and under the lock by design. The injected
// eventlog.Log.Append MUST therefore be non-blocking/local (an in-memory or fast
// local sink): a log that blocks on remote I/O would stall every concurrent
// reader and state transition for that duration. Moving the append off-lock is
// not a safe local change — it would either reorder same-entity events in the
// restore fold or force appends to become asynchronous (losing the
// synchronous-failure rollback callers depend on); an async ordered-append
// pipeline is the proper redesign if a blocking log is ever required. The
// context is non-cancellable on purpose: a metadata append must complete on
// shutdown to persist final state (unlike background work, which derives from
// the cancellable baseCtx).
func (r *Runtime) appendProcess(proc *processState) error {
	ev, err := durable.ProcessStateEvent(r.now().UTC(), r.storedProcessLocked(proc))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), r.scope(proc.sessionID), ev)
	return err
}

func (r *Runtime) appendSession(session *sessionState) error {
	ev, err := durable.SessionStateEvent(r.now().UTC(), r.storedSessionLocked(session))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), r.scope(session.id), ev)
	return err
}

func (r *Runtime) newJournal(proc *processState, history *processHistory, forkOffset int) *logJournal {
	return newLogJournal(r.log, r.scope(proc.sessionID), proc.id, proc.revision,
		history, forkOffset, r.journalNow)
}
