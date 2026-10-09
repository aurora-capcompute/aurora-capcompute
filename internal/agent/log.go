package agent

// The durable log is a session's whole state of record: restore folds it from
// the beginning, and every read is a projection of what was folded.

import (
	"context"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

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
	_, err = r.log.Append(context.Background(), proc.sessionID, ev)
	return err
}

func (r *Runtime) appendSession(session *sessionState) error {
	ev, err := durable.SessionStateEvent(r.now().UTC(), r.storedSessionLocked(session))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), session.id, ev)
	return err
}

func (r *Runtime) newJournal(proc *processState, history *processHistory, length int) *logJournal {
	return newLogJournal(r.log, proc.sessionID, proc.id, proc.revision,
		history, length, r.journalNow)
}
