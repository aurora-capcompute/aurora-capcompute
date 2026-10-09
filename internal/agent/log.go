package agent

// The durable log is a session's whole state of record: restore folds it from
// the beginning, and every read is a projection of what was folded.

import (
	"context"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

func (r *Runtime) journalNow() time.Time { return r.now().UTC() }

// appendProcess records a process's current state on its session's stream.
//
// It runs under r.mu, and callers roll a partial mutation back on its error, so
// the append is synchronous by design. The injected log must therefore not block
// on remote I/O: that would stall every reader and transition. The context is
// not cancellable on purpose: a final state must persist during shutdown.
func (r *Runtime) appendProcess(proc *processState) error {
	ev, err := durable.ProcessStateEvent(r.journalNow(), r.storedProcessLocked(proc))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), proc.sessionID, ev)
	return err
}

func (r *Runtime) appendSession(session *sessionState) error {
	ev, err := durable.SessionStateEvent(r.journalNow(), r.storedSessionLocked(session))
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
