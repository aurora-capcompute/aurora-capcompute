package agent

// The in-memory state of sessions and processes, and how a change is recorded.
// The event log is the whole state of record: every change is appended under
// r.mu, restore.go folds the log back into this state at boot, and every read
// is a projection of it (snapshots.go).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// sessionState is one session in memory.
type sessionState struct {
	id   string
	name string
	tags map[string]string
	// processIDs is the session's processes in creation order.
	processIDs []string
	// activeProcessID is the process that holds the session, if any: queued,
	// running, or parked on a task.
	activeProcessID string
	createdAt       time.Time
	updatedAt       time.Time
}

// processState is one process in memory.
type processState struct {
	// Identity, fixed at creation.
	id        string
	sessionID string
	input     string
	manifest  manifest.Manifest
	// digest is the identity of the program the process is bound to for life.
	digest string

	// The current run.
	status      durable.ProcessStatus
	attempt     int
	answer      string
	err         string
	createdAt   time.Time
	updatedAt   time.Time
	startedAt   *time.Time
	completedAt *time.Time
	// labels is the run's taint, kept when the run ends. It goes onto the
	// session-history entry this process adds, so a later run that reads the
	// answer inherits the taint.
	labels []string

	// The journal. revision is the current revision. forkOffset is where it
	// forked: positions below it hold an earlier revision's records. It is
	// logged, so restore can place a revision that forked but crashed before
	// writing a record.
	journal    *logJournal
	revision   uint64
	forkOffset int

	// Guards against running forever.
	//
	// lastFailureLength is the journal length at this revision's last failure.
	// A failure at the same length again is deterministic (recovery.go). It is
	// not logged: losing it to a crash costs at most one extra run.
	lastFailureLength int
	// abortRetries counts the sections this process ran again after a
	// sys.abort, bounded by maxAbortRetries. It is logged and survives forks, so
	// neither a restart nor a fork resets the budget.
	abortRetries int

	// Control of the running quantum. stop cancels it, and is nil when no
	// quantum runs. stopRequested is a Stop that arrived before the quantum
	// could be cancelled.
	stop          func()
	stopRequested bool
}

// context is the identity of the process's current revision.
func (p *processState) context() durable.ProcessContext {
	return durable.ProcessContext{SessionID: p.sessionID, ProcessID: p.id, Revision: p.revision}
}

// randomID is a new session or process id: the prefix and 128 random bits.
func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

// appendSession records a session's current state on its stream.
func (r *Runtime) appendSession(session *sessionState) error {
	ev, err := durable.SessionStateEvent(r.journalNow(), r.storedSessionLocked(session))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), session.id, ev)
	return err
}

// appendProcess records a process's current state on its session's stream.
//
// Appends run under r.mu, so a change and its event are one step. The log must
// therefore not block on remote I/O: that would stall every reader. The context
// is not cancellable on purpose: a final state must persist during shutdown.
func (r *Runtime) appendProcess(proc *processState) error {
	ev, err := durable.ProcessStateEvent(r.journalNow(), r.storedProcessLocked(proc))
	if err != nil {
		return err
	}
	_, err = r.log.Append(context.Background(), proc.sessionID, ev)
	return err
}

// storedSessionLocked is the durable form of a session, which a session.state
// event carries.
func (r *Runtime) storedSessionLocked(session *sessionState) durable.Session {
	return durable.Session{
		ID:        session.id,
		Name:      session.name,
		CreatedAt: session.createdAt,
		UpdatedAt: session.updatedAt,
		Tags:      durable.CloneTags(session.tags),
	}
}

// storedProcessLocked is the durable form of a process, which a process.state
// event carries.
func (r *Runtime) storedProcessLocked(proc *processState) durable.Process {
	return durable.Process{
		ID:            proc.id,
		SessionID:     proc.sessionID,
		Revision:      proc.revision,
		Input:         proc.input,
		Status:        proc.status,
		Attempt:       proc.attempt,
		CreatedAt:     proc.createdAt,
		UpdatedAt:     proc.updatedAt,
		StartedAt:     copyTime(proc.startedAt),
		CompletedAt:   copyTime(proc.completedAt),
		Answer:        proc.answer,
		Error:         proc.err,
		Manifest:      proc.manifest.Clone(),
		ProgramDigest: proc.digest,
		Labels:        append([]string(nil), proc.labels...),
		ForkOffset:    proc.forkOffset,
		AbortRetries:  proc.abortRetries,
	}
}

// journalNow is the time an event carries.
func (r *Runtime) journalNow() time.Time { return r.now().UTC() }

// newJournal opens the process's current revision of its journal, length
// records long.
func (r *Runtime) newJournal(proc *processState, history *processHistory, length int) *logJournal {
	return newLogJournal(r.log, proc.sessionID, proc.id, proc.revision,
		history, length, r.journalNow)
}
