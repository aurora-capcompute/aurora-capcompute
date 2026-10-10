package agent

// The session API. A session is a conversation: an ordered list of processes,
// at most one of them active, whose completed answers form the history a later
// process reads.

import (
	"fmt"
	"strings"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
)

// CreateSession opens a session. A name is the session's unique handle. An
// unnamed session's handle is its id. The session is recorded at once, so it
// survives a restart before it runs anything.
func (r *Runtime) CreateSession(name string, tags map[string]string) (SessionSnapshot, error) {
	name = strings.TrimSpace(name)
	id, err := randomID("ses_")
	if err != nil {
		return SessionSnapshot{}, err
	}
	now := r.now().UTC()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	if err := r.checkSessionNameFreeLocked(name, ""); err != nil {
		return SessionSnapshot{}, err
	}
	session := &sessionState{id: id, name: name, createdAt: now, updatedAt: now, tags: durable.CloneTags(tags)}
	if err := r.appendSession(session); err != nil {
		return SessionSnapshot{}, err
	}
	r.sessions[id] = session
	return r.sessionSnapshotLocked(session), nil
}

// RenameSession changes a session's explicit handle. The new name must be free.
// An empty name clears it, and the id becomes the handle again.
func (r *Runtime) RenameSession(sessionID, name string) (SessionSnapshot, error) {
	name = strings.TrimSpace(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return SessionSnapshot{}, fmt.Errorf("%w: runtime is closed", errs.Conflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		return SessionSnapshot{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	if err := r.checkSessionNameFreeLocked(name, sessionID); err != nil {
		return SessionSnapshot{}, err
	}
	// Record the renamed session first, and apply it only once it is recorded.
	renamed := *session
	renamed.name = name
	renamed.updatedAt = r.now().UTC()
	if err := r.appendSession(&renamed); err != nil {
		return SessionSnapshot{}, err
	}
	*session = renamed
	return r.sessionSnapshotLocked(session), nil
}

// checkSessionNameFreeLocked rejects a name another session already holds. An
// empty name is always free: unnamed sessions coexist.
func (r *Runtime) checkSessionNameFreeLocked(name, exceptID string) error {
	if name == "" {
		return nil
	}
	for id, session := range r.sessions {
		if id != exceptID && session.name == name {
			return fmt.Errorf("%w: a session named %q already exists", errs.Conflict, name)
		}
	}
	return nil
}

// GetSession returns the whole session: its history, and every process with
// its journal and tasks.
func (r *Runtime) GetSession(sessionID string) (SessionSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.sessions[sessionID]
	if session == nil {
		return SessionSnapshot{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	return r.sessionSnapshotLocked(session), nil
}

// ListSessions returns a summary of every session, in no order.
func (r *Runtime) ListSessions() []SessionSummary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionSummary, 0, len(r.sessions))
	for _, session := range r.sessions {
		out = append(out, r.sessionSummaryLocked(session))
	}
	return out
}
