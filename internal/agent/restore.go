package agent

// Restore: rebuild the runtime's in-memory state on startup by folding each
// session's event stream back into session, process, and task projections.

import (
	"context"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

// restore rebuilds in-memory state by folding each session's event stream.
func (r *Runtime) restore(ctx context.Context) error {
	sessions, err := r.log.Sessions(ctx)
	if err != nil {
		return err
	}
	for _, sessionID := range sessions {
		events, err := r.log.Read(ctx, sessionID, 0)
		if err != nil {
			return err
		}
		proj, err := durable.Fold(events)
		if err != nil {
			return err
		}
		histories, err := foldJournals(events)
		if err != nil {
			return err
		}
		if err := r.restoreSession(proj, histories); err != nil {
			return err
		}
		r.tasks.seed(proj.Tasks)
	}
	return nil
}

// restoreSession folds one session's projection back into memory: the session,
// its processes in creation order, and each process's journal at its current
// revision. A process a crash left mid-flight is marked interrupted and
// recorded again.
func (r *Runtime) restoreSession(proj durable.Projection, histories map[string]*processHistory) error {
	stored := proj.Session
	session := &sessionState{
		id:              stored.ID,
		name:            stored.Name,
		createdAt:       stored.CreatedAt,
		updatedAt:       stored.UpdatedAt,
		activeProcessID: stored.ActiveProcessID,
		tags:            durable.CloneTags(stored.Tags),
	}
	r.sessions[session.id] = session

	for _, sr := range proj.Processes {
		// The manifest was validated when the process was created. A driver
		// removed since then fails the process when it next runs, not the boot.
		status := sr.Status
		if status == durable.ProcessQueued || status == durable.ProcessRunning || status == durable.ProcessStopping {
			status = durable.ProcessInterrupted
		}
		proc := &processState{
			id:           sr.ID,
			sessionID:    sr.SessionID,
			input:        sr.Input,
			status:       status,
			attempt:      sr.Attempt,
			revision:     sr.Revision,
			createdAt:    sr.CreatedAt,
			updatedAt:    sr.UpdatedAt,
			startedAt:    sr.StartedAt,
			completedAt:  sr.CompletedAt,
			answer:       sr.Answer,
			err:          sr.Error,
			manifest:     sr.Manifest,
			digest:       sr.ProgramDigest,
			labels:       sr.Labels,
			forkOffset:   sr.ForkOffset,
			abortRetries: sr.AbortRetries,
		}
		history := histories[proc.id]
		if history == nil {
			// The process never journaled anything.
			history = newProcessHistory()
		}
		// The persisted fork offset places a revision that forked but crashed
		// before it logged a record.
		proc.journal = r.newJournal(proc, history, history.length(proc.revision, sr.ForkOffset))
		r.processes[proc.id] = proc
		session.processIDs = append(session.processIDs, proc.id)
		if status != sr.Status {
			if err := r.appendProcess(proc); err != nil {
				return err
			}
		}
	}
	return nil
}
