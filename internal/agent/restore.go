package agent

// Restore: rebuild the runtime's in-memory state on startup by folding each
// session's event stream back into session, process, and task projections.

import (
	"context"
	"log/slog"
	"sort"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

// Restore: rebuild in-memory state by folding each session's event stream.
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
		r.tasks.seed(proj.TaskList())
	}
	return nil
}

// restoreSession folds one session's projection back into memory: it rebuilds the
// session, its processes (in creation order, deriving conversation history from
// completed processes), and opens each process's journal at its current revision. Processes left mid-flight
// by a crash are marked interrupted and re-recorded.
func (r *Runtime) restoreSession(proj durable.Projection, histories map[string]*processHistory) error {
	stored := proj.Session
	if stored.ID == "" {
		return nil
	}
	session := &sessionState{
		id:              stored.ID,
		name:            stored.Name,
		createdAt:       stored.CreatedAt,
		updatedAt:       stored.UpdatedAt,
		activeProcessID: stored.ActiveProcessID,
		tags:            durable.CloneTags(stored.Tags),
	}
	r.sessions[session.id] = session

	procs := make([]durable.Process, 0, len(proj.Processes))
	for _, sr := range proj.Processes {
		procs = append(procs, sr)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].CreatedAt.Before(procs[j].CreatedAt) })

	for _, sr := range procs {
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
			startedAt:    copyTime(sr.StartedAt),
			completedAt:  copyTime(sr.CompletedAt),
			answer:       sr.Answer,
			err:          sr.Error,
			manifest:     sr.Manifest,
			digest:       sr.ProgramDigest,
			labels:       append([]string(nil), sr.Labels...),
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
		proc.history = append([]HistoryMessage(nil), session.history...)
		session.processIDs = append(session.processIDs, proc.id)
		// Only a completed ROOT contributes to session history, matching the live
		if proc.status == durable.ProcessCompleted {
			session.history = append(session.history,
				HistoryMessage{Role: "user", Content: proc.input},
				HistoryMessage{Role: "assistant", Content: proc.answer, Labels: proc.labels},
			)
		}
		if status != sr.Status {
			if err := r.appendProcess(proc); err != nil {
				return err
			}
		}
	}
	if session.activeProcessID != "" && r.processes[session.activeProcessID] == nil {
		slog.Info("clearing active process from session: the process was not restored",
			"session_id", session.id, "process_id", session.activeProcessID)
		session.activeProcessID = ""
	}
	return nil
}
