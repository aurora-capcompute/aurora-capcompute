package agent

// Restore: rebuild the runtime's in-memory state on startup by folding each
// session's event stream back into session, process, and task projections.

import (
	"context"
	"log/slog"
	"sort"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
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
		journals, histories, err := foldJournals(events, r.log, sessionID, r.journalNow)
		if err != nil {
			return err
		}
		if err := r.restoreSession(proj, journals, histories); err != nil {
			return err
		}
		r.tasks.seed(proj.TaskList())
	}
	return nil
}

// restoreSession folds one session's projection back into memory: it rebuilds the
// session, its processes (in creation order, deriving conversation history from
// completed processes), and attaches each process's journal revision. Processes left mid-flight
// by a crash are marked interrupted and re-recorded.
func (r *Runtime) restoreSession(proj durable.Projection, journals map[string]map[uint64]*logJournal, histories map[string]*processHistory) error {
	stored := proj.Session
	if stored.ID == "" {
		return nil
	}
	session := &sessionState{
		id:              stored.ID,
		name:            stored.Name,
		title:           stored.Title,
		createdAt:       stored.CreatedAt,
		updatedAt:       stored.UpdatedAt,
		activeProcessID: stored.ActiveProcessID,
		tags:            durable.CloneTags(stored.Tags),
	}
	// A process-less session has no derived title; give it the same placeholder
	// the live runtime assigns at creation so its title survives a restart.
	if session.title == "" {
		session.title = durable.DefaultSessionTitle
	}
	r.sessions[session.id] = session

	procs := make([]durable.Process, 0, len(proj.Processes))
	for _, sr := range proj.Processes {
		procs = append(procs, sr)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].CreatedAt.Before(procs[j].CreatedAt) })

	for _, sr := range procs {
		// Quarantine, never refuse to boot: a historical process whose manifest no
		// longer validates against the compiled driver set (a decommissioned
		// driver type) is restored verbatim — visible, auditable — and any later
		// execution attempt fails with the provider's error. Dispatcher
		// upgrades thereby follow the same drain-and-deprecate story as
		// program upgrades.
		em, err := manifest.Validate(sr.Manifest, r.dispatchers)
		if err != nil {
			slog.Warn("process manifest no longer validates against the compiled driver set; quarantining",
				"process_id", sr.ID, "session_id", sr.SessionID, "err", err)
			em = sr.Manifest
		}
		// Processes are always restored regardless of program registration state:
		// programs are added after restore via AddProgram, so r.programs is empty
		// here. If the program is unavailable when execution is attempted, execute()
		// will fail the process cleanly at that point (program == nil check).
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
			manifest:     em.Clone(),
			digest:       sr.ProgramDigest,
			labels:       append([]string(nil), sr.Labels...),
			forkOffset:   sr.ForkOffset,
			abortRetries: sr.AbortRetries,
		}
		if proc.revision == 0 {
			proc.revision = 1
		}
		if j := journals[proc.id][proc.revision]; j != nil {
			proc.journal = j
		} else if history := histories[proc.id]; history != nil {
			// No records logged for this revision yet (process crashed before any
			// syscall). Share the existing history so replay can serve the shared
			// prefix; the exact fork point was persisted when the revision forked.
			proc.journal = r.newJournal(proc, history, sr.ForkOffset)
		} else {
			// No journal events survive for this process at all — it never
			// journaled anything. An empty view at fork 0 keeps
			// Journal()/snapshots well-defined (length 0, no dangling shared prefix
			// beneath a stale fork offset); a hard restart forks from 0 anyway.
			proc.journal = r.newJournal(proc, newProcessHistory(), 0)
		}
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
