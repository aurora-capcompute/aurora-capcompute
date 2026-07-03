package agent

// Restore: rebuild the runtime's in-memory state on startup by folding each
// session's event stream back into session, run, and task projections.

import (
	"context"
	"log/slog"
	"sort"
)

// Restore: rebuild in-memory state by folding each session's event stream.
func (r *Runtime) restore(ctx context.Context) error {
	scopes, err := r.log.Streams(ctx, r.tenantID)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		events, err := r.log.Read(ctx, scope, 0)
		if err != nil {
			return err
		}
		proj, err := Fold(events)
		if err != nil {
			return err
		}
		journals, histories, err := foldJournals(events, r.log, scope, r.journalNow, r.journalAppendPublisher(scope.SessionID))
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
// session, its runs (in creation order, deriving conversation history from
// completed runs), and attaches each run's journal revision. Runs left mid-flight
// by a crash are marked interrupted and re-recorded.
func (r *Runtime) restoreSession(proj Projection, journals map[string]map[uint64]*logJournal, histories map[string]*runHistory) error {
	stored := proj.Session
	if stored.ID == "" {
		return nil
	}
	session := &sessionState{
		id:          stored.ID,
		title:       stored.Title,
		createdAt:   stored.CreatedAt,
		updatedAt:   stored.UpdatedAt,
		activeRunID: stored.ActiveRunID,
		tags:        cloneTags(stored.Tags),
	}
	r.sessions[session.id] = session

	runs := make([]StoredRun, 0, len(proj.Runs))
	for _, sr := range proj.Runs {
		runs = append(runs, sr)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.Before(runs[j].CreatedAt) })

	for _, sr := range runs {
		if sr.Manifest.Program == "" {
			sr.Manifest.Program = r.programs.DefaultID()
		}
		// Quarantine, never refuse to boot: a historical run whose manifest no
		// longer validates against the compiled driver set (a decommissioned
		// tool type) is restored verbatim — visible, auditable — and any later
		// execution attempt fails with the provider's error. Dispatcher
		// upgrades thereby follow the same drain-and-deprecate story as
		// program upgrades.
		em, err := ValidateManifest(sr.Manifest, r.dispatchers)
		if err != nil {
			slog.Warn("run manifest no longer validates against the compiled driver set; quarantining",
				"run_id", sr.ID, "session_id", sr.SessionID, "err", err)
			em = sr.Manifest
		}
		// Runs are always restored regardless of program registration state:
		// programs are loaded after restore via SetPrograms, so r.programs is empty
		// here. If the program is unavailable when execution is attempted, execute()
		// will fail the run cleanly at that point (kernel == nil check).
		status := sr.Status
		if status == RunQueued || status == RunRunning || status == RunStopping {
			status = RunInterrupted
		}
		run := &runState{
			id:                sr.ID,
			sessionID:         sr.SessionID,
			message:           sr.Message,
			status:            status,
			attempt:           sr.Attempt,
			revision:          sr.Revision,
			createdAt:         sr.CreatedAt,
			updatedAt:         sr.UpdatedAt,
			startedAt:         copyTime(sr.StartedAt),
			completedAt:       copyTime(sr.CompletedAt),
			answer:            sr.Answer,
			err:               sr.Error,
			manifest:          cloneManifest(em),
			programDigest:     sr.ProgramDigest,
			parentRunID:       sr.ParentRunID,
			childRunIDs:       append([]string(nil), sr.ChildRunIDs...),
			childSpawnOffsets: append([]int(nil), sr.ChildSpawnOffsets...),
			forkOffset:        sr.ForkOffset,
		}
		if run.revision == 0 {
			run.revision = 1
		}
		if j := journals[run.id][run.revision]; j != nil {
			run.journal = j
		} else {
			// No records logged for this revision yet (run crashed before any
			// syscall). Share the existing history so replay can serve the shared
			// prefix; the exact fork point was persisted when the revision forked.
			history := histories[run.id]
			if history == nil {
				history = newRunHistory()
			}
			run.journal = r.newJournal(run, history, sr.ForkOffset)
		}
		r.runs[run.id] = run
		run.history = append([]HistoryMessage(nil), session.history...)
		session.runIDs = append(session.runIDs, run.id)
		if run.status == RunCompleted {
			session.history = append(session.history,
				HistoryMessage{Role: "user", Content: run.message},
				HistoryMessage{Role: "assistant", Content: run.answer},
			)
		}
		if status != sr.Status {
			if err := r.appendRun(run); err != nil {
				return err
			}
		}
	}
	if session.activeRunID != "" && r.runs[session.activeRunID] == nil {
		slog.Info("clearing active run from session due to program digest mismatch",
			"session_id", session.id, "run_id", session.activeRunID)
		session.activeRunID = ""
	}
	return nil
}
