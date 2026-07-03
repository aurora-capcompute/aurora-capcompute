package agent

// Restore: rebuild the runtime's in-memory state on startup by folding each
// thread's event stream back into thread, run, and task projections.

import (
	"context"
	"log/slog"
	"sort"
)

// Restore: rebuild in-memory state by folding each thread's event stream.
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
		journals, histories, err := foldJournals(events, r.log, scope, r.journalNow, r.journalAppendPublisher(scope.ThreadID))
		if err != nil {
			return err
		}
		if err := r.restoreThread(proj, journals, histories); err != nil {
			return err
		}
		r.tasks.seed(proj.TaskList())
	}
	return nil
}

// restoreThread folds one thread's projection back into memory: it rebuilds the
// thread, its runs (in creation order, deriving conversation history from
// completed runs), and attaches each run's journal revision. Runs left mid-flight
// by a crash are marked interrupted and re-recorded.
func (r *Runtime) restoreThread(proj Projection, journals map[string]map[uint64]*logJournal, histories map[string]*runHistory) error {
	stored := proj.Thread
	if stored.ID == "" {
		return nil
	}
	thread := &threadState{
		id:          stored.ID,
		title:       stored.Title,
		createdAt:   stored.CreatedAt,
		updatedAt:   stored.UpdatedAt,
		activeRunID: stored.ActiveRunID,
		tags:        cloneTags(stored.Tags),
	}
	r.threads[thread.id] = thread

	runs := make([]StoredRun, 0, len(proj.Runs))
	for _, sr := range proj.Runs {
		runs = append(runs, sr)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.Before(runs[j].CreatedAt) })

	for _, sr := range runs {
		if sr.Manifest.Brain == "" {
			sr.Manifest.Brain = r.brains.DefaultID()
		}
		em, err := ValidateManifest(sr.Manifest, r.dispatchers)
		if err != nil {
			return err
		}
		// Runs are always restored regardless of brain registration state:
		// brains are loaded after restore via SetBrains, so r.brains is empty
		// here. If the brain is unavailable when execution is attempted, execute()
		// will fail the run cleanly at that point (compute == nil check).
		status := sr.Status
		if status == RunQueued || status == RunRunning || status == RunStopping {
			status = RunInterrupted
		}
		run := &runState{
			id:                sr.ID,
			threadID:          sr.ThreadID,
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
			brainDigest:       sr.BrainDigest,
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
		run.history = append([]HistoryMessage(nil), thread.history...)
		thread.runIDs = append(thread.runIDs, run.id)
		if run.status == RunCompleted {
			thread.history = append(thread.history,
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
	if thread.activeRunID != "" && r.runs[thread.activeRunID] == nil {
		slog.Info("clearing active run from thread due to brain digest mismatch",
			"thread_id", thread.id, "run_id", thread.activeRunID)
		thread.activeRunID = ""
	}
	return nil
}
