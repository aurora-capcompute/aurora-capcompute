package agent

// Restore: rebuild the runtime's in-memory state on startup by folding each
// session's event stream back into session, process, and task projections.

import (
	"context"
	"log/slog"
	"sort"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
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
// session, its processes (in creation order, deriving conversation history from
// completed processes), and attaches each process's journal revision. Processes left mid-flight
// by a crash are marked interrupted and re-recorded.
func (r *Runtime) restoreSession(proj Projection, journals map[string]map[uint64]*logJournal, histories map[string]*processHistory) error {
	stored := proj.Session
	if stored.ID == "" {
		return nil
	}
	session := &sessionState{
		id:              stored.ID,
		title:           stored.Title,
		createdAt:       stored.CreatedAt,
		updatedAt:       stored.UpdatedAt,
		activeProcessID: stored.ActiveProcessID,
		tags:            cloneTags(stored.Tags),
	}
	r.sessions[session.id] = session

	procs := make([]StoredProcess, 0, len(proj.Processes))
	for _, sr := range proj.Processes {
		procs = append(procs, sr)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].CreatedAt.Before(procs[j].CreatedAt) })

	for _, sr := range procs {
		if sr.Manifest.Program == "" {
			sr.Manifest.Program = r.programs.DefaultID()
		}
		// Quarantine, never refuse to boot: a historical process whose manifest no
		// longer validates against the compiled driver set (a decommissioned
		// driver type) is restored verbatim — visible, auditable — and any later
		// execution attempt fails with the provider's error. Dispatcher
		// upgrades thereby follow the same drain-and-deprecate story as
		// program upgrades.
		em, err := ValidateManifest(sr.Manifest, r.dispatchers)
		if err != nil {
			slog.Warn("process manifest no longer validates against the compiled driver set; quarantining",
				"process_id", sr.ID, "session_id", sr.SessionID, "err", err)
			em = sr.Manifest
		}
		// Processes are always restored regardless of program registration state:
		// programs are loaded after restore via SetPrograms, so r.programs is empty
		// here. If the program is unavailable when execution is attempted, execute()
		// will fail the process cleanly at that point (kernel == nil check).
		status := sr.Status
		if status == ProcessQueued || status == ProcessRunning || status == ProcessStopping {
			status = ProcessInterrupted
		}
		proc := &processState{
			id:                sr.ID,
			sessionID:         sr.SessionID,
			input:             sr.Input,
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
			hideHistory:       sr.HideHistory,
			parentProcessID:   sr.ParentProcessID,
			childProcessIDs:   append([]string(nil), sr.ChildProcessIDs...),
			childSpawnOffsets: append([]int(nil), sr.ChildSpawnOffsets...),
			forkOffset:        sr.ForkOffset,
			abandoning:        sr.Abandoning,
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
		if proc.status == ProcessCompleted {
			session.history = append(session.history,
				HistoryMessage{Role: "user", Content: proc.input},
				HistoryMessage{Role: "assistant", Content: proc.answer},
			)
		}
		if status != sr.Status {
			if err := r.appendProcess(proc); err != nil {
				return err
			}
		}
	}
	// A park is only coherent with its wakeup: a waiting process whose pending
	// task resolved (the resolution outran the crash, the resume did not) and a
	// yielded parent whose children all finished would otherwise sleep forever —
	// nothing re-delivers a lost wakeup. Fold them to interrupted, the
	// re-drivable status, so recovery resumes them like any cut-off process.
	pending := map[string]bool{}
	for _, record := range proj.TaskList() {
		if record.State == task.StatePending {
			pending[record.Scope.ProcessID] = true
		}
	}
	for _, processID := range session.processIDs {
		proc := r.processes[processID]
		if proc == nil {
			continue
		}
		lost := false
		switch proc.status {
		case ProcessWaitingTask:
			lost = !pending[proc.id]
		case ProcessYielded:
			lost = true
			for _, childID := range proc.childProcessIDs {
				if child := r.processes[childID]; child != nil && !isTerminal(child.status) {
					lost = false
					break
				}
			}
		}
		if lost {
			slog.Info("parked process lost its wakeup in a crash; folding to interrupted",
				"process_id", proc.id, "status", proc.status)
			proc.status = ProcessInterrupted
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
