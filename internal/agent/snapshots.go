package agent

// The read projections: in-memory state turned into the snapshots the API
// returns (api.go). A snapshot is a copy: a caller cannot change runtime state
// through it.

import (
	"slices"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

func (r *Runtime) sessionSummaryLocked(session *sessionState) SessionSummary {
	// The title is the first process's input, shortened.
	var firstInput string
	if len(session.processIDs) > 0 {
		firstInput = r.processes[session.processIDs[0]].input
	}
	return SessionSummary{
		ID:              session.id,
		Name:            session.name,
		Title:           durable.SessionTitle(firstInput),
		CreatedAt:       session.createdAt,
		UpdatedAt:       session.updatedAt,
		ProcessCount:    len(session.processIDs),
		ActiveProcessID: session.activeProcessID,
		Tags:            durable.CloneTags(session.tags),
	}
}

// historyLocked is the conversation of a list of processes: each completed one
// adds its input and its answer, and the answer carries the run's taint. It is
// derived, not stored, so a restarted process replaces its turn.
func (r *Runtime) historyLocked(processIDs []string) []HistoryMessage {
	var history []HistoryMessage
	for _, id := range processIDs {
		proc := r.processes[id]
		if proc.status != durable.ProcessCompleted {
			continue
		}
		history = append(history,
			HistoryMessage{Role: "user", Content: proc.input},
			HistoryMessage{Role: "assistant", Content: proc.answer, Labels: proc.labels},
		)
	}
	return history
}

// historyBeforeLocked is the conversation a process reads: its session's turns
// before it.
func (r *Runtime) historyBeforeLocked(proc *processState) []HistoryMessage {
	ids := r.sessions[proc.sessionID].processIDs
	return r.historyLocked(ids[:slices.Index(ids, proc.id)])
}

func (r *Runtime) sessionSnapshotLocked(session *sessionState) SessionSnapshot {
	procs := make([]ProcessLog, 0, len(session.processIDs))
	for _, processID := range session.processIDs {
		proc := r.processes[processID]
		records := r.tasks.List(proc.id)
		tasks := make([]TaskSnapshot, 0, len(records))
		for _, record := range records {
			tasks = append(tasks, r.taskSnapshot(record))
		}
		procs = append(procs, ProcessLog{
			ProcessSnapshot: r.processSnapshotLocked(proc),
			Entries:         proc.journal.history.entries(),
			Tasks:           tasks,
		})
	}
	return SessionSnapshot{
		SessionSummary: r.sessionSummaryLocked(session),
		History:        r.historyLocked(session.processIDs),
		Processes:      procs,
	}
}

func (r *Runtime) processSnapshotLocked(proc *processState) ProcessSnapshot {
	return ProcessSnapshot{
		ID:            proc.id,
		SessionID:     proc.sessionID,
		Input:         proc.input,
		Status:        proc.status,
		Attempt:       proc.attempt,
		Revision:      proc.revision,
		Answer:        proc.answer,
		Error:         proc.err,
		Labels:        append([]string(nil), proc.labels...),
		JournalLength: proc.journal.Length(),
		CreatedAt:     proc.createdAt,
		UpdatedAt:     proc.updatedAt,
		StartedAt:     copyTime(proc.startedAt),
		CompletedAt:   copyTime(proc.completedAt),
		Manifest:      proc.manifest.Clone(),
		ProgramDigest: proc.digest,
	}
}

func (r *Runtime) taskSnapshot(record durable.TaskRecord) TaskSnapshot {
	return TaskSnapshot{
		ID:              record.ID,
		ProcessID:       record.Scope.ProcessID,
		Revision:        record.Scope.Revision,
		JournalPosition: record.JournalPosition,
		Syscall:         record.Syscall.Copy(),
		Summary:         record.Summary,
		State:           record.State,
		Resolution:      record.Resolution,
		CreatedAt:       record.CreatedAt,
		ExpiresAt:       copyTime(record.ExpiresAt),
		ResolvedAt:      copyTime(record.ResolvedAt),
		ResolutionToken: durable.TaskToken(r.taskSecret, record.ID),
	}
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	dup := *value
	return &dup
}
