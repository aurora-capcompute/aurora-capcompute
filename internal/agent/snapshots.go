package agent

// Read projections: the *Locked helpers that fold in-memory session and run state
// into the immutable snapshots the public API returns, plus the small pure
// helpers (titles, visible capabilities, defensive copies) they lean on.

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

func (r *Runtime) sessionSummaryLocked(session *sessionState) SessionSummary {
	return SessionSummary{
		ID:          session.id,
		Title:       session.title,
		CreatedAt:   session.createdAt,
		UpdatedAt:   session.updatedAt,
		RunCount:    len(session.runIDs),
		ActiveRunID: session.activeRunID,
		Tags:        cloneTags(session.tags),
	}
}

func sessionTitle(message string) string {
	fields := strings.Fields(message)
	if len(fields) == 0 {
		return "New session"
	}
	title := strings.Join(fields, " ")
	runes := []rune(title)
	if len(runes) <= 60 {
		return title
	}
	return string(runes[:60]) + "…"
}

func (r *Runtime) sessionSnapshotLocked(session *sessionState) SessionSnapshot {
	runs := make([]RunSnapshot, 0, len(session.runIDs))
	for _, runID := range session.runIDs {
		if run := r.runs[runID]; run != nil {
			runs = append(runs, r.runSnapshotLocked(run))
		}
	}
	return SessionSnapshot{
		SessionSummary: r.sessionSummaryLocked(session),
		History:        append([]HistoryMessage(nil), session.history...),
		Runs:           runs,
	}
}

func (r *Runtime) runSnapshotLocked(run *runState) RunSnapshot {
	journalLength := 0
	if run.journal != nil {
		journalLength = run.journal.Length()
	}
	return RunSnapshot{
		ID:            run.id,
		SessionID:     run.sessionID,
		Message:       run.message,
		Status:        run.status,
		Attempt:       run.attempt,
		Revision:      run.revision,
		Answer:        run.answer,
		Error:         run.err,
		JournalLength: journalLength,
		CreatedAt:     run.createdAt,
		UpdatedAt:     run.updatedAt,
		StartedAt:     copyTime(run.startedAt),
		CompletedAt:   copyTime(run.completedAt),
		Manifest:      cloneManifest(run.manifest),
		ProgramDigest: run.programDigest,
	}
}

func (r *Runtime) taskSnapshot(record task.Record) TaskSnapshot {
	return TaskSnapshot{
		ID:              record.ID,
		RunID:           record.Scope.RunID,
		Revision:        record.Scope.Revision,
		JournalPosition: record.JournalPosition,
		Syscall:         record.Syscall.Copy(),
		Summary:         record.Summary,
		State:           record.State,
		Resolution:      record.Resolution,
		CreatedAt:       record.CreatedAt,
		ExpiresAt:       copyTime(record.ExpiresAt),
		ResolvedAt:      copyTime(record.ResolvedAt),
		ResolutionToken: task.Token(r.taskSecret, record.Scope.TenantID, record.ID),
	}
}

func hasPendingTask(records []task.Record) bool {
	for _, record := range records {
		if record.State == task.StatePending {
			return true
		}
	}
	return false
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// visibleCapabilities drops capabilities marked Hidden (e.g. the LLM cognition
// tool and the runtime's protocol calls) from the program's discoverable menu.
// Hidden is set at build time on each published capability, so it works even
// when a tool's published operation names differ from its local name.
func visibleCapabilities(caps []sys.Capability) []sys.Capability {
	visible := make([]sys.Capability, 0, len(caps))
	for _, c := range caps {
		if !c.Hidden {
			visible = append(visible, c)
		}
	}
	return visible
}

func (r *Runtime) runContext(run *runState) RunContext {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runContextLocked(run)
}

func (r *Runtime) runContextLocked(run *runState) RunContext {
	return RunContext{
		TenantID:  r.tenantID,
		SessionID: run.sessionID,
		RunID:     run.id,
		Revision:  run.revision,
	}
}

func (r *Runtime) storedRunLocked(run *runState) StoredRun {
	var tags map[string]string
	if session := r.sessions[run.sessionID]; session != nil {
		tags = cloneTags(session.tags)
	}
	return StoredRun{
		TenantID:          r.tenantID,
		ID:                run.id,
		SessionID:         run.sessionID,
		Revision:          run.revision,
		Message:           run.message,
		Status:            run.status,
		Attempt:           run.attempt,
		CreatedAt:         run.createdAt,
		UpdatedAt:         run.updatedAt,
		StartedAt:         copyTime(run.startedAt),
		CompletedAt:       copyTime(run.completedAt),
		Answer:            run.answer,
		Error:             run.err,
		Manifest:          cloneManifest(run.manifest),
		ProgramDigest:     run.programDigest,
		Tags:              tags,
		ParentRunID:       run.parentRunID,
		ChildRunIDs:       append([]string(nil), run.childRunIDs...),
		ChildSpawnOffsets: append([]int(nil), run.childSpawnOffsets...),
		ForkOffset:        run.forkOffset,
	}
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func cloneTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}
