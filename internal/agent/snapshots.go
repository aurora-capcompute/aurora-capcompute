package agent

// Read projections: the *Locked helpers that fold in-memory session and process state
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
		ID:              session.id,
		Title:           session.title,
		CreatedAt:       session.createdAt,
		UpdatedAt:       session.updatedAt,
		ProcessCount:    len(session.processIDs),
		ActiveProcessID: session.activeProcessID,
		Tags:            cloneTags(session.tags),
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
	procs := make([]ProcessSnapshot, 0, len(session.processIDs))
	for _, processID := range session.processIDs {
		if proc := r.processes[processID]; proc != nil {
			procs = append(procs, r.processSnapshotLocked(proc))
		}
	}
	return SessionSnapshot{
		SessionSummary: r.sessionSummaryLocked(session),
		History:        append([]HistoryMessage(nil), session.history...),
		Processes:      procs,
	}
}

func (r *Runtime) processSnapshotLocked(proc *processState) ProcessSnapshot {
	journalLength := 0
	if proc.journal != nil {
		journalLength = proc.journal.Length()
	}
	return ProcessSnapshot{
		ID:            proc.id,
		SessionID:     proc.sessionID,
		Message:       proc.message,
		Status:        proc.status,
		Attempt:       proc.attempt,
		Revision:      proc.revision,
		Answer:        proc.answer,
		Error:         proc.err,
		JournalLength: journalLength,
		CreatedAt:     proc.createdAt,
		UpdatedAt:     proc.updatedAt,
		StartedAt:     copyTime(proc.startedAt),
		CompletedAt:   copyTime(proc.completedAt),
		Manifest:      cloneManifest(proc.manifest),
		ProgramDigest: proc.programDigest,
	}
}

func (r *Runtime) taskSnapshot(record task.Record) TaskSnapshot {
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

func (r *Runtime) processContext(proc *processState) ProcessContext {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.processContextLocked(proc)
}

func (r *Runtime) processContextLocked(proc *processState) ProcessContext {
	return ProcessContext{
		TenantID:  r.tenantID,
		SessionID: proc.sessionID,
		ProcessID: proc.id,
		Revision:  proc.revision,
	}
}

func (r *Runtime) storedProcessLocked(proc *processState) StoredProcess {
	var tags map[string]string
	if session := r.sessions[proc.sessionID]; session != nil {
		tags = cloneTags(session.tags)
	}
	return StoredProcess{
		TenantID:          r.tenantID,
		ID:                proc.id,
		SessionID:         proc.sessionID,
		Revision:          proc.revision,
		Message:           proc.message,
		Status:            proc.status,
		Attempt:           proc.attempt,
		CreatedAt:         proc.createdAt,
		UpdatedAt:         proc.updatedAt,
		StartedAt:         copyTime(proc.startedAt),
		CompletedAt:       copyTime(proc.completedAt),
		Answer:            proc.answer,
		Error:             proc.err,
		Manifest:          cloneManifest(proc.manifest),
		ProgramDigest:     proc.programDigest,
		Tags:              tags,
		ParentProcessID:   proc.parentProcessID,
		ChildProcessIDs:   append([]string(nil), proc.childProcessIDs...),
		ChildSpawnOffsets: append([]int(nil), proc.childSpawnOffsets...),
		ForkOffset:        proc.forkOffset,
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
