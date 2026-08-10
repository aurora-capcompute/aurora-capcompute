package agent

// Read projections: the *Locked helpers that fold in-memory session and process state
// into the immutable snapshots the public API returns, plus the small pure
// helpers (titles, visible capabilities, defensive copies) they lean on.

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

func (r *Runtime) sessionSummaryLocked(session *sessionState) SessionSummary {
	return SessionSummary{
		ID:              session.id,
		Name:            session.name,
		Title:           session.title,
		CreatedAt:       session.createdAt,
		UpdatedAt:       session.updatedAt,
		ProcessCount:    len(session.processIDs),
		ActiveProcessID: session.activeProcessID,
		Tags:            durable.CloneTags(session.tags),
	}
}

// storedSessionLocked builds the durable identity a session.state event carries.
func (r *Runtime) storedSessionLocked(session *sessionState) durable.Session {
	return durable.Session{
		TenantID:  r.tenantID,
		ID:        session.id,
		Name:      session.name,
		CreatedAt: session.createdAt,
		UpdatedAt: session.updatedAt,
		Tags:      durable.CloneTags(session.tags),
	}
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
		Input:         proc.input,
		Status:        proc.status,
		Attempt:       proc.attempt,
		Revision:      proc.revision,
		Answer:        proc.answer,
		Error:         proc.err,
		Labels:        append([]string(nil), proc.labels...),
		JournalLength: journalLength,
		CreatedAt:     proc.createdAt,
		UpdatedAt:     proc.updatedAt,
		StartedAt:     copyTime(proc.startedAt),
		CompletedAt:   copyTime(proc.completedAt),
		Manifest:      proc.manifest.Clone(),
		ProgramDigest: proc.digest.ArtifactDigest,
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
	dup := *value
	return &dup
}

// visibleCapabilities drops capabilities marked Hidden (e.g. the LLM cognition
// syscall and the runtime's protocol calls) from the program's discoverable
// menu. Hidden is set at build time on each published capability, so it works
// even when a driver's published operation names differ from its local name.
func visibleCapabilities(caps []sys.Capability) []sys.Capability {
	visible := make([]sys.Capability, 0, len(caps))
	for _, c := range caps {
		if !c.Hidden {
			visible = append(visible, c)
		}
	}
	return visible
}

func (r *Runtime) processContextLocked(proc *processState) ProcessContext {
	return ProcessContext{
		TenantID:  r.tenantID,
		SessionID: proc.sessionID,
		ProcessID: proc.id,
		Revision:  proc.revision,
		Digest:    proc.digest,
	}
}

func (r *Runtime) storedProcessLocked(proc *processState) durable.Process {
	var tags map[string]string
	if session := r.sessions[proc.sessionID]; session != nil {
		tags = durable.CloneTags(session.tags)
	}
	return durable.Process{
		TenantID:         r.tenantID,
		ID:               proc.id,
		SessionID:        proc.sessionID,
		Revision:         proc.revision,
		Input:            proc.input,
		Status:           proc.status,
		Attempt:          proc.attempt,
		CreatedAt:        proc.createdAt,
		UpdatedAt:        proc.updatedAt,
		StartedAt:        copyTime(proc.startedAt),
		CompletedAt:      copyTime(proc.completedAt),
		Answer:           proc.answer,
		Error:            proc.err,
		Manifest:         proc.manifest.Clone(),
		ProgramDigest:    proc.digest.ArtifactDigest,
		SourceCodeDigest: proc.digest.SourceCodeDigest,
		HideHistory:      proc.hideHistory,
		Labels:           append([]string(nil), proc.labels...),
		Tags:             tags,
		ForkOffset:       proc.forkOffset,
		AbortRetries:     proc.abortRetries,
	}
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
