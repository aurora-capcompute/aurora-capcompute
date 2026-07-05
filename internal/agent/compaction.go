package agent

// Journal lifecycle (ROADMAP #16): snapshot + compaction.
//
// appendProcess writes a full StoredProcess per lifecycle transition, so a
// session's stream grows super-linearly with activity. Compaction rewrites the
// stream — in the spirit of event-sourcing snapshots and Temporal's
// ContinueAsNew — as one session.snapshot event (every process's latest state
// plus every task record) followed by the retained journal tail, atomically,
// renumbering Seq from 1.
//
// The law: a compacted stream folds to the same projection; only terminal
// processes' journals are traded away. Retention keeps the journal.header and
// syscall.recorded events of every process that is not in a terminal-final
// status ({completed, failed, stopped, compensated}) — an interrupted, parked,
// or mid-rollback process resumes by replaying its journal, so that journal
// must survive verbatim and in original relative order. Finished processes
// lose their journal entries: bounded storage for finished work is the trade,
// and the snapshot keeps their final states, answers, and tasks. After a
// restore, a compacted-away journal reads as empty — a completed process's
// Journal() view is gone, and a failed/stopped one can only be re-driven as a
// fresh fork-0 revision (restart-equivalent), never replayed.
//
// Live views are untouched by design: logJournal serves Header/Load from the
// in-memory processHistory and never re-reads the log, so an in-flight or
// parked process's journal view cannot observe the rewrite. The invariant is
// enforced where the log is actually read — restore — and proven there by the
// compaction tests.

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
)

// isFinalStatus reports whether a process is terminal-final for journal
// retention: it will never replay its journal again (a completed process can
// only be restarted from scratch as a fresh revision). Deliberately narrower
// than isTerminal: interrupted is terminal for delegation accounting but
// resumes by replay, so its journal must be retained.
func isFinalStatus(status ProcessStatus) bool {
	switch status {
	case ProcessCompleted, ProcessFailed, ProcessStopped, ProcessCompensated:
		return true
	default:
		return false
	}
}

// CompactSession rewrites one session's stream as [session.snapshot] +
// [retained journal events], atomically renumbering Seq from 1. It refuses
// (ErrConflict) while any of the session's processes is queued, running, or
// stopping: an executing quantum appends journal records outside the runtime
// mutex, and compaction must capture a stream no writer is extending. Every
// other append path either runs under the runtime mutex (all process.state
// transitions) or under the task store's lock (task events), both of which are
// held across the read-and-swap — so the rewrite is exact, not best-effort.
// An empty stream (a session that never persisted anything) is a no-op.
func (r *Runtime) CompactSession(sessionID string) error {
	return r.compactSession(context.Background(), sessionID, false)
}

// CompactSessions compacts every session, skipping the ones that cannot or
// need not compact: sessions with an executing quantum (ErrConflict — they are
// caught on a later sweep) and sessions where retention would keep everything,
// i.e. the rewrite would not shrink the stream (a freshly compacted stream
// stays put until new events land). Errors from individual sessions are
// joined, not short-circuiting, so one bad stream cannot starve the rest.
func (r *Runtime) CompactSessions(ctx context.Context) error {
	r.mu.Lock()
	ids := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	sort.Strings(ids)

	var errs []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		if err := r.compactSession(ctx, id, true); err != nil && !errors.Is(err, ErrConflict) {
			errs = append(errs, fmt.Errorf("compact session %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// compactSession builds and applies one session's compacted stream under the
// runtime mutex and the task store freeze. With skipNoop, a rewrite that would
// not shrink the stream is skipped (the periodic sweep's no-op guard); an
// explicit CompactSession always applies.
func (r *Runtime) compactSession(ctx context.Context, sessionID string, skipNoop bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		return fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	for _, processID := range session.processIDs {
		proc := r.processes[processID]
		if proc == nil {
			continue
		}
		switch proc.status {
		case ProcessQueued, ProcessRunning, ProcessStopping:
			return fmt.Errorf("%w: process %s is %s; compaction requires a quiescent session",
				ErrConflict, processID, proc.status)
		}
	}
	// Freeze task events: ResolveTask appends task.resolved without the runtime
	// mutex, and an append between our read and the swap would be erased.
	defer r.tasks.freeze()()

	scope := r.scope(sessionID)
	stream, err := r.log.Read(ctx, scope, 0)
	if err != nil {
		return err
	}
	if len(stream) == 0 {
		return nil // nothing durable yet — nothing to rewrite
	}

	// The snapshot base is the in-memory state, which is the fold of the stream
	// plus any transition whose append was lost to a store hiccup — compacting
	// from memory re-persists the authoritative state.
	processes := make([]StoredProcess, 0, len(session.processIDs))
	dropJournal := make(map[string]bool, len(session.processIDs))
	for _, processID := range session.processIDs {
		proc := r.processes[processID]
		if proc == nil {
			continue
		}
		processes = append(processes, r.storedProcessLocked(proc))
		dropJournal[processID] = isFinalStatus(proc.status)
	}
	snapshot, err := sessionSnapshotEvent(r.now().UTC(), processes,
		r.tasks.sessionRecordsLocked(r.tenantID, sessionID))
	if err != nil {
		return err
	}

	// The retained tail: every journal event of every non-final process, in
	// original relative order (replay depends on it). Journal events of a
	// process this runtime does not know are retained, never silently dropped.
	// Everything else — process.state, task.*, prior session.snapshot events —
	// is subsumed by the fresh snapshot.
	compacted := make([]eventlog.Event, 0, len(stream)/2+1)
	compacted = append(compacted, snapshot)
	for _, ev := range stream {
		switch ev.Kind {
		case evJournalHeader, evSyscall:
			if !dropJournal[ev.Proc] {
				compacted = append(compacted, ev)
			}
		}
	}
	if skipNoop && len(compacted) >= len(stream) {
		return nil
	}
	return r.log.Compact(ctx, scope, compacted)
}
