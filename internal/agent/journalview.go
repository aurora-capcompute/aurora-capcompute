package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability-journal events. Each journal record (an intent or a completion)
// is a syscall.recorded event carrying the record verbatim plus the revision
// that produced it. The fork structure (which revision shared which prefix) is
// fully derivable from the flat set of (position, revision) pairs — no
// separate fork event is needed.
const evSyscall = "syscall.recorded"

type syscallRecordData struct {
	Revision uint64           `json:"revision"` // mirrors ev.Rev for self-documentation
	Record   journaled.Record `json:"record"`
}

// processHistory accumulates every (position, revision, record) triple written
// for a process. It is the only copy of the records: every revision of the
// process reads from it, with no parent-pointer chain.
//
// That works because revisions form a line. Each fork starts from the current
// revision, and a revision writes only from its fork offset on. So the record a
// revision sees at a position is the one the highest revision not above it
// wrote there.
type processHistory struct {
	mu    sync.Mutex
	byPos map[int][]histEntry
}

type histEntry struct {
	revision uint64
	record   journaled.Record
}

func newProcessHistory() *processHistory {
	return &processHistory{byPos: make(map[int][]histEntry)}
}

func (h *processHistory) add(position int, revision uint64, rec journaled.Record) {
	h.mu.Lock()
	h.byPos[position] = append(h.byPos[position], histEntry{revision: revision, record: rec})
	h.mu.Unlock()
}

// getAt returns a copy of the record at position with the highest revision ≤ maxRev.
func (h *processHistory) getAt(position int, maxRev uint64) (journaled.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var best *histEntry
	for i := range h.byPos[position] {
		e := &h.byPos[position][i]
		if e.revision <= maxRev && (best == nil || e.revision > best.revision) {
			best = e
		}
	}
	if best == nil {
		return journaled.Record{}, false
	}
	return copyRecord(best.record), true
}

// length is one past the last record a revision wrote, or its fork offset when
// it wrote nothing yet.
func (h *processHistory) length(revision uint64, forkOffset int) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	length := forkOffset
	for position, written := range h.byPos {
		for _, e := range written {
			if e.revision == revision && position >= length {
				length = position + 1
			}
		}
	}
	return length
}

// entries pairs every intent the process ever journaled, in every revision,
// with its completion: the record its own revision wrote one position later. A
// revision writes only from its fork offset on, so its intent's completion is
// never another revision's. An intent with no completion — a crash window, a
// pending task, an abandoned attempt — is in flight.
func (h *processHistory) entries() []JournalEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	entries := []JournalEntry{}
	for position, written := range h.byPos {
		for _, intent := range written {
			if intent.record.Syscall == nil {
				continue // completions fold into their intent's entry
			}
			entry := JournalEntry{
				Position: position,
				Revision: intent.revision,
				Syscall:  intent.record.Syscall.Copy(),
				Outcome:  JournalOutcome{Status: sys.StatusYield, Message: "in flight"},
			}
			for _, completion := range h.byPos[position+1] {
				if completion.revision == intent.revision && completion.record.Result != nil {
					entry.Outcome = encodeOutcome(completion.record.Result.Copy())
				}
			}
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Position != entries[j].Position {
			return entries[i].Position < entries[j].Position
		}
		return entries[i].Revision < entries[j].Revision
	})
	return entries
}

func copyRecord(rec journaled.Record) journaled.Record {
	out := rec
	if rec.Syscall != nil {
		copied := rec.Syscall.Copy()
		out.Syscall = &copied
	}
	if rec.Result != nil {
		copied := rec.Result.Copy()
		out.Result = &copied
	}
	return out
}

// logJournal implements journaled.Journal over an event stream: one revision's
// view of its process's history. Positions before the revision's fork offset
// hold an earlier revision's records, and the rest hold its own.
type logJournal struct {
	log     eventlog.Log
	session string
	proc    string
	rev     uint64
	now     func() time.Time
	history *processHistory

	mu     sync.Mutex
	length int
}

func newLogJournal(
	log eventlog.Log,
	session string,
	proc string,
	rev uint64,
	history *processHistory,
	length int,
	now func() time.Time,
) *logJournal {
	return &logJournal{
		log: log, session: session, proc: proc, rev: rev,
		history: history, length: length,
		now: now,
	}
}

func (j *logJournal) Length() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.length
}

func (j *logJournal) Load(index int) (journaled.Record, error) {
	if index >= j.Length() {
		return journaled.Record{}, fmt.Errorf("journal record not found at index %d", index)
	}
	rec, ok := j.history.getAt(index, j.rev)
	if !ok {
		return journaled.Record{}, fmt.Errorf("journal record not found at index %d", index)
	}
	return rec, nil
}

func (j *logJournal) Append(rec journaled.Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if rec.Position != j.length {
		return fmt.Errorf("invalid journal position %d (want %d)", rec.Position, j.length)
	}
	stored := copyRecord(rec)
	// Stamp the attempt: this revision wrote the record. Records served from
	// the shared prefix keep the revision that first wrote them.
	stored.Revision = j.rev
	ev, err := durable.EncodeEvent(evSyscall, j.proc, j.rev, j.now(), syscallRecordData{
		Revision: j.rev,
		Record:   stored,
	})
	if err != nil {
		return err
	}
	if _, err := j.log.Append(context.Background(), j.session, ev); err != nil {
		return err
	}
	// The record is in the history before the length admits it, so a Load
	// below Length always finds it.
	j.history.add(rec.Position, j.rev, stored)
	j.length++
	return nil
}

// outermostOpenBegin scans the effective journal for the outermost sys.begin
// savepoint that was never closed by a matching sys.commit, treating the
// markers as balanced brackets over completed syscalls. It returns the fork
// offset (one past that begin's completion record, so the marker itself is
// replayed from history and its whole body re-executes live) and true when
// such an open begin exists. The outermost still-open begin is the unit the
// program was inside when it failed; forking there re-runs the whole declared
// unit. With no open begin it returns false and the caller keeps the default
// (replay everything, including recorded soft failures).
func (j *logJournal) outermostOpenBegin() (int, bool) {
	length := j.Length()
	depth := 0
	start := -1 // position of the outermost open begin's completion record
	for i := range length {
		rec, err := j.Load(i)
		if err != nil {
			return 0, false
		}
		if rec.Kind != journaled.KindIntent || rec.Syscall == nil {
			continue
		}
		completed := i+1 < length
		switch rec.Syscall.Name {
		case sys.SyscallBegin:
			if !completed {
				continue // an uncompleted begin intent never bracketed anything
			}
			if depth == 0 {
				start = i + 1
			}
			depth++
		case sys.SyscallCommit:
			if !completed {
				continue
			}
			if depth > 0 {
				depth--
				if depth == 0 {
					start = -1
				}
			}
		}
	}
	if depth > 0 && start >= 0 {
		return start + 1, true
	}
	return 0, false
}

func encodeOutcome(result sys.SyscallResult) JournalOutcome {
	return JournalOutcome{
		Status:  result.Status(),
		Code:    result.Errno(),
		Result:  result.Result(),
		Message: result.Message(),
		Labels:  result.Labels(),
	}
}

// foldJournals rebuilds each process's history for a session stream from its
// syscall.recorded events. Every other event kind is skipped: only journal
// events carry journal records.
func foldJournals(events []eventlog.Event) (map[string]*processHistory, error) {
	histories := map[string]*processHistory{}
	for _, ev := range events {
		if ev.Kind != evSyscall {
			continue
		}
		var sd syscallRecordData
		if err := json.Unmarshal(ev.Data, &sd); err != nil {
			return nil, fmt.Errorf("decode syscall.recorded: %w", err)
		}
		if histories[ev.Proc] == nil {
			histories[ev.Proc] = newProcessHistory()
		}
		histories[ev.Proc].add(sd.Record.Position, ev.Rev, sd.Record)
	}
	return histories, nil
}
