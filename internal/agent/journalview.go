package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Capability-journal events. Each journal record (an intent or a completion)
// is a syscall.recorded event carrying the record verbatim, stamped with the
// revision that wrote it. The fork structure (which revision shared which
// prefix) is fully derivable from the flat set of (position, revision) pairs —
// no separate fork event is needed.
const evSyscall = "syscall.recorded"

type syscallRecordData struct {
	Record journaled.Record `json:"record"`
}

// processHistory holds every record written for a process, in every revision,
// by position. It is the only copy of the records: every revision of the
// process reads from it, with no parent-pointer chain.
//
// That works because revisions form a line. Each fork starts from the current
// revision, and a revision writes only from its fork offset on. So the record a
// revision sees at a position is the one the highest revision not above it
// wrote there.
type processHistory struct {
	mu    sync.Mutex
	byPos map[int][]journaled.Record
}

func newProcessHistory() *processHistory {
	return &processHistory{byPos: make(map[int][]journaled.Record)}
}

// add keeps a record that its revision already stamped.
func (h *processHistory) add(rec journaled.Record) {
	h.mu.Lock()
	h.byPos[rec.Position] = append(h.byPos[rec.Position], rec)
	h.mu.Unlock()
}

// getAt returns a copy of the record at position with the highest revision ≤ maxRev.
func (h *processHistory) getAt(position int, maxRev uint64) (journaled.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var best *journaled.Record
	for i, rec := range h.byPos[position] {
		if rec.Revision <= maxRev && (best == nil || rec.Revision > best.Revision) {
			best = &h.byPos[position][i]
		}
	}
	if best == nil {
		return journaled.Record{}, false
	}
	return copyRecord(*best), true
}

// length is one past the last record a revision wrote, or its fork offset when
// it wrote nothing yet.
func (h *processHistory) length(revision uint64, forkOffset int) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	length := forkOffset
	for position, written := range h.byPos {
		for _, rec := range written {
			if rec.Revision == revision && position >= length {
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
			if intent.Kind != journaled.KindIntent {
				continue // completions fold into their intent's entry
			}
			entry := JournalEntry{
				Position: position,
				Revision: intent.Revision,
				Syscall:  intent.Syscall.Copy(),
				Outcome:  JournalOutcome{Status: sys.StatusYield, Message: "in flight"},
			}
			for _, completion := range h.byPos[position+1] {
				if completion.Revision == intent.Revision {
					entry.Outcome = encodeOutcome(completion.Result.Copy())
				}
			}
			entries = append(entries, entry)
		}
	}
	slices.SortFunc(entries, func(a, b JournalEntry) int {
		return cmp.Or(cmp.Compare(a.Position, b.Position), cmp.Compare(a.Revision, b.Revision))
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
	if index < j.Length() {
		if rec, ok := j.history.getAt(index, j.rev); ok {
			return rec, nil
		}
	}
	return journaled.Record{}, fmt.Errorf("journal record not found at index %d", index)
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
	ev, err := durable.EncodeEvent(evSyscall, j.proc, j.rev, j.now(), syscallRecordData{Record: stored})
	if err != nil {
		return err
	}
	if _, err := j.log.Append(context.Background(), j.session, ev); err != nil {
		return err
	}
	// The record is in the history before the length admits it, so a Load
	// below Length always finds it.
	j.history.add(stored)
	j.length++
	return nil
}

// outermostOpenBegin finds the outermost sys.begin that no sys.commit closed,
// counting only completed calls. It returns the fork offset one past that
// begin's completion, so replay serves the marker and the section's whole body
// runs live again. That section is the unit the program was inside when it
// stopped. With no open begin it returns false.
//
// The journal is intent/completion pairs, so a call's intent is at an even
// position and its completion follows it.
func (j *logJournal) outermostOpenBegin() (int, bool) {
	length := j.Length()
	depth, forkOffset := 0, 0
	for i := 0; i+1 < length; i += 2 {
		intent, _ := j.Load(i)
		switch intent.Syscall.Name {
		case sys.SyscallBegin:
			if depth == 0 {
				forkOffset = i + 2
			}
			depth++
		case sys.SyscallCommit:
			if depth > 0 {
				depth--
			}
		}
	}
	return forkOffset, depth > 0
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
		histories[ev.Proc].add(sd.Record)
	}
	return histories, nil
}
