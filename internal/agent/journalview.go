package agent

import (
	"context"
	"encoding/json"
	"errors"
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
// for a process. All logJournal instances for the same process share one
// processHistory so a forked revision can serve its shared prefix without a
// parent-pointer chain.
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

// logJournal implements journaled.Journal over an event stream. Positions
// [0, forkOffset) are served from the shared processHistory (written by prior
// revisions); positions [forkOffset, ...) are from this revision's own records.
// A record appended at forkOffset continues the shared prefix, whose tail Load
// serves verbatim.
type logJournal struct {
	log     eventlog.Log
	session string
	proc    string
	rev     uint64
	now     func() time.Time

	history    *processHistory
	forkOffset int // positions [0, forkOffset) come from history

	mu      sync.Mutex
	records []journaled.Record // records appended during this revision
}

func newLogJournal(
	log eventlog.Log,
	session string,
	proc string,
	rev uint64,
	history *processHistory,
	forkOffset int,
	now func() time.Time,
) *logJournal {
	return &logJournal{
		log: log, session: session, proc: proc, rev: rev,
		history: history, forkOffset: forkOffset,
		now: now,
	}
}

func (j *logJournal) Length() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.forkOffset + len(j.records)
}

func (j *logJournal) Load(index int) (journaled.Record, error) {
	if index < j.forkOffset {
		// Shared prefix: served from history. By contract this revision never
		// writes to positions < forkOffset, so j.rev is a safe upper bound.
		rec, ok := j.history.getAt(index, j.rev)
		if !ok {
			return journaled.Record{}, fmt.Errorf("journal record not found at index %d", index)
		}
		return rec, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	local := index - j.forkOffset
	if local < 0 || local >= len(j.records) {
		return journaled.Record{}, errors.New("journal record not found")
	}
	return copyRecord(j.records[local]), nil
}

func (j *logJournal) Append(rec journaled.Record) error {
	j.mu.Lock()
	if rec.Position != j.forkOffset+len(j.records) {
		j.mu.Unlock()
		return fmt.Errorf("invalid journal position %d (want %d)", rec.Position, j.forkOffset+len(j.records))
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
		j.mu.Unlock()
		return err
	}
	if _, err := j.log.Append(context.Background(), j.session, ev); err != nil {
		j.mu.Unlock()
		return err
	}
	j.records = append(j.records, stored)
	j.history.add(rec.Position, j.rev, stored) // update shared history while still holding j.mu
	j.mu.Unlock()
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

// foldJournals rebuilds every revision's journal for a session stream from its
// syscall.recorded events. Revisions are linked to a shared processHistory so
// forked journals can serve the shared prefix without parent-pointer chains. It
// returns both the journals and the per-process histories (so callers that need
// to create new revisions for an existing process can share the same history).
// Every other event kind is skipped: only journal events carry journal records.
func foldJournals(
	events []eventlog.Event,
	log eventlog.Log,
	session string,
	now func() time.Time,
) (map[string]map[uint64]*logJournal, map[string]*processHistory, error) {
	histories := map[string]*processHistory{}
	revData := map[string]map[uint64][]journaled.Record{} // process → rev → records (in log order)

	for _, ev := range events {
		if ev.Kind != evSyscall {
			continue
		}
		var sd syscallRecordData
		if err := json.Unmarshal(ev.Data, &sd); err != nil {
			return nil, nil, fmt.Errorf("decode syscall.recorded: %w", err)
		}
		rev := ev.Rev // authoritative; sd.Revision is the same on new events
		if histories[ev.Proc] == nil {
			histories[ev.Proc] = newProcessHistory()
		}
		histories[ev.Proc].add(sd.Record.Position, rev, sd.Record)
		if revData[ev.Proc] == nil {
			revData[ev.Proc] = map[uint64][]journaled.Record{}
		}
		revData[ev.Proc][rev] = append(revData[ev.Proc][rev], sd.Record)
	}

	result := map[string]map[uint64]*logJournal{}
	for proc, history := range histories {
		result[proc] = map[uint64]*logJournal{}
		for rev, records := range revData[proc] {
			// Sort by position so forkOffset = records[0].Position is reliable.
			sort.Slice(records, func(i, k int) bool { return records[i].Position < records[k].Position })
			forkOffset := 0
			if len(records) > 0 {
				forkOffset = records[0].Position
			}
			j := newLogJournal(log, session, proc, rev, history, forkOffset, now)
			j.records = append(j.records, records...)
			result[proc][rev] = j
		}
		// A revision that forked but crashed before its first record still
		// needs a journal view; restore synthesizes it from process state.
	}
	return result, histories, nil
}
