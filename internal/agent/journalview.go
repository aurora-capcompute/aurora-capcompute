package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"
)

// Capability-journal events. Each journal record (an intent, a completion, or
// a compensation pair member — the kernel's envelope+payload shape, hash chain
// included) is a syscall.recorded event carrying the record verbatim plus the
// revision that produced it. The fork structure (which revision shared which
// prefix) is fully derivable from the flat set of (position, revision) pairs —
// no separate fork event is needed. A journal.header event pins the writer
// identity (ABI, program digest, proc) per revision, so replaying a journal
// under a different program is refused up front.
const (
	evSyscall       = "syscall.recorded"
	evJournalHeader = "journal.header"
)

type syscallRecordData struct {
	Revision uint64           `json:"revision"` // mirrors ev.Rev for self-documentation
	Record   journaled.Record `json:"record"`
}

type journalHeaderData struct {
	Revision uint64           `json:"revision"`
	Header   journaled.Header `json:"header"`
}

// processHistory accumulates every (position, revision, record) triple and every
// revision header written for a process. All logJournal instances for the same process
// share one processHistory so a forked revision can serve its shared prefix
// without a parent-pointer chain.
type processHistory struct {
	mu      sync.Mutex
	byPos   map[int][]histEntry
	headers map[uint64]journaled.Header
}

type histEntry struct {
	revision uint64
	record   journaled.Record
}

func newProcessHistory() *processHistory {
	return &processHistory{byPos: make(map[int][]histEntry), headers: make(map[uint64]journaled.Header)}
}

func (h *processHistory) add(position int, revision uint64, rec journaled.Record) {
	h.mu.Lock()
	h.byPos[position] = append(h.byPos[position], histEntry{revision: revision, record: rec})
	h.mu.Unlock()
}

func (h *processHistory) setHeader(revision uint64, header journaled.Header) {
	h.mu.Lock()
	h.headers[revision] = header
	h.mu.Unlock()
}

// ownHeader returns the header stamped by revision rev itself, if any.
func (h *processHistory) ownHeader(rev uint64) (journaled.Header, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	header, ok := h.headers[rev]
	return header, ok
}

// header returns the journal header governing revision rev: the revision's own
// header if stamped, else the highest earlier revision's (the writer identity
// a forked journal inherits with its shared prefix).
func (h *processHistory) header(rev uint64) (journaled.Header, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if header, ok := h.headers[rev]; ok {
		return header, true
	}
	var best uint64
	var found bool
	var out journaled.Header
	for r, header := range h.headers {
		if r < rev && (!found || r > best) {
			best, found, out = r, true, header
		}
	}
	return out, found
}

// allRevisions returns all distinct revision numbers in the history, sorted ascending.
func (h *processHistory) allRevisions() []uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := make(map[uint64]struct{})
	for _, entries := range h.byPos {
		for _, e := range entries {
			seen[e.revision] = struct{}{}
		}
	}
	out := make([]uint64, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// lengthAt returns the journal length effective at revision rev: one past the
// highest position holding a record with revision ≤ rev.
func (h *processHistory) lengthAt(rev uint64) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	length := 0
	for position, entries := range h.byPos {
		for _, e := range entries {
			if e.revision <= rev && position+1 > length {
				length = position + 1
			}
		}
	}
	return length
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

// revAt returns the revision number of the record at position with the highest
// revision ≤ maxRev. Used to annotate shared-prefix entries with their origin revision.
func (h *processHistory) revAt(position int, maxRev uint64) (uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var best uint64
	found := false
	for _, e := range h.byPos[position] {
		if e.revision <= maxRev && (!found || e.revision > best) {
			best = e.revision
			found = true
		}
	}
	return best, found
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
	if rec.Compensates != nil {
		compensates := *rec.Compensates
		out.Compensates = &compensates
	}
	return out
}

// logJournal implements journaled.Journal over an event stream. Positions
// [0, forkOffset) are served from the shared processHistory (written by prior
// revisions); positions [forkOffset, ...) are from this revision's own records.
// Hash-chain integrity holds across the fork: a record appended at forkOffset
// chains from the shared prefix's tail record, which Load serves verbatim.
type logJournal struct {
	log      eventlog.Log
	scope    eventlog.Scope
	proc     string
	rev      uint64
	now      func() time.Time
	onAppend func(proc string, revision uint64, rec journaled.Record, syscallName string)

	history    *processHistory
	forkOffset int // positions [0, forkOffset) come from history

	mu      sync.Mutex
	records []journaled.Record // records appended during this revision
}

func newLogJournal(
	log eventlog.Log,
	scope eventlog.Scope,
	proc string,
	rev uint64,
	history *processHistory,
	forkOffset int,
	now func() time.Time,
	onAppend func(string, uint64, journaled.Record, string),
) *logJournal {
	return &logJournal{
		log: log, scope: scope, proc: proc, rev: rev,
		history: history, forkOffset: forkOffset,
		now: now, onAppend: onAppend,
	}
}

func (j *logJournal) Header() (journaled.Header, bool, error) {
	if header, ok := j.history.ownHeader(j.rev); ok {
		return header, true, nil
	}
	// A forked journal inherits the writer identity of the shared prefix it
	// replays, so a resume under a different program digest is refused by the
	// tape. A fresh (fork-0) journal inherits nothing: a hard restart may
	// legitimately run a different program.
	if j.forkOffset > 0 {
		if header, ok := j.history.header(j.rev); ok {
			return header, true, nil
		}
	}
	return journaled.Header{}, false, nil
}

func (j *logJournal) SetHeader(header journaled.Header) error {
	ev, err := encodeEvent(evJournalHeader, j.proc, j.rev, j.now(), journalHeaderData{
		Revision: j.rev,
		Header:   header,
	})
	if err != nil {
		return err
	}
	if _, err := j.log.Append(context.Background(), j.scope, ev); err != nil {
		return err
	}
	j.history.setHeader(j.rev, header)
	return nil
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
	// the shared prefix keep the revision that first wrote them, which is what
	// scopes intent identity (idempotency keys) to the attempt — a re-driven
	// open intent keeps its original key; a rolled-back section's re-execution
	// writes fresh records here and gets a fresh key space.
	stored.Revision = j.rev
	ev, err := encodeEvent(evSyscall, j.proc, j.rev, j.now(), syscallRecordData{
		Revision: j.rev,
		Record:   stored,
	})
	if err != nil {
		j.mu.Unlock()
		return err
	}
	if _, err := j.log.Append(context.Background(), j.scope, ev); err != nil {
		j.mu.Unlock()
		return err
	}
	j.records = append(j.records, stored)
	j.history.add(rec.Position, j.rev, stored) // update shared history while still holding j.mu
	name := j.syscallNameLocked(stored)
	j.mu.Unlock()
	if j.onAppend != nil {
		j.onAppend(j.proc, j.rev, stored, name)
	}
	return nil
}

// syscallNameLocked resolves the syscall a record belongs to: an intent
// carries it; a completion pairs with the immediately preceding intent.
func (j *logJournal) syscallNameLocked(rec journaled.Record) string {
	if rec.Syscall != nil {
		return rec.Syscall.Name
	}
	prev := rec.Position - 1
	if prev < j.forkOffset {
		if intent, ok := j.history.getAt(prev, j.rev); ok && intent.Syscall != nil {
			return intent.Syscall.Name
		}
		return ""
	}
	local := prev - j.forkOffset
	if local >= 0 && local < len(j.records) && j.records[local].Syscall != nil {
		return j.records[local].Syscall.Name
	}
	return ""
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
	for i := 0; i < length; i++ {
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

// entries pairs the journal's intent/completion records into per-syscall
// entries. An intent with no completion (an open intent — a crash window or a
// pending external task) yields an entry with a yield outcome; callers render
// it as in-flight.
func (j *logJournal) entries() ([]JournalEntry, error) {
	length := j.Length()
	entries := make([]JournalEntry, 0, length/2+1)
	for i := 0; i < length; i++ {
		rec, err := j.Load(i)
		if err != nil {
			return nil, err
		}
		if rec.Syscall == nil {
			continue // completions fold into their intent's entry below
		}
		rev := j.rev
		if r, ok := j.history.revAt(i, j.rev); ok {
			rev = r
		}
		entry := JournalEntry{
			Position: rec.Position,
			Revision: rev,
			Syscall:  *rec.Syscall,
			Outcome:  JournalOutcome{Status: sys.StatusYield, Message: "in flight"},
		}
		if rec.Kind == journaled.KindCompensationIntent {
			entry.Compensates = rec.Compensates
		}
		if i+1 < length {
			completion, err := j.Load(i + 1)
			if err != nil {
				return nil, err
			}
			if completion.Result != nil {
				entry.Outcome = encodeOutcome(*completion.Result)
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
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
// syscall.recorded and journal.header events. Revisions are linked to a shared
// processHistory so forked journals can serve the shared prefix without
// parent-pointer chains. It returns both the journals and the per-process
// histories (so callers that need to create new revisions for an existing process
// can share the same history). Every other event kind is skipped: only journal
// events carry journal records.
func foldJournals(
	events []eventlog.Event,
	log eventlog.Log,
	scope eventlog.Scope,
	now func() time.Time,
	onAppend func(string, uint64, journaled.Record, string),
) (map[string]map[uint64]*logJournal, map[string]*processHistory, error) {
	histories := map[string]*processHistory{}
	revData := map[string]map[uint64][]journaled.Record{} // process → rev → records (in log order)

	for _, ev := range events {
		switch ev.Kind {
		case evJournalHeader:
			var hd journalHeaderData
			if err := json.Unmarshal(ev.Data, &hd); err != nil {
				return nil, nil, fmt.Errorf("decode journal.header: %w", err)
			}
			if histories[ev.Proc] == nil {
				histories[ev.Proc] = newProcessHistory()
			}
			histories[ev.Proc].setHeader(ev.Rev, hd.Header)
		case evSyscall:
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
			j := newLogJournal(log, scope, proc, rev, history, forkOffset, now, onAppend)
			j.records = append(j.records, records...)
			result[proc][rev] = j
		}
		// A revision that stamped a header but crashed before its first record
		// still needs a journal view; restore synthesizes it from process state.
	}
	return result, histories, nil
}
