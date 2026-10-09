// Package journaled is a replay Tape backed by an append-only Journal of
// intent/completion records: an intent is appended before a syscall executes
// (journal-before-execute), a completion after its outcome is known and
// before the guest observes it (journal-before-observe). It serves recorded
// pairs in order, raises ReplayDivergedError when a re-run guest issues a
// syscall that does not match the recorded sequence, and surfaces an intent
// without completion as replay.OpenIntentError. It owns the on-tape record
// format — a fixed envelope (position, kind, revision) plus an opaque
// syscall/result payload; the Journal itself — where records durably live — is
// supplied by the caller. Verify checks a journal's structure, not its
// authenticity: the records are not chained, so a store that rewrites one is
// not detected.
package journaled

import (
	"bytes"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Kind classifies a journal record within the fixed envelope.
type Kind string

const (
	// KindIntent records that a syscall is about to execute.
	KindIntent Kind = "intent"
	// KindCompletion records the outcome of the immediately preceding intent.
	KindCompletion Kind = "completion"
)

// Record is one journal entry: a fixed envelope — the store's index keys —
// plus an opaque payload. A datum lives in the envelope or in the payload,
// never both. Scope columns above the process (the session) belong to the
// store that owns the Journal.
type Record struct {
	// Envelope.
	Position int  `json:"position"`
	Kind     Kind `json:"kind"`
	// Revision is the attempt that first wrote this record, stamped by the
	// Journal implementation at append (zero when the journal has no attempt
	// notion). A record in a fork's shared prefix keeps its origin revision.
	Revision uint64 `json:"revision,omitempty"`

	// Payload: exactly one of the two, by Kind.
	Syscall *sys.Syscall       `json:"syscall,omitempty"`
	Result  *sys.SyscallResult `json:"result,omitempty"`
}

// Journal stores durable records for a tape. Append must persist the record at
// index Length().
type Journal interface {
	Load(idx int) (Record, error)
	Append(Record) error
	Length() int
}

// ReplayDivergedError means the guest requested a different syscall than history recorded.
type ReplayDivergedError struct {
	Index int
	Want  sys.Syscall
	Got   sys.Syscall
}

func (e ReplayDivergedError) Error() string {
	return fmt.Sprintf("replay diverged at syscall %d: want %q got %q", e.Index, e.Want.Name, e.Got.Name)
}

// CorruptJournalError means the journal's record structure is invalid — not a
// divergence (guest behavior) but damage or a buggy store.
type CorruptJournalError struct {
	Position int
	Reason   string
}

func (e CorruptJournalError) Error() string {
	return fmt.Sprintf("journal corrupt at position %d: %s", e.Position, e.Reason)
}

// Tape is a journal-backed replay tape.
type Tape struct {
	journal Journal
	cursor  int
	pending bool // an intent is open and owned by the in-flight dispatch
}

// NewTape creates a journal-backed replay tape whose cursor starts at the
// beginning. The journal belongs to one process, and the process is bound to
// one program for life, so the tape replays only what that program wrote.
func NewTape(journal Journal) *Tape {
	return &Tape{journal: journal}
}

// Next returns a recorded outcome for syscall, ok=false when syscall is new,
// or replay.OpenIntentError when the journal ends in this syscall's intent
// with no completion. The journal's structure was checked by Verify before the
// quantum began, so every record is the kind its position says.
func (t *Tape) Next(syscall sys.Syscall) (sys.SyscallResult, bool, error) {
	if t.cursor >= t.journal.Length() {
		return sys.SyscallResult{}, false, nil
	}
	intent, err := t.journal.Load(t.cursor)
	if err != nil {
		return sys.SyscallResult{}, false, err
	}
	if !sameSyscall(*intent.Syscall, syscall) {
		return sys.SyscallResult{}, false, ReplayDivergedError{Index: t.cursor, Want: *intent.Syscall, Got: syscall}
	}
	if t.cursor+1 >= t.journal.Length() {
		// Open intent at the tail: dispatched once, outcome unknown.
		t.cursor++
		t.pending = true
		return sys.SyscallResult{}, false, replay.OpenIntentError{Position: intent.Position, Syscall: syscall}
	}
	completion, err := t.journal.Load(t.cursor + 1)
	if err != nil {
		return sys.SyscallResult{}, false, err
	}
	t.cursor += 2
	return *completion.Result, true, nil
}

// Begin appends the intent record for a fresh syscall — before it executes. It
// refuses while an intent is open: a guest that keeps calling after a yield
// would otherwise write a second intent behind the first.
func (t *Tape) Begin(syscall sys.Syscall) error {
	if t.pending {
		return fmt.Errorf("begin: an intent is already open at position %d", t.journal.Length()-1)
	}
	recorded := syscall.Copy()
	if err := appendRecord(t.journal, Record{Kind: KindIntent, Syscall: &recorded}); err != nil {
		return err
	}
	t.cursor++
	t.pending = true
	return nil
}

// Commit appends the completion record for the open intent — after the
// outcome is known and before the guest observes it.
func (t *Tape) Commit(result sys.SyscallResult) error {
	recorded := result.Copy()
	if err := appendRecord(t.journal, Record{Kind: KindCompletion, Result: &recorded}); err != nil {
		return err
	}
	t.cursor++
	t.pending = false
	return nil
}

// Verify walks the whole journal and checks its structure: positions in
// order, and alternating intent/completion with at most one open intent at the
// tail. It returns CorruptJournalError at the first damage found.
func Verify(journal Journal) error {
	// Structure: intent/completion pairs, with at most one trailing open
	// intent — an abandoned revision may leave its last intent open forever
	// (the failing dispatch never completed), and that is legal history.
	const (
		wantIntent = iota
		wantCompletion
	)
	expect := wantIntent
	for position := 0; position < journal.Length(); position++ {
		record, err := journal.Load(position)
		if err != nil {
			return err
		}
		if record.Position != position {
			return CorruptJournalError{Position: position, Reason: fmt.Sprintf("record carries position %d", record.Position)}
		}
		switch expect {
		case wantIntent:
			if record.Kind != KindIntent || record.Syscall == nil {
				return CorruptJournalError{Position: position, Reason: "expected an intent record"}
			}
			expect = wantCompletion
		case wantCompletion:
			if record.Kind != KindCompletion || record.Result == nil {
				return CorruptJournalError{Position: position, Reason: "expected a completion record"}
			}
			expect = wantIntent
		}
	}
	return nil
}

// appendRecord appends one record at the journal tail, stamped with its
// position. Every appender goes through here, so positioning cannot drift
// between them.
func appendRecord(journal Journal, record Record) error {
	record.Position = journal.Length()
	return journal.Append(record)
}

func sameSyscall(left sys.Syscall, right sys.Syscall) bool {
	return left.Name == right.Name && bytes.Equal(left.Args, right.Args)
}
