// Package journaled is a replay Tape backed by an append-only Journal of
// intent/completion records: an intent is appended before a syscall executes
// (journal-before-execute), a completion after its outcome is known and
// before the guest observes it (journal-before-observe). It serves recorded
// pairs in order, raises ReplayDivergedError when a re-run guest issues a
// syscall that does not match the recorded sequence, and surfaces an intent
// without completion as replay.OpenIntentError. It owns the on-tape record
// format — a fixed envelope (position, kind, prev_hash) plus an opaque
// syscall/result payload, hash-chained for tamper evidence; the Journal
// itself — where records durably live — is supplied by the caller.
package journaled

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
)

// Kind classifies a journal record within the fixed envelope.
type Kind string

const (
	// KindIntent records that a syscall is about to execute.
	KindIntent Kind = "intent"
	// KindCompletion records the outcome of the immediately preceding intent.
	KindCompletion Kind = "completion"
	// KindCompensationIntent records that an inverse syscall is about to
	// undo the completed effect at the position its Compensates field names.
	// The first compensation record ends the journal's execution section:
	// an unwound process is terminal.
	KindCompensationIntent Kind = "compensation_intent"
	// KindCompensationCompletion records the outcome of the immediately
	// preceding compensation intent.
	KindCompensationCompletion Kind = "compensation_completion"
)

// Header identifies what wrote a journal: the syscall ABI version, the
// program (e.g. an artifact digest), and the process the journal belongs
// to. Replay against a different writer is refused up front — the
// versioned-replay law (see docs/ARCHITECTURE.md, "Coherence under growth")
// — instead of failing later as a confusing divergence. Process also scopes
// the intent identity, so idempotency keys are unique across processes.
type Header struct {
	ABI     int    `json:"abi"`
	Program string `json:"program"`
	Process string `json:"process,omitempty"`
}

// Record is one journal entry: a fixed envelope — the store's index keys —
// plus an opaque payload. A datum lives in the envelope or in the payload,
// never both. Scope columns above the process (tenant, session) belong to the
// store that owns the Journal, keyed by Header.Process.
type Record struct {
	// Envelope.
	Position int    `json:"position"`
	Kind     Kind   `json:"kind"`
	PrevHash string `json:"prev_hash"`
	// Revision is the attempt that first wrote this record, stamped by the
	// Journal implementation at append (zero when the journal has no attempt
	// notion). It scopes the intent identity: a record in a fork's shared
	// prefix keeps its origin revision, so a crash re-drive recomputes the
	// original idempotency key — while a rolled-back section's retry appends
	// fresh records under the new revision and can never adopt the compensated
	// attempt's recorded effects.
	Revision uint64 `json:"revision,omitempty"`
	// Compensates names the intent position a compensation record undoes.
	Compensates *int `json:"compensates,omitempty"`

	// Payload: exactly one of the two, by Kind.
	Syscall *sys.Syscall       `json:"syscall,omitempty"`
	Result  *sys.SyscallResult `json:"result,omitempty"`
}

// Journal stores durable records for a tape, plus the header identifying
// their writer. Append must persist the record at index Length().
type Journal interface {
	Header() (header Header, ok bool, err error)
	SetHeader(Header) error
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

// ReplayIncompatibleError means the journal was written by a different program
// or ABI than the one attempting to replay it.
type ReplayIncompatibleError struct {
	Recorded Header
	Current  Header
}

func (e ReplayIncompatibleError) Error() string {
	return fmt.Sprintf("journal written by program %q (abi %d); cannot replay as program %q (abi %d)",
		e.Recorded.Program, e.Recorded.ABI, e.Current.Program, e.Current.ABI)
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

// ChainBrokenError means a record's prev_hash does not match the digest of
// its predecessor: the journal was altered after the fact.
type ChainBrokenError struct {
	Position int
}

func (e ChainBrokenError) Error() string {
	return fmt.Sprintf("journal hash chain broken at position %d", e.Position)
}

// ProcessUnwoundError means execution replay reached the journal's
// compensation section: this revision was rolled back and its registered
// undos ran; it cannot be resumed.
type ProcessUnwoundError struct {
	Position int
}

func (e ProcessUnwoundError) Error() string {
	return fmt.Sprintf("process was unwound: compensation section starts at position %d", e.Position)
}

// Tape is a journal-backed replay tape.
type Tape struct {
	journal Journal
	header  Header
	cursor  int
	pending bool // an intent is open and owned by the in-flight dispatch
}

// NewTape creates a journal-backed replay tape whose cursor starts at the
// beginning. The header identifies the program about to run: a fresh journal
// is stamped with it; a journal written by a different program, ABI, or
// process is refused with ReplayIncompatibleError.
func NewTape(journal Journal, header Header) (*Tape, error) {
	recorded, ok, err := journal.Header()
	if err != nil {
		return nil, err
	}
	if !ok {
		if err := journal.SetHeader(header); err != nil {
			return nil, err
		}
		return &Tape{journal: journal, header: header}, nil
	}
	if recorded != header {
		return nil, ReplayIncompatibleError{Recorded: recorded, Current: header}
	}
	return &Tape{journal: journal, header: header}, nil
}

// loadExecution reads the record at position and enforces the read path's one
// law about rolled-back state: a compensation record must never replay as if
// live (ProcessUnwoundError). Anything else must be the expected execution
// kind, or the journal is corrupt.
func (t *Tape) loadExecution(position int, want Kind, reason string) (Record, error) {
	record, err := t.journal.Load(position)
	if err != nil {
		return Record{}, err
	}
	if record.Kind == KindCompensationIntent || record.Kind == KindCompensationCompletion {
		return Record{}, ProcessUnwoundError{Position: position}
	}
	if record.Kind != want {
		return Record{}, CorruptJournalError{Position: position, Reason: reason}
	}
	return record, nil
}

// Next returns a recorded outcome for syscall, ok=false when syscall is new,
// or replay.OpenIntentError when the journal ends in this syscall's intent
// with no completion.
func (t *Tape) Next(syscall sys.Syscall) (sys.SyscallResult, bool, error) {
	if t == nil || t.cursor >= t.journal.Length() {
		return sys.SyscallResult{}, false, nil
	}

	intent, err := t.loadExecution(t.cursor, KindIntent, "expected an intent record")
	if err != nil {
		return sys.SyscallResult{}, false, err
	}
	if intent.Syscall == nil {
		return sys.SyscallResult{}, false, CorruptJournalError{Position: t.cursor, Reason: "expected an intent record"}
	}
	if !sameSyscall(*intent.Syscall, syscall) {
		return sys.SyscallResult{}, false, ReplayDivergedError{
			Index: t.cursor,
			Want:  *intent.Syscall,
			Got:   syscall,
		}
	}

	if t.cursor+1 >= t.journal.Length() {
		// Open intent at the tail: dispatched once, outcome unknown. Hand the
		// original intent identity back — derived from the record, origin
		// revision included — so a retry carries the same key however many
		// resume forks sit between then and now.
		key, err := intentKey(t.header, intent)
		if err != nil {
			return sys.SyscallResult{}, false, err
		}
		t.cursor++
		t.pending = true
		return sys.SyscallResult{}, false, replay.OpenIntentError{
			Position: intent.Position,
			Key:      key,
			Syscall:  syscall,
		}
	}

	completion, err := t.loadExecution(t.cursor+1, KindCompletion, "expected a completion record")
	if err != nil {
		return sys.SyscallResult{}, false, err
	}
	if completion.Result == nil {
		return sys.SyscallResult{}, false, CorruptJournalError{Position: t.cursor + 1, Reason: "expected a completion record"}
	}
	t.cursor += 2
	return *completion.Result, true, nil
}

// Begin appends the intent record for a fresh syscall — before it executes —
// and returns its idempotency key.
func (t *Tape) Begin(syscall sys.Syscall) (string, error) {
	if t == nil {
		return "", fmt.Errorf("begin on nil tape")
	}
	if t.pending {
		return "", fmt.Errorf("begin: an intent is already open at position %d", t.journal.Length()-1)
	}
	if t.cursor != t.journal.Length() {
		return "", fmt.Errorf("begin: cursor %d has not consumed the journal (length %d)", t.cursor, t.journal.Length())
	}

	recorded := syscall.Copy()
	stored, err := appendChained(t.journal, t.header, Record{Kind: KindIntent, Syscall: &recorded})
	if err != nil {
		return "", err
	}
	t.cursor++
	t.pending = true
	return intentKey(t.header, stored)
}

// Commit appends the completion record for the open intent — after the
// outcome is known and before the guest observes it.
func (t *Tape) Commit(result sys.SyscallResult) error {
	if t == nil || !t.pending {
		return fmt.Errorf("commit: no open intent")
	}
	if result.Status() != sys.StatusResult && result.Status() != sys.StatusFailed {
		return fmt.Errorf("cannot commit invalid result %q", result.Status())
	}

	recorded := result.Copy()
	if _, err := appendChained(t.journal, t.header, Record{Kind: KindCompletion, Result: &recorded}); err != nil {
		return err
	}
	t.cursor++
	t.pending = false
	return nil
}

func (t *Tape) Reset() {
	if t == nil {
		return
	}
	t.cursor = 0
	t.pending = false
}

func (t *Tape) Remaining() int {
	if t == nil {
		return 0
	}
	return t.journal.Length() - t.cursor
}

// Verify walks the whole journal and checks structure (alternating
// intent/completion, positions in order, at most one open intent at the tail)
// and the hash chain. It returns ChainBrokenError or CorruptJournalError at
// the first damage found.
func Verify(journal Journal) error {
	header, ok, err := journal.Header()
	if err != nil {
		return err
	}
	if !ok {
		if journal.Length() > 0 {
			return CorruptJournalError{Position: 0, Reason: "records present without a header"}
		}
		return nil
	}

	prev, err := digest(header)
	if err != nil {
		return err
	}
	// Structure: an execution section of intent/completion pairs (at most one
	// trailing open intent), optionally followed by a terminal compensation
	// section of compensation pairs (at most one trailing open compensation
	// intent). The abandonment that triggered unwinding may leave the
	// execution section's last intent open forever — the failing dispatch
	// never completed — and that is legal history.
	const (
		wantIntent = iota
		wantCompletion
		wantCompensationIntent
		wantCompensationCompletion
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
		if (expect == wantIntent || expect == wantCompletion) && record.Kind == KindCompensationIntent {
			expect = wantCompensationIntent // the execution section is over
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
		case wantCompensationIntent:
			if record.Kind != KindCompensationIntent || record.Syscall == nil || record.Compensates == nil {
				return CorruptJournalError{Position: position, Reason: "expected a compensation intent record"}
			}
			expect = wantCompensationCompletion
		case wantCompensationCompletion:
			if record.Kind != KindCompensationCompletion || record.Result == nil {
				return CorruptJournalError{Position: position, Reason: "expected a compensation completion record"}
			}
			expect = wantCompensationIntent
		}
		if record.PrevHash != prev {
			return ChainBrokenError{Position: position}
		}
		prev, err = digest(record)
		if err != nil {
			return err
		}
	}
	return nil
}

// intentKey is the intent identity — (process, revision, position, call-hash)
// — used as the idempotency key handed to drivers. It derives from the record
// as written, so it is stable exactly as long as the record is: a crash
// re-drive of an open intent (served from a fork's shared prefix, origin
// revision intact) recomputes the original key, while a rolled-back section's
// re-execution writes fresh records under the new revision and gets a fresh
// key space — its effects are new effects, never the compensated attempt's.
func intentKey(header Header, record Record) (string, error) {
	if record.Syscall == nil {
		return "", CorruptJournalError{Position: record.Position, Reason: "intent identity requires a syscall"}
	}
	return digest(struct {
		Header   Header      `json:"header"`
		Revision uint64      `json:"revision"`
		Position int         `json:"position"`
		Syscall  sys.Syscall `json:"syscall"`
	}{header, record.Revision, record.Position, *record.Syscall})
}

func prevHash(journal Journal, header Header, position int) (string, error) {
	if position == 0 {
		return digest(header)
	}
	prev, err := journal.Load(position - 1)
	if err != nil {
		return "", err
	}
	return digest(prev)
}

// appendChained appends one record at the journal tail, stamped with its
// position and the chain hash of its predecessor (or of the header for the
// first record), and returns the record as stored — the Journal may stamp its
// attempt scope (Revision) on the way in. Every appender — execution and
// compensation alike — goes through here, so the chain semantics cannot drift
// between them.
func appendChained(journal Journal, header Header, record Record) (Record, error) {
	record.Position = journal.Length()
	prev, err := prevHash(journal, header, record.Position)
	if err != nil {
		return Record{}, err
	}
	record.PrevHash = prev
	if err := journal.Append(record); err != nil {
		return Record{}, err
	}
	return journal.Load(record.Position)
}

func digest(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func sameSyscall(left sys.Syscall, right sys.Syscall) bool {
	return left.Name == right.Name && bytes.Equal(left.Args, right.Args)
}
