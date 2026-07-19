package journaled_test

import (
	"errors"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
)

// stampingJournal is a fakeJournal whose Append stamps the current attempt on
// each record — the contract a revision-aware Journal (the runtime's
// log-backed one) fulfills.
type stampingJournal struct {
	fakeJournal
	revision uint64
}

func (j *stampingJournal) Append(record journaled.Record) error {
	record.Revision = j.revision
	return j.fakeJournal.Append(record)
}

// Intent identity is scoped by the revision that wrote the record: the same
// call at the same position under a different attempt is a different effect
// (a rolled-back attempt's key space is never reused), while a re-driven open
// intent keeps its original key however many resume forks came between.
func TestIntentKeysAreRevisionScoped(t *testing.T) {
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "billing.charge", Args: []byte(`{"amount":100}`)}

	keyUnder := func(revision uint64) string {
		t.Helper()
		journal := &stampingJournal{revision: revision}
		tape := newTestTape(t, journal)
		key, err := tape.Begin(call)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		return key
	}
	if keyUnder(1) == keyUnder(2) {
		t.Fatal("identical call and position under different attempts must not share an idempotency key")
	}
	if keyUnder(1) != keyUnder(1) {
		t.Fatal("intent keys must be deterministic within an attempt")
	}

	// The crash re-drive: attempt 1 leaves an open intent; the resumed run
	// (its journal now stamping a later revision, as a fork bump would) must
	// hand back the ORIGINAL key — the record remembers its attempt.
	journal := &stampingJournal{revision: 1}
	first := newTestTape(t, journal)
	original, err := first.Begin(call)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	journal.revision = 2 // the resume runs under a bumped attempt
	resumed := newTestTape(t, journal)
	_, _, err = resumed.Next(call)
	var open replay.OpenIntentError
	if !errors.As(err, &open) {
		t.Fatalf("next over the open intent = %v, want OpenIntentError", err)
	}
	if open.Key != original {
		t.Fatal("a re-driven open intent must carry its original idempotency key")
	}
}
