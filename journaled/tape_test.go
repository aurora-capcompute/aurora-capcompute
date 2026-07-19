package journaled_test

import (
	"errors"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/aurora-capcompute/replay"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
)

// fakeJournal is an in-memory journaled.Journal. The tape needs only the Journal
// contract, so the package's own tests supply it directly rather than depending
// on a concrete store from a consumer module.
type fakeJournal struct {
	header    journaled.Header
	hasHeader bool
	records   []journaled.Record
}

func (j *fakeJournal) Header() (journaled.Header, bool, error) {
	return j.header, j.hasHeader, nil
}

func (j *fakeJournal) SetHeader(header journaled.Header) error {
	j.header = header
	j.hasHeader = true
	return nil
}

func (j *fakeJournal) Load(idx int) (journaled.Record, error) {
	return j.records[idx], nil
}

func (j *fakeJournal) Append(record journaled.Record) error {
	j.records = append(j.records, record)
	return nil
}

func (j *fakeJournal) Length() int { return len(j.records) }

var testHeader = journaled.Header{ABI: sys.ABIVersion, Program: "sha256:test", Process: "run-1"}

func newTestTape(t *testing.T, journal journaled.Journal) *journaled.Tape {
	t.Helper()
	tape, err := journaled.NewTape(journal, testHeader)
	if err != nil {
		t.Fatalf("new tape: %v", err)
	}
	return tape
}

// record drives one full fresh syscall through the tape: intent then completion.
func record(t *testing.T, tape *journaled.Tape, syscall sys.Syscall, result sys.SyscallResult) string {
	t.Helper()
	if _, replayed, err := tape.Next(syscall); err != nil || replayed {
		t.Fatalf("next before begin: replayed=%v err=%v", replayed, err)
	}
	key, err := tape.Begin(syscall)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tape.Commit(result); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return key
}

func TestNewTapeStampsFreshJournal(t *testing.T) {
	journal := &fakeJournal{}
	newTestTape(t, journal)

	header, ok, err := journal.Header()
	if err != nil || !ok {
		t.Fatalf("header = %v, ok = %v, err = %v", header, ok, err)
	}
	if header != testHeader {
		t.Fatalf("header = %+v, want %+v", header, testHeader)
	}
}

func TestNewTapeAcceptsMatchingHeader(t *testing.T) {
	journal := &fakeJournal{header: testHeader, hasHeader: true}
	newTestTape(t, journal)
}

func TestNewTapeRefusesIncompatibleJournal(t *testing.T) {
	recorded := journaled.Header{ABI: sys.ABIVersion, Program: "sha256:other", Process: "run-1"}
	journal := &fakeJournal{header: recorded, hasHeader: true}

	_, err := journaled.NewTape(journal, testHeader)
	var incompatible journaled.ReplayIncompatibleError
	if !errors.As(err, &incompatible) {
		t.Fatalf("error = %v, want ReplayIncompatibleError", err)
	}
	if incompatible.Recorded != recorded || incompatible.Current != testHeader {
		t.Fatalf("error = %+v", incompatible)
	}
}

func TestBeginCommitAppendsIntentCompletionPair(t *testing.T) {
	journal := &fakeJournal{}
	tape := newTestTape(t, journal)

	key := record(t, tape, sys.Syscall{Name: "step.one"}, sys.Result(nil))
	if key == "" {
		t.Fatal("begin returned an empty idempotency key")
	}
	if journal.Length() != 2 {
		t.Fatalf("journal length = %d, want 2 (intent + completion)", journal.Length())
	}
	if journal.records[0].Kind != journaled.KindIntent || journal.records[0].Syscall == nil {
		t.Fatalf("record 0 = %+v, want intent", journal.records[0])
	}
	if journal.records[1].Kind != journaled.KindCompletion || journal.records[1].Result == nil {
		t.Fatalf("record 1 = %+v, want completion", journal.records[1])
	}
	if remaining := tape.Remaining(); remaining != 0 {
		t.Fatalf("remaining = %d, want 0", remaining)
	}
	if err := journaled.Verify(journal); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestResetReplaysRecordedResults(t *testing.T) {
	tape := newTestTape(t, &fakeJournal{})
	syscall := sys.Syscall{Name: "step.one"}
	record(t, tape, syscall, sys.Result([]byte(`{"ok":true}`)))

	tape.Reset()
	result, ok, err := tape.Next(syscall)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !ok {
		t.Fatal("record was not replayed")
	}
	if string(result.Result()) != `{"ok":true}` {
		t.Fatalf("result = %s", result.Result())
	}
	if remaining := tape.Remaining(); remaining != 0 {
		t.Fatalf("remaining = %d, want 0", remaining)
	}
}

func TestResetReplaysRecordedFailures(t *testing.T) {
	tape := newTestTape(t, &fakeJournal{})
	syscall := sys.Syscall{Name: "step.one"}
	record(t, tape, syscall, sys.FailCode(sys.ErrnoDenied, "permission denied"))

	tape.Reset()
	result, ok, err := tape.Next(syscall)
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !ok {
		t.Fatal("failure was not replayed")
	}
	if result.Status() != sys.StatusFailed || result.Message() != "permission denied" {
		t.Fatalf("result = %#v", result)
	}
	if result.Errno() != sys.ErrnoDenied {
		t.Fatalf("errno = %q, want denied", result.Errno())
	}
}

func TestReplayDivergenceDetected(t *testing.T) {
	tape := newTestTape(t, &fakeJournal{})
	record(t, tape, sys.Syscall{Name: "step.one"}, sys.Result(nil))

	tape.Reset()
	_, _, err := tape.Next(sys.Syscall{Name: "step.other"})
	var diverged journaled.ReplayDivergedError
	if !errors.As(err, &diverged) {
		t.Fatalf("error = %v, want ReplayDivergedError", err)
	}
	if diverged.Index != 0 || diverged.Want.Name != "step.one" || diverged.Got.Name != "step.other" {
		t.Fatalf("error = %+v", diverged)
	}
}

func TestOpenIntentSurfacedWithStableKey(t *testing.T) {
	journal := &fakeJournal{}
	tape := newTestTape(t, journal)
	syscall := sys.Syscall{Name: "mail.send", Args: []byte(`{"to":"ops"}`)}

	key, err := tape.Begin(syscall)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Crash before Commit: a fresh tape over the same journal meets the open intent.
	crashed := newTestTape(t, journal)
	_, replayed, err := crashed.Next(syscall)
	if replayed {
		t.Fatal("open intent served as a completed result")
	}
	var open replay.OpenIntentError
	if !errors.As(err, &open) {
		t.Fatalf("error = %v, want OpenIntentError", err)
	}
	if open.Position != 0 || open.Syscall.Name != "mail.send" {
		t.Fatalf("open intent = %+v", open)
	}
	if open.Key != key {
		t.Fatalf("retry key %q != original key %q; idempotency broken", open.Key, key)
	}

	// Retrying resolves the intent: Commit closes it without a second Begin.
	if err := crashed.Commit(sys.Result([]byte(`{"sent":true}`))); err != nil {
		t.Fatalf("commit after open intent: %v", err)
	}
	if journal.Length() != 2 {
		t.Fatalf("journal length = %d, want 2", journal.Length())
	}
	if err := journaled.Verify(journal); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestYieldLeavesIntentOpenAcrossReset(t *testing.T) {
	journal := &fakeJournal{}
	tape := newTestTape(t, journal)
	syscall := sys.Syscall{Name: "task.request"}

	key, err := tape.Begin(syscall)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Dispatch yielded: nothing committed, the run is re-driven from zero.
	tape.Reset()

	_, replayed, err := tape.Next(syscall)
	if replayed {
		t.Fatal("yielded intent served as a completed result")
	}
	var open replay.OpenIntentError
	if !errors.As(err, &open) {
		t.Fatalf("error = %v, want OpenIntentError", err)
	}
	if open.Key != key {
		t.Fatalf("resumed key %q != original %q", open.Key, key)
	}
	if err := tape.Commit(sys.Result(nil)); err != nil {
		t.Fatalf("commit resumed intent: %v", err)
	}
}

func TestBeginRefusedWhileIntentOpen(t *testing.T) {
	tape := newTestTape(t, &fakeJournal{})
	if _, err := tape.Begin(sys.Syscall{Name: "step.one"}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tape.Begin(sys.Syscall{Name: "step.two"}); err == nil {
		t.Fatal("second begin with an open intent did not error")
	}
}

func TestCommitWithoutIntentRefused(t *testing.T) {
	tape := newTestTape(t, &fakeJournal{})
	if err := tape.Commit(sys.Result(nil)); err == nil {
		t.Fatal("commit without an open intent did not error")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	journal := &fakeJournal{}
	tape := newTestTape(t, journal)
	record(t, tape, sys.Syscall{Name: "step.one"}, sys.Result([]byte(`{"amount":10}`)))
	record(t, tape, sys.Syscall{Name: "step.two"}, sys.Result(nil))

	if err := journaled.Verify(journal); err != nil {
		t.Fatalf("verify clean journal: %v", err)
	}

	tampered := *journal.records[1].Result
	_ = tampered.UnmarshalJSON([]byte(`{"status":"result","result":{"amount":1000000}}`))
	journal.records[1].Result = &tampered

	err := journaled.Verify(journal)
	var broken journaled.ChainBrokenError
	if !errors.As(err, &broken) {
		t.Fatalf("error = %v, want ChainBrokenError", err)
	}
	if broken.Position != 2 {
		t.Fatalf("chain break at %d, want 2 (first record after the tampered one)", broken.Position)
	}
}

func TestVerifyDetectsStructureDamage(t *testing.T) {
	journal := &fakeJournal{}
	tape := newTestTape(t, journal)
	record(t, tape, sys.Syscall{Name: "step.one"}, sys.Result(nil))

	journal.records[0].Kind = journaled.KindCompletion
	err := journaled.Verify(journal)
	var corrupt journaled.CorruptJournalError
	if !errors.As(err, &corrupt) {
		t.Fatalf("error = %v, want CorruptJournalError", err)
	}
}

func TestIntentKeysDifferByPositionAndCall(t *testing.T) {
	tape := newTestTape(t, &fakeJournal{})
	one := record(t, tape, sys.Syscall{Name: "step.one"}, sys.Result(nil))
	two := record(t, tape, sys.Syscall{Name: "step.one"}, sys.Result(nil))
	if one == two {
		t.Fatal("same call at different positions produced the same idempotency key")
	}

	other := newTestTape(t, &fakeJournal{})
	otherOne := record(t, other, sys.Syscall{Name: "step.one"}, sys.Result(nil))
	if one != otherOne {
		t.Fatal("same run, position, and call produced different idempotency keys")
	}
}
