package agent

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// pair builds a syscall and a JSON-string result for it.
func pair(name, result string) (sys.Syscall, sys.SyscallResult) {
	return sys.Syscall{Abi: sys.ABIVersion, Name: name},
		sys.Result([]byte(strconv.Quote(result)))
}

// loadEntries projects a journal into `name="result"` strings, one per
// completed syscall.
func loadEntries(t *testing.T, j *logJournal) []string {
	t.Helper()
	entries, err := j.entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Syscall.Name+"="+string(e.Outcome.Result))
	}
	return out
}

func TestLogJournalLinearRoundTrip(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now, nil)

	for _, n := range []string{"a", "b", "c"} {
		syscall, result := pair(n, n)
		appendPair(t, j, syscall, result)
	}
	if got := loadEntries(t, j); len(got) != 3 || got[2] != "c=\"c\"" {
		t.Fatalf("live journal = %v", got)
	}
	// The stored chain is a valid hash-chained journal.
	if err := journaled.Verify(j); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Rebuild purely from the event stream and confirm identical records.
	events, _ := log.Read(context.Background(), scope, 0)
	journals, _, err := foldJournals(events, log, scope, now, nil)
	if err != nil {
		t.Fatalf("fold journals: %v", err)
	}
	rebuilt := journals["proc1"][1]
	if got := loadEntries(t, rebuilt); len(got) != 3 || got[0] != `a="a"` || got[2] != `c="c"` {
		t.Fatalf("rebuilt journal = %v", got)
	}
	if err := journaled.Verify(rebuilt); err != nil {
		t.Fatalf("verify rebuilt: %v", err)
	}
	header, ok, err := rebuilt.Header()
	if err != nil || !ok || header != testHeader() {
		t.Fatalf("rebuilt header = %+v ok=%v err=%v", header, ok, err)
	}
}

// Syscall args and results must round-trip through the event log
// byte-identically — including <, >, and &, which encoding/json would rewrite
// to <-style escapes inside raw messages. A restored journal holding
// different bytes than the guest re-issues would refuse its own history as a
// replay divergence.
func TestLogJournalRoundTripsHTMLCharactersVerbatim(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now, nil)

	args := []byte(`{"prompt":"reply with <exact tool name> & schema"}`)
	syscall := sys.Syscall{Abi: sys.ABIVersion, Name: "core.openaiApi", Args: append([]byte(nil), args...)}
	result := sys.Result([]byte(`{"text":"<done> & gone"}`))
	appendPair(t, j, syscall, result)

	events, _ := log.Read(context.Background(), scope, 0)
	journals, _, err := foldJournals(events, log, scope, now, nil)
	if err != nil {
		t.Fatalf("fold journals: %v", err)
	}
	rebuilt := journals["proc1"][1]
	intent, err := rebuilt.Load(0)
	if err != nil || intent.Syscall == nil {
		t.Fatalf("load intent: %+v, %v", intent, err)
	}
	if string(intent.Syscall.Args) != string(args) {
		t.Fatalf("restored args = %s, want %s", intent.Syscall.Args, args)
	}
	completion, err := rebuilt.Load(1)
	if err != nil || completion.Result == nil {
		t.Fatalf("load completion: %+v, %v", completion, err)
	}
	if string(completion.Result.Result()) != `{"text":"<done> & gone"}` {
		t.Fatalf("restored result = %s", completion.Result.Result())
	}
	if err := journaled.Verify(rebuilt); err != nil {
		t.Fatalf("verify rebuilt: %v", err)
	}
}

func TestLogJournalForkSharesPrefixThenDiverges(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	history := newProcessHistory()

	base := newLogJournal(log, scope, "proc1", 1, history, 0, now, nil)
	for _, n := range []string{"a", "b", "c"} {
		syscall, result := pair(n, n)
		appendPair(t, base, syscall, result)
	}
	// Create rev 2 sharing the first two pairs [a, b] (forkOffset=4 records),
	// then append a different third pair.
	child := newLogJournal(log, scope, "proc1", 2, history, 4, now, nil)
	if child.Length() != 4 {
		t.Fatalf("forked length = %d, want 4 (shared prefix records)", child.Length())
	}
	// The fork inherits the parent's writer identity with its shared prefix.
	header, ok, err := child.Header()
	if err != nil || !ok || header != testHeader() {
		t.Fatalf("forked header = %+v ok=%v err=%v", header, ok, err)
	}
	syscall, result := pair("c2", "c2")
	appendPair(t, child, syscall, result)
	if got := loadEntries(t, child); len(got) != 3 || got[0] != `a="a"` || got[1] != `b="b"` || got[2] != `c2="c2"` {
		t.Fatalf("forked journal = %v", got)
	}
	// The chain stays valid across the fork boundary.
	if err := journaled.Verify(child); err != nil {
		t.Fatalf("verify fork: %v", err)
	}
	// The base revision is untouched.
	if got := loadEntries(t, base); got[2] != `c="c"` {
		t.Fatalf("parent mutated: %v", got)
	}

	// Rebuild both revisions from the stream.
	events, _ := log.Read(context.Background(), scope, 0)
	journals, _, err := foldJournals(events, log, scope, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := loadEntries(t, journals["proc1"][1]); got[2] != `c="c"` {
		t.Fatalf("rebuilt rev1 = %v", got)
	}
	if got := loadEntries(t, journals["proc1"][2]); len(got) != 3 || got[2] != `c2="c2"` {
		t.Fatalf("rebuilt rev2 = %v", got)
	}
}

// A journal driven by the real tape (Begin/Commit) and one built by the test
// helpers must be indistinguishable: both hash-chained, both verifiable.
func TestLogJournalBacksTheKernelTape(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now, nil)

	tape, err := journaled.NewTape(j, testHeader())
	if err != nil {
		t.Fatalf("new tape: %v", err)
	}
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "x", Args: []byte(`{"k":1}`)}
	if _, err := tape.Begin(call); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tape.Commit(sys.Result([]byte(`"done"`))); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := journaled.Verify(j); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A fresh tape over the same journal replays the recorded pair.
	replayTape, err := journaled.NewTape(j, testHeader())
	if err != nil {
		t.Fatalf("replay tape: %v", err)
	}
	result, replayed, err := replayTape.Next(call)
	if err != nil || !replayed {
		t.Fatalf("next: replayed=%v err=%v", replayed, err)
	}
	if string(result.Result()) != `"done"` {
		t.Fatalf("replayed result = %s", result.Result())
	}

	// A different program identity is refused up front.
	if _, err := journaled.NewTape(j, journaled.Header{ABI: sys.ABIVersion, Program: "other", Process: "proc1"}); err == nil {
		t.Fatal("expected ReplayIncompatibleError for a different program")
	}
}

// An open intent at the tail (a crash window or pending approval) surfaces as
// an in-flight entry and does not break folding.
func TestLogJournalOpenIntentEntry(t *testing.T) {
	log := newMemLog()
	scope := eventlog.Scope{TenantID: "t", SessionID: "th"}
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now, nil)

	syscall, result := pair("a", "a")
	appendPair(t, j, syscall, result)
	open, _ := pair("b", "")
	appendIntent(t, j, open)

	entries, err := j.entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[1].Syscall.Name != "b" || entries[1].Outcome.Status != sys.StatusYield {
		t.Fatalf("open entry = %+v, want in-flight b", entries[1])
	}
}
