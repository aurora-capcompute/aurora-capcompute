package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// pair builds a syscall and a JSON-string result for it.
func pair(name, result string) (sys.Syscall, sys.SyscallResult) {
	return sys.Syscall{Abi: sys.ABIVersion, Name: name},
		sys.Result([]byte(strconv.Quote(result)))
}

// loadEntries projects a journal view into `name="result"` strings, one per
// completed syscall.
func loadEntries(t *testing.T, j *logJournal) []string {
	t.Helper()
	var out []string
	for i := 0; i+1 < j.Length(); i += 2 {
		intent, err := j.Load(i)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		completion, err := j.Load(i + 1)
		if err != nil {
			t.Fatalf("load %d: %v", i+1, err)
		}
		out = append(out, intent.Syscall.Name+"="+string(completion.Result.Result()))
	}
	return out
}

func TestLogJournalLinearRoundTrip(t *testing.T) {
	log := newMemLog()
	scope := "th"
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now)

	for _, n := range []string{"a", "b", "c"} {
		syscall, result := pair(n, n)
		appendPair(t, j, syscall, result)
	}
	if got := loadEntries(t, j); len(got) != 3 || got[2] != "c=\"c\"" {
		t.Fatalf("live journal = %v", got)
	}
	// The stored records are a well-formed journal.
	if err := journaled.Verify(j); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Rebuild purely from the event stream and confirm identical records.
	events, _ := log.Read(context.Background(), scope, 0)
	journals, _, err := foldJournals(events, log, scope, now)
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
}

// manifest.Syscall args and results must round-trip through the event log
// byte-identically — including <, >, and &, which encoding/json would rewrite
// to <-style escapes inside raw messages. A restored journal holding
// different bytes than the guest re-issues would refuse its own history as a
// replay divergence.
func TestLogJournalRoundTripsHTMLCharactersVerbatim(t *testing.T) {
	log := newMemLog()
	scope := "th"
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now)

	args := []byte(`{"prompt":"reply with <exact tool name> & schema"}`)
	syscall := sys.Syscall{Abi: sys.ABIVersion, Name: "core.openaiApi", Args: append([]byte(nil), args...)}
	result := sys.Result([]byte(`{"text":"<done> & gone"}`))
	appendPair(t, j, syscall, result)

	events, _ := log.Read(context.Background(), scope, 0)
	journals, _, err := foldJournals(events, log, scope, now)
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
	scope := "th"
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	history := newProcessHistory()

	base := newLogJournal(log, scope, "proc1", 1, history, 0, now)
	for _, n := range []string{"a", "b", "c"} {
		syscall, result := pair(n, n)
		appendPair(t, base, syscall, result)
	}
	// Create rev 2 sharing the first two pairs [a, b] (forkOffset=4 records),
	// then append a different third pair.
	child := newLogJournal(log, scope, "proc1", 2, history, 4, now)
	if child.Length() != 4 {
		t.Fatalf("forked length = %d, want 4 (shared prefix records)", child.Length())
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
	journals, _, err := foldJournals(events, log, scope, now)
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
// helpers must be indistinguishable: both well-formed, both verifiable.
func TestLogJournalBacksTheKernelTape(t *testing.T) {
	log := newMemLog()
	scope := "th"
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	j := newLogJournal(log, scope, "proc1", 1, newProcessHistory(), 0, now)

	tape := journaled.NewTape(j)
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "x", Args: []byte(`{"k":1}`)}
	if err := tape.Begin(call); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tape.Commit(sys.Result([]byte(`"done"`))); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := journaled.Verify(j); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// A fresh tape over the same journal replays the recorded pair.
	replayTape := journaled.NewTape(j)
	result, replayed, err := replayTape.Next(call)
	if err != nil || !replayed {
		t.Fatalf("next: replayed=%v err=%v", replayed, err)
	}
	if string(result.Result()) != `"done"` {
		t.Fatalf("replayed result = %s", result.Result())
	}
}

// The history pairs every revision's intents with that revision's own
// completions. An open intent (a crash window, a pending approval, an attempt
// abandoned by a fork) is in flight, even where an earlier revision completed
// the same position.
func TestProcessHistoryEntriesPairWithinTheirRevision(t *testing.T) {
	log := newMemLog()
	scope := "th"
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	history := newProcessHistory()
	base := newLogJournal(log, scope, "proc1", 1, history, 0, now)
	for _, name := range []string{"a", "b", "c"} {
		syscall, result := pair(name, name)
		appendPair(t, base, syscall, result)
	}
	// Revision 2 forks after a, and leaves its b2 open.
	child := newLogJournal(log, scope, "proc1", 2, history, 2, now)
	open, _ := pair("b2", "")
	appendIntent(t, child, open)

	var got []string
	for _, e := range history.entries() {
		got = append(got, fmt.Sprintf("%d@%d %s %s", e.Position, e.Revision, e.Syscall.Name, e.Outcome.Status))
	}
	want := []string{"0@1 a result", "2@1 b result", "2@2 b2 yield", "4@1 c result"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("entries = %v, want %v", got, want)
	}
}
