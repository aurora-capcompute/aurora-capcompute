package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/capcompute/sys"
)

// received waits for the next event a subscriber sees, or gives up.
func received(t *testing.T, events <-chan eventlog.Event) (eventlog.Event, bool) {
	t.Helper()
	select {
	case event := <-events:
		return event, true
	case <-time.After(time.Second):
		return eventlog.Event{}, false
	}
}

// A subscription is a tap on the durable log, not a channel of its own: what a
// watcher sees is what was written. Today that is narrowed to the guest's own
// progress reports — a journalled syscall like any other, which is why it needs
// no delivery mechanism beyond the log.
func TestSubscriptionCarriesGuestProgressOffTheLog(t *testing.T) {
	runtime := bootSessionRuntime(t, newRuntimeStore())
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	session, err := runtime.CreateSession("watched", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	events, unsubscribe, err := runtime.Subscribe(session.ID)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer unsubscribe()

	journal := newLogJournal(runtime.log, runtime.scope(session.ID), "p1", 1,
		newProcessHistory(), 0, runtime.journalNow)
	report := sys.Syscall{Abi: sys.ABIVersion, Name: callSysLog, Args: json.RawMessage(`{"message":"halfway"}`)}
	if err := journal.Append(journaled.Record{Position: 0, Kind: journaled.KindIntent, Syscall: &report}); err != nil {
		t.Fatalf("append report: %v", err)
	}

	event, ok := received(t, events)
	if !ok {
		t.Fatal("the progress report never reached the subscriber")
	}
	if event.Kind != evSyscall || event.Seq == 0 {
		t.Fatalf("event = %+v, want a sequenced %s", event, evSyscall)
	}
	var data syscallRecordData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	if data.Record.Syscall == nil || string(data.Record.Syscall.Args) != `{"message":"halfway"}` {
		t.Fatalf("record = %+v, want the report verbatim", data.Record)
	}
}

// Everything else written to the log is durable state a watcher has no business
// being pushed today. The filter is the only thing holding it back, so it is
// worth pinning: a session's own state event must not reach a subscriber, and a
// second session's progress must not either.
func TestSubscriptionFiltersEverythingElse(t *testing.T) {
	runtime := bootSessionRuntime(t, newRuntimeStore())
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	watched, err := runtime.CreateSession("watched", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	events, unsubscribe, err := runtime.Subscribe(watched.ID)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer unsubscribe()

	// A session.state append on the watched stream: durable, not a notification.
	if _, err := runtime.RenameSession(watched.ID, "renamed"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// A completion carries no message — only the intent does.
	journal := newLogJournal(runtime.log, runtime.scope(watched.ID), "p1", 1,
		newProcessHistory(), 0, runtime.journalNow)
	call := sys.Syscall{Abi: sys.ABIVersion, Name: "billing.charge"}
	if err := journal.Append(journaled.Record{Position: 0, Kind: journaled.KindIntent, Syscall: &call}); err != nil {
		t.Fatalf("append call: %v", err)
	}

	// Another session's progress, which this subscriber must never see.
	other, err := runtime.CreateSession("other", nil)
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}
	elsewhere := newLogJournal(runtime.log, runtime.scope(other.ID), "p2", 1,
		newProcessHistory(), 0, runtime.journalNow)
	report := sys.Syscall{Abi: sys.ABIVersion, Name: callSysLog, Args: json.RawMessage(`{"message":"not yours"}`)}
	if err := elsewhere.Append(journaled.Record{Position: 0, Kind: journaled.KindIntent, Syscall: &report}); err != nil {
		t.Fatalf("append report: %v", err)
	}

	if event, ok := received(t, events); ok {
		t.Fatalf("subscriber saw %+v, want nothing", event)
	}
}

// Unsubscribing detaches: the stream keeps taking writes, the watcher stops
// hearing about them, and nothing blocks on the abandoned channel.
func TestUnsubscribeDetaches(t *testing.T) {
	runtime := bootSessionRuntime(t, newRuntimeStore())
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	session, err := runtime.CreateSession("watched", nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	events, unsubscribe, err := runtime.Subscribe(session.ID)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	unsubscribe()
	unsubscribe() // idempotent

	journal := newLogJournal(runtime.log, runtime.scope(session.ID), "p1", 1,
		newProcessHistory(), 0, runtime.journalNow)
	report := sys.Syscall{Abi: sys.ABIVersion, Name: callSysLog, Args: json.RawMessage(`{"message":"gone"}`)}
	if err := journal.Append(journaled.Record{Position: 0, Kind: journaled.KindIntent, Syscall: &report}); err != nil {
		t.Fatalf("append report: %v", err)
	}
	if event, ok := received(t, events); ok {
		t.Fatalf("detached subscriber saw %+v, want nothing", event)
	}
}

// A subscription names a session that exists.
func TestSubscribeRefusesAnUnknownSession(t *testing.T) {
	runtime := bootSessionRuntime(t, newRuntimeStore())
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	if _, _, err := runtime.Subscribe("nope"); err == nil {
		t.Fatal("Subscribe on an unknown session = nil error, want a refusal")
	}
}
