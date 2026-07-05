// Package eventlog is a generic append-only log: the single source of truth a
// runtime folds into projections. It is domain-agnostic — events carry an opaque
// payload owned by the layer above — so the same primitive backs lifecycle,
// task, and capability-journal events for one session stream.
//
// A stream is one session's ordered history, identified by Scope. The store
// assigns each appended event a contiguous sequence and serializes appends per
// stream; cross-instance coordination is handled separately by leases, so the
// log itself needs no optimistic-concurrency guard. State is reconstructed by
// reading a stream from the beginning and folding its events; there is no
// in-place mutation and no separate "current row" store.
package eventlog

import (
	"context"
	"encoding/json"
	"time"
)

// Scope identifies one append-only stream — one session's history.
type Scope struct {
	TenantID  string
	SessionID string
}

// Event is one immutable record in a stream. Seq is assigned by the log on
// append (1-based, contiguous per stream). Kind and Data are owned by the domain
// layer; Proc and Rev locate the event within a process's revision when
// applicable (zero for session-level events).
type Event struct {
	Seq  uint64          `json:"seq"`
	Kind string          `json:"kind"`
	Time time.Time       `json:"time"`
	Proc string          `json:"proc,omitempty"`
	Rev  uint64          `json:"rev,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Log is the append-only event store. Implementations must make Append atomic
// and totally ordered per stream.
type Log interface {
	// Append atomically writes events to a stream, assigning each a contiguous
	// Seq, and returns the new head. Appends to one stream are serialized.
	Append(ctx context.Context, scope Scope, events ...Event) (head uint64, err error)
	// Read returns the stream's events with Seq > after, in order. after == 0
	// reads from the beginning.
	Read(ctx context.Context, scope Scope, after uint64) ([]Event, error)
	// Streams lists the scopes that have at least one event for a tenant, so a
	// runtime can enumerate sessions to fold on restore.
	Streams(ctx context.Context, tenantID string) ([]Scope, error)
	// Compact atomically replaces the stream's entire contents with events,
	// re-assigning contiguous Seq 1..len(events); any Seq the caller set is
	// ignored. It is the journal-lifecycle primitive behind snapshot
	// compaction: the caller hands over a projection-equivalent rewrite (one
	// snapshot event plus the retained tail) and the store swaps it in as a
	// single atomic unit — a reader observes the old stream or the new one,
	// never a mix, and a crash mid-compact must leave the old stream intact.
	// Subsequent Appends continue at len(events)+1. Compacting to zero events
	// erases the stream (it stops appearing in Streams).
	Compact(ctx context.Context, scope Scope, events []Event) error
}
