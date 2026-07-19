// Package replay decorates a dispatcher so a re-run guest sees the same
// results it saw the first time: each syscall is served from a Tape if already
// recorded, otherwise journaled as an intent, delegated to the underlying
// dispatcher, and journaled as a completion. It owns the replay-cursor
// protocol (the Tape interface), the divergence checks, and the open-intent
// policy; it does not own where the tape is stored — a concrete Tape such as
// the journaled package supplies that.
package replay

import (
	"context"
	"errors"
	"fmt"

	"github.com/aurora-capcompute/capcompute/sys"
)

// CompletionChecker validates per-resume dispatcher state after the guest returns.
type CompletionChecker interface {
	CheckCompleted() error
}

// Tape owns replay cursor state and the two-record intent/completion protocol:
// an intent is appended before a syscall executes (journal-before-execute), a
// completion after its outcome is known and before the guest observes it
// (journal-before-observe).
type Tape interface {
	// Next serves the recorded outcome of syscall, or ok=false when the
	// syscall is new. When replay reaches an intent with no completion — the
	// syscall was dispatched but its outcome never journaled — Next returns
	// OpenIntentError.
	Next(syscall sys.Syscall) (sys.SyscallResult, bool, error)
	// Begin appends the intent record for a fresh syscall and returns its
	// idempotency key: the intent identity (process, revision, position,
	// call-hash) — scoped to the attempt that wrote the record.
	Begin(syscall sys.Syscall) (string, error)
	// Commit appends the completion record for the open intent.
	Commit(result sys.SyscallResult) error
	Reset()
	Remaining() int
}

// OpenIntentError reports that replay reached an intent record with no
// completion: the syscall was dispatched once, but whether its effect happened
// is unknown (a crash between execute and journal, or an external task still
// pending). Key is the same idempotency key the original dispatch carried.
type OpenIntentError struct {
	Position int
	Key      string
	Syscall  sys.Syscall
}

func (e OpenIntentError) Error() string {
	return fmt.Sprintf("open intent at position %d: syscall %q was dispatched but its outcome was never journaled", e.Position, e.Syscall.Name)
}

// IndeterminateError means an open intent was met on replay and policy refused
// to retry it: the effect may or may not have happened, and a human (or the
// app) must review the journal to resolve it.
type IndeterminateError struct {
	Position int
	Syscall  sys.Syscall
}

func (e IndeterminateError) Error() string {
	return fmt.Sprintf("syscall %q outcome is indeterminate: open intent at position %d requires review", e.Syscall.Name, e.Position)
}

// OpenIntentDecision is the per-syscall policy answer for an open intent met
// on replay.
type OpenIntentDecision int

const (
	// RetryOpenIntent re-dispatches with the original idempotency key —
	// at-least-once, deduplicated by keyed drivers. The right default: reads
	// are harmless to repeat and pending external tasks are re-polled.
	RetryOpenIntent OpenIntentDecision = iota
	// FailOpenIntent surfaces IndeterminateError instead of re-executing —
	// for non-idempotent mutations whose driver cannot dedup.
	FailOpenIntent
)

// OpenIntentPolicy decides, per syscall, what to do with an open intent met
// on replay. Nil means RetryOpenIntent for everything.
type OpenIntentPolicy func(syscall sys.Syscall) OpenIntentDecision

// Dispatcher serves recorded results before delegating new syscalls.
type Dispatcher[K any] struct {
	tape       Tape
	next       sys.Dispatcher[K]
	openIntent OpenIntentPolicy
}

func NewDispatcher[K any](tape Tape, next sys.Dispatcher[K]) *Dispatcher[K] {
	return &Dispatcher[K]{tape: tape, next: next}
}

// WithOpenIntentPolicy sets the open-intent decision; without it every open
// intent is retried under its original idempotency key.
func (d *Dispatcher[K]) WithOpenIntentPolicy(policy OpenIntentPolicy) *Dispatcher[K] {
	d.openIntent = policy
	return d
}

func (d *Dispatcher[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	result, replayed, err := d.tape.Next(syscall)
	if replayed {
		return result, nil
	}

	var key string
	var open OpenIntentError
	switch {
	case err == nil:
		key, err = d.tape.Begin(syscall)
		if err != nil {
			return sys.SyscallResult{}, err
		}
	case errors.As(err, &open):
		if d.decideOpenIntent(syscall) != RetryOpenIntent {
			return sys.SyscallResult{}, IndeterminateError{Position: open.Position, Syscall: syscall}
		}
		key = open.Key
	default:
		return sys.SyscallResult{}, err
	}

	result, err = d.next.Dispatch(sys.WithIdempotencyKey(ctx, key), cred, syscall, auth)
	if err != nil {
		// Outcome unknown: the intent stays open so the next replay resolves
		// it by policy. Journaling a made-up completion here would assert an
		// outcome nobody observed.
		return sys.SyscallResult{}, err
	}
	if result.Status() == sys.StatusYield {
		d.tape.Reset()
		return result, nil
	}
	if err := d.tape.Commit(result); err != nil {
		return sys.SyscallResult{}, err
	}
	return result, nil
}

func (d *Dispatcher[K]) decideOpenIntent(syscall sys.Syscall) OpenIntentDecision {
	if d.openIntent == nil {
		return RetryOpenIntent
	}
	return d.openIntent(syscall)
}

func (d *Dispatcher[K]) Remaining() int {
	return d.tape.Remaining()
}

func (d *Dispatcher[K]) CheckCompleted() error {
	if remaining := d.Remaining(); remaining > 0 {
		return IncompleteError{Remaining: remaining}
	}
	return nil
}

func (d *Dispatcher[K]) Capabilities() []sys.Capability {
	return d.next.Capabilities()
}

// IncompleteError means the guest completed before replaying all recorded syscalls.
type IncompleteError struct {
	Remaining int
}

func (e IncompleteError) Error() string {
	return fmt.Sprintf("replay incomplete: %d recorded journal records were not consumed", e.Remaining)
}
