// Package replay decorates a dispatcher so a re-run guest sees the same
// results it saw the first time: each syscall is served from a Tape if already
// recorded, otherwise journaled as an intent, delegated to the underlying
// dispatcher, and journaled as a completion. It owns the replay-cursor
// protocol (the Tape interface) and the divergence checks; it does not own
// where the tape is stored — a concrete Tape such as the journaled package
// supplies that.
package replay

import (
	"context"
	"errors"
	"fmt"

	"github.com/aurora-capcompute/capcompute/sys"
)

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
	// Begin appends the intent record for a fresh syscall.
	Begin(syscall sys.Syscall) error
	// Commit appends the completion record for the open intent.
	Commit(result sys.SyscallResult) error
}

// OpenIntentError reports that replay reached an intent record with no
// completion: the syscall was dispatched once, but whether its effect happened
// is unknown (a crash between execute and journal, or an external task still
// pending).
type OpenIntentError struct {
	Position int
	Syscall  sys.Syscall
}

func (e OpenIntentError) Error() string {
	return fmt.Sprintf("open intent at position %d: syscall %q was dispatched but its outcome was never journaled", e.Position, e.Syscall.Name)
}

// Dispatcher serves recorded results before delegating new syscalls.
type Dispatcher[K any] struct {
	tape Tape
	next sys.Dispatcher[K]
}

func NewDispatcher[K any](tape Tape, next sys.Dispatcher[K]) *Dispatcher[K] {
	return &Dispatcher[K]{tape: tape, next: next}
}

func (d *Dispatcher[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	result, replayed, err := d.tape.Next(syscall)
	if replayed {
		return result, nil
	}

	var open OpenIntentError
	switch {
	case err == nil:
		if err := d.tape.Begin(syscall); err != nil {
			return sys.SyscallResult{}, err
		}
	case errors.As(err, &open):
		// An open intent is driven again: at-least-once. An effect that happened
		// before the crash happens again; reads repeat harmlessly and a pending
		// external task is polled again.
	default:
		return sys.SyscallResult{}, err
	}

	result, err = d.next.Dispatch(ctx, cred, syscall, auth)
	if err != nil {
		// Outcome unknown: the intent stays open, so the next replay drives it
		// again. Journaling a made-up completion here would assert an outcome
		// nobody observed.
		return sys.SyscallResult{}, err
	}
	if result.Status() == sys.StatusYield {
		// The intent stays open: the quantum ends here, and the next one meets
		// the intent at the journal's tail and drives it again.
		return result, nil
	}
	if err := d.tape.Commit(result); err != nil {
		return sys.SyscallResult{}, err
	}
	return result, nil
}
