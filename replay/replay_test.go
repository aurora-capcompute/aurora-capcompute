package replay

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

// fakeTape scripts Next's answer and records the protocol calls it receives.
type fakeTape struct {
	nextResult sys.SyscallResult
	nextOK     bool
	nextErr    error

	beginKey  string
	begun     bool
	committed bool
	reset     bool
}

func (t *fakeTape) Next(sys.Syscall) (sys.SyscallResult, bool, error) {
	return t.nextResult, t.nextOK, t.nextErr
}

func (t *fakeTape) Begin(sys.Syscall) (string, error) {
	t.begun = true
	return t.beginKey, nil
}

func (t *fakeTape) Commit(sys.SyscallResult) error {
	t.committed = true
	return nil
}

func (t *fakeTape) Reset() {
	t.reset = true
}

func (t *fakeTape) Remaining() int {
	return 0
}

type nextFunc[K any] func(context.Context, K, sys.Syscall, sys.Authorization) (sys.SyscallResult, error)

func (f nextFunc[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	return f(ctx, cred, syscall, auth)
}

func (nextFunc[K]) Capabilities() []sys.Capability { return nil }

func dispatchWith(t *testing.T, tape *fakeTape, next nextFunc[string]) (sys.SyscallResult, error) {
	t.Helper()
	return NewDispatcher[string](tape, next).Dispatch(
		context.Background(), "run-1", sys.Syscall{Name: "step.one"}, sys.Authorization{})
}

func TestDispatcherResetsTapeOnYield(t *testing.T) {
	tape := &fakeTape{beginKey: "key-1"}
	result, err := dispatchWith(t, tape, func(context.Context, string, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
		return sys.Yield("waiting"), nil
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusYield {
		t.Fatalf("result = %#v", result)
	}
	if !tape.begun {
		t.Fatal("yielding syscall must still journal its intent first")
	}
	if !tape.reset {
		t.Fatal("tape was not reset")
	}
	if tape.committed {
		t.Fatal("yield should not be committed")
	}
}

func TestDispatcherJournalsIntentThenCompletion(t *testing.T) {
	tape := &fakeTape{beginKey: "key-1"}
	var sawKey string
	result, err := dispatchWith(t, tape, func(ctx context.Context, _ string, _ sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
		if !tape.begun {
			t.Fatal("driver ran before the intent was journaled (journal-before-execute violated)")
		}
		sawKey, _ = sys.IdempotencyKey(ctx)
		return sys.Result(json.RawMessage(`{"ok":true}`)), nil
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("result = %#v", result)
	}
	if sawKey != "key-1" {
		t.Fatalf("driver saw idempotency key %q, want key-1", sawKey)
	}
	if !tape.committed {
		t.Fatal("result was not committed")
	}
	if tape.reset {
		t.Fatal("result should not reset tape")
	}
}

func TestDispatcherCommitsFailures(t *testing.T) {
	tape := &fakeTape{beginKey: "key-1"}
	result, err := dispatchWith(t, tape, func(context.Context, string, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
		return sys.Fail("denied"), nil
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed {
		t.Fatalf("result = %#v", result)
	}
	if !tape.committed {
		t.Fatal("failure should be committed")
	}
}

func TestDispatcherServesReplayedResultWithoutDelegating(t *testing.T) {
	tape := &fakeTape{nextResult: sys.Result(json.RawMessage(`{"replayed":true}`)), nextOK: true}
	result, err := dispatchWith(t, tape, func(context.Context, string, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
		t.Fatal("replayed syscall reached the driver")
		return sys.SyscallResult{}, nil
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if string(result.Result()) != `{"replayed":true}` {
		t.Fatalf("result = %s", result.Result())
	}
	if tape.begun || tape.committed {
		t.Fatal("replayed syscall must not journal new records")
	}
}

func TestDispatcherRetriesOpenIntentWithOriginalKey(t *testing.T) {
	tape := &fakeTape{nextErr: OpenIntentError{Position: 4, Key: "key-4", Syscall: sys.Syscall{Name: "step.one"}}}
	var sawKey string
	result, err := dispatchWith(t, tape, func(ctx context.Context, _ string, _ sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
		sawKey, _ = sys.IdempotencyKey(ctx)
		return sys.Result(nil), nil
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("result = %#v", result)
	}
	if sawKey != "key-4" {
		t.Fatalf("retry carried key %q, want the original key-4", sawKey)
	}
	if tape.begun {
		t.Fatal("retry of an open intent must not journal a second intent")
	}
	if !tape.committed {
		t.Fatal("resolved open intent was not committed")
	}
}

func TestDispatcherFailsOpenIntentPerPolicy(t *testing.T) {
	tape := &fakeTape{nextErr: OpenIntentError{Position: 4, Key: "key-4", Syscall: sys.Syscall{Name: "mail.send"}}}
	dispatcher := NewDispatcher[string](tape, nextFunc[string](func(context.Context, string, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
		t.Fatal("policy-failed open intent reached the driver")
		return sys.SyscallResult{}, nil
	})).WithOpenIntentPolicy(func(syscall sys.Syscall) OpenIntentDecision {
		if syscall.Name == "mail.send" {
			return FailOpenIntent
		}
		return RetryOpenIntent
	})

	_, err := dispatcher.Dispatch(context.Background(), "run-1", sys.Syscall{Name: "mail.send"}, sys.Authorization{})
	var indeterminate IndeterminateError
	if !errors.As(err, &indeterminate) {
		t.Fatalf("error = %v, want IndeterminateError", err)
	}
	if indeterminate.Position != 4 || indeterminate.Syscall.Name != "mail.send" {
		t.Fatalf("error = %+v", indeterminate)
	}
}
