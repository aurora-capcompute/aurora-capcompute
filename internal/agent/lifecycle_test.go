package agent

// The lifecycle dispatcher's own syscalls: sys.abort's arguments, and the
// output-schema hook sys.output runs before an answer is acknowledged.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

// TestLifecycleAbortArgs: sys.abort carries the guest's reason; malformed args
// are rejected at dispatch and empty args are a bare "give up".
func TestLifecycleAbortArgs(t *testing.T) {
	l := newLifecycleDispatcher(stubNext{}, "msg", nil, nil, manifest.Manifest{}, 1, nil)
	dispatch := func(args string) sys.SyscallResult {
		t.Helper()
		result, err := l.Dispatch(context.Background(), ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: callSysAbort, Args: json.RawMessage(args)},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return result
	}
	if r := dispatch(`{"reason":"r"}`); r.Status() != sys.StatusResult {
		t.Fatalf("abort = %v, want acknowledged", r.Status())
	}
	if r := dispatch(``); r.Status() != sys.StatusResult {
		t.Fatalf("bare abort = %v, want acknowledged", r.Status())
	}
	if r := dispatch(`{"reason":`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("malformed abort = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
}

// TestLifecycleValidatesAnswer: sys.output runs the program's output-schema
// hook, so an answer that violates the interface comes back as a failed
// result the guest can react to — nothing is recorded as terminal until the
// answer satisfies the schema. A nil hook (unbound program) acknowledges.
func TestLifecycleValidatesAnswer(t *testing.T) {
	reject := func(answer string) error {
		if answer == "bad" {
			return fmt.Errorf("answer rejected by output schema")
		}
		return nil
	}
	l := newLifecycleDispatcher(stubNext{}, "msg", nil, nil, manifest.Manifest{}, 1, reject)
	output := func(args string) sys.SyscallResult {
		t.Helper()
		result, err := l.Dispatch(context.Background(), ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: callSysOutput, Args: json.RawMessage(args)},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return result
	}
	if r := output(`{"answer":"good"}`); r.Status() != sys.StatusResult {
		t.Fatalf("valid answer = %v, want acknowledged", r.Status())
	}
	if r := output(`{"answer":"bad"}`); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("invalid answer = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
}

type stubNext struct{}

func (stubNext) Dispatch(context.Context, ProcessContext, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Fail("unexpected"), nil
}

func (stubNext) Capabilities() []sys.Capability { return nil }
