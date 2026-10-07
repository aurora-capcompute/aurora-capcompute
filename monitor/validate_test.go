package monitor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute/sys"
)

type recordingDispatcher struct {
	calls []sys.Syscall
}

func (d *recordingDispatcher) Dispatch(_ context.Context, _ testCred, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	d.calls = append(d.calls, syscall)
	return sys.Result(json.RawMessage(`{"ok":true}`)), nil
}

// grantsFixture is a table that admits names without routing them — the
// Validator only ever asks what a name means, never who serves it.
func grantsFixture(grants ...capability.Descriptor) *capability.Table {
	table := capability.NewTable()
	for _, grant := range grants {
		if err := table.Reserve(grant); err != nil {
			panic(err)
		}
	}
	return table
}

func callValidator(t *testing.T, v *Validator[testCred], name string, args string) (sys.SyscallResult, error) {
	t.Helper()
	var raw json.RawMessage
	if args != "" {
		raw = json.RawMessage(args)
	}
	return v.Dispatch(context.Background(), testCred{id: "p1"}, sys.Syscall{Abi: sys.ABIVersion, Name: name, Args: raw}, sys.Authorization{})
}

func TestValidatorRejectsArgsFailingInputSchema(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(capability.Descriptor{
		Name:        "mail.send",
		InputSchema: json.RawMessage(`{"type":"object","required":["to"],"properties":{"to":{"type":"string"}}}`),
	}), next)

	for _, args := range []string{`{"to":42}`, `{}`, `"not an object"`, ""} {
		result, err := callValidator(t, v, "mail.send", args)
		if err != nil {
			t.Fatalf("dispatch(%q): %v", args, err)
		}
		if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoInvalidArgs {
			t.Fatalf("args %q: status/errno = %v/%v, want failed/invalid_args", args, result.Status(), result.Errno())
		}
	}
	if len(next.calls) != 0 {
		t.Fatalf("invalid args reached the next dispatcher: %v", next.calls)
	}
}

func TestValidatorPassesValidCallUnchanged(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(capability.Descriptor{
		Name:        "mail.send",
		InputSchema: json.RawMessage(`{"type":"object","required":["to"],"properties":{"to":{"type":"string"}}}`),
	}), next)

	result, err := callValidator(t, v, "mail.send", `{"to":"ops@example.com"}`)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("status = %v, want result", result.Status())
	}
	if len(next.calls) != 1 || next.calls[0].Name != "mail.send" || string(next.calls[0].Args) != `{"to":"ops@example.com"}` {
		t.Fatalf("next dispatcher saw %v, want the original syscall", next.calls)
	}
}

func TestValidatorPassesReservedSyscallsWithoutGrant(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(), next)

	for _, name := range []string{sys.SyscallBegin, sys.SyscallCommit} {
		result, err := callValidator(t, v, name, "")
		if err != nil {
			t.Fatalf("dispatch(%s): %v", name, err)
		}
		if result.Status() != sys.StatusResult {
			t.Fatalf("%s: status = %v, want passthrough result", name, result.Status())
		}
	}
	if len(next.calls) != 2 {
		t.Fatalf("reserved syscalls delegated %d times, want 2", len(next.calls))
	}
}

func TestValidatorSurfacesBrokenSchemaAsHostError(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(capability.Descriptor{
		Name:        "mail.send",
		InputSchema: json.RawMessage(`{"type":`),
	}), next)

	_, err := callValidator(t, v, "mail.send", `{}`)
	if err == nil || !strings.Contains(err.Error(), "input schema") {
		t.Fatalf("err = %v, want host-side schema error", err)
	}
	if len(next.calls) != 0 {
		t.Fatalf("call with broken schema reached the next dispatcher")
	}
}
