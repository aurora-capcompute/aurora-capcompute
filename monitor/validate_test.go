package monitor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

type recordingDispatcher struct {
	calls []sys.Syscall
}

func (d *recordingDispatcher) Dispatch(_ context.Context, _ testPID, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	d.calls = append(d.calls, syscall)
	return sys.Result(json.RawMessage(`{"ok":true}`)), nil
}

func (d *recordingDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{{Name: "listed.by.next"}}
}

func grantsFixture(grants ...sys.Capability) GrantSource[testPID] {
	return func(testPID) []sys.Capability { return grants }
}

func callValidator(t *testing.T, v *Validator[testPID], name string, args string) (sys.SyscallResult, error) {
	t.Helper()
	var raw json.RawMessage
	if args != "" {
		raw = json.RawMessage(args)
	}
	return v.Dispatch(context.Background(), testPID{id: "p1"}, sys.Syscall{Abi: sys.ABIVersion, Name: name, Args: raw}, sys.Authorization{})
}

func TestValidatorDeniesUngrantedCapability(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(sys.Capability{Name: "mail.send"}), next)

	result, err := callValidator(t, v, "k8s.delete", `{}`)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusFailed || result.Errno() != sys.ErrnoDenied {
		t.Fatalf("status/errno = %v/%v, want failed/denied", result.Status(), result.Errno())
	}
	if len(next.calls) != 0 {
		t.Fatalf("ungranted syscall reached the next dispatcher: %v", next.calls)
	}
}

func TestValidatorRejectsArgsFailingInputSchema(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(sys.Capability{
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
	v := NewValidator(grantsFixture(sys.Capability{
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

func TestValidatorAllowsCapabilityWithoutSchema(t *testing.T) {
	next := &recordingDispatcher{}
	v := NewValidator(grantsFixture(sys.Capability{Name: "clock.now"}), next)

	result, err := callValidator(t, v, "clock.now", "")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if result.Status() != sys.StatusResult {
		t.Fatalf("status = %v, want result", result.Status())
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
	v := NewValidator(grantsFixture(sys.Capability{
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

func TestValidatorCapabilitiesDelegates(t *testing.T) {
	v := NewValidator(grantsFixture(), &recordingDispatcher{})
	capabilities := v.Capabilities()
	if len(capabilities) != 1 || capabilities[0].Name != "listed.by.next" {
		t.Fatalf("capabilities = %v, want next's list", capabilities)
	}
}
