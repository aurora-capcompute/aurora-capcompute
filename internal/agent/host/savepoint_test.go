package host

import (
	"context"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

// recordingDispatcher records the syscalls it receives so a test can assert
// which were passed through versus short-circuited by the savepoint layer.
type recordingDispatcher struct {
	seen []string
}

func (d *recordingDispatcher) Dispatch(_ context.Context, _ struct{}, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	d.seen = append(d.seen, syscall.Name)
	return sys.Result([]byte(`"passed"`)), nil
}

func (d *recordingDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{{Name: "base.cap"}}
}

func TestSavepointDispatcherInterceptsMarkers(t *testing.T) {
	next := &recordingDispatcher{}
	d := &savepointDispatcher[struct{}]{next: next}

	for _, name := range []string{sys.SyscallBegin, sys.SyscallCommit} {
		out, err := d.Dispatch(context.Background(), struct{}{}, sys.Syscall{Name: name}, sys.Authorization{})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if out.Status() != sys.StatusResult {
			t.Fatalf("%s: status = %s, want result", name, out.Status())
		}
	}
	if len(next.seen) != 0 {
		t.Fatalf("markers reached next dispatcher: %v", next.seen)
	}
}

func TestSavepointDispatcherPassesThroughOtherCalls(t *testing.T) {
	next := &recordingDispatcher{}
	d := &savepointDispatcher[struct{}]{next: next}

	out, err := d.Dispatch(context.Background(), struct{}{}, sys.Syscall{Name: "k8s.apply"}, sys.Authorization{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out.Result()) != `"passed"` {
		t.Fatalf("result = %s, want passthrough", out.Result())
	}
	if len(next.seen) != 1 || next.seen[0] != "k8s.apply" {
		t.Fatalf("passthrough calls = %v, want [k8s.apply]", next.seen)
	}
}

func TestSavepointDispatcherDelegatesCapabilities(t *testing.T) {
	d := &savepointDispatcher[struct{}]{next: &recordingDispatcher{}}
	caps := d.Capabilities()
	if len(caps) != 1 || caps[0].Name != "base.cap" {
		t.Fatalf("capabilities = %v, want [base.cap]", caps)
	}
}
