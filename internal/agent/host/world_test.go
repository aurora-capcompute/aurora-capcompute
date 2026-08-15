package host

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute/sys"
)

type sink struct{}

func (sink) Dispatch(context.Context, struct{}, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Fail("unexpected passthrough"), nil
}

func TestWorldDispatcherServesJournaledSources(t *testing.T) {
	calls := 0
	table := capability.NewTable()
	world, buildErr := newWorldDispatcher[struct{}](sink{},
		func() time.Time { calls++; return time.UnixMilli(1_234_567) },
		bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}), table)
	if buildErr != nil {
		t.Fatalf("new world dispatcher: %v", buildErr)
	}

	result, err := world.Dispatch(context.Background(), struct{}{}, sys.Syscall{Abi: sys.ABIVersion, Name: sys.SyscallNow}, sys.Authorization{})
	if err != nil || result.Status() != sys.StatusResult {
		t.Fatalf("sys.now = %v, %v", result, err)
	}
	var now struct {
		UnixMS int64 `json:"unix_ms"`
	}
	if json.Unmarshal(result.Result(), &now) != nil || now.UnixMS != 1_234_567 || calls != 1 {
		t.Fatalf("now payload = %s (clock calls %d)", result.Result(), calls)
	}

	result, err = world.Dispatch(context.Background(), struct{}{}, sys.Syscall{
		Abi: sys.ABIVersion, Name: sys.SyscallRandom, Args: json.RawMessage(`{"bytes":4}`),
	}, sys.Authorization{})
	if err != nil || result.Status() != sys.StatusResult {
		t.Fatalf("sys.random = %v, %v", result, err)
	}
	var random struct {
		Hex string `json:"hex"`
	}
	if json.Unmarshal(result.Result(), &random) != nil || random.Hex != "deadbeef" {
		t.Fatalf("random payload = %s", result.Result())
	}

	// Bounds are enforced; the world sources are published, hidden, granted.
	result, _ = world.Dispatch(context.Background(), struct{}{}, sys.Syscall{
		Abi: sys.ABIVersion, Name: sys.SyscallRandom, Args: json.RawMessage(`{"bytes":65}`),
	}, sys.Authorization{})
	if result.Status() != sys.StatusFailed {
		t.Fatalf("oversized draw = %v, want failed", result)
	}
	for _, name := range []string{sys.SyscallNow, sys.SyscallRandom} {
		descriptor, ok := table.Descriptor(name)
		if !ok || !descriptor.Hidden {
			t.Fatalf("%s is not declared as a hidden capability in the grant table", name)
		}
	}
}
