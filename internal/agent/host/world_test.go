package host

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

type sink struct{}

func (sink) Dispatch(context.Context, struct{}, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Fail("unexpected passthrough"), nil
}

func (sink) Capabilities() []sys.Capability { return nil }

func TestWorldDispatcherServesJournaledSources(t *testing.T) {
	calls := 0
	world := &worldDispatcher[struct{}]{
		next: sink{},
		now:  func() time.Time { calls++; return time.UnixMilli(1_234_567) },
		rand: bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}),
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
	var sawNow, sawRandom bool
	for _, capability := range world.Capabilities() {
		if capability.Name == sys.SyscallNow && capability.Hidden {
			sawNow = true
		}
		if capability.Name == sys.SyscallRandom && capability.Hidden {
			sawRandom = true
		}
	}
	if !sawNow || !sawRandom {
		t.Fatal("world sources are not published as hidden capabilities")
	}
}
