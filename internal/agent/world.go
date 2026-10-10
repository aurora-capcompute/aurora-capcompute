package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/capcompute/sys"
)

// worldDispatcher serves sys.now and sys.random: the real clock and real
// entropy. The processor pins the guest's own clock and RNG for determinism, so
// real values come only through these calls. The layer sits below the replay
// layer, so a value is journaled the first time and replayed after that.
type worldDispatcher struct {
	next sys.Dispatcher[durable.ProcessContext]
	now  func() time.Time
	rand io.Reader
}

// newWorldDispatcher builds the layer and admits its syscalls into the table.
func newWorldDispatcher(next sys.Dispatcher[durable.ProcessContext], now func() time.Time, rand io.Reader, table *capability.Table) (*worldDispatcher, error) {
	for _, descriptor := range []capability.Descriptor{
		{
			Name:        sys.SyscallNow,
			Description: "read the wall clock (journaled: replay returns the recorded time)",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
			Hidden:      true,
		},
		{
			Name:        sys.SyscallRandom,
			Description: "draw random bytes, 16 by default (journaled: replay returns the recorded bytes)",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"bytes":{"type":"integer","minimum":1,"maximum":64}},"additionalProperties":false}`),
			Hidden:      true,
		},
	} {
		if err := table.Reserve(descriptor); err != nil {
			return nil, err
		}
	}
	return &worldDispatcher{next: next, now: now, rand: rand}, nil
}

type randomArgs struct {
	// Bytes is how much entropy to draw. The schema bounds it to 1..64.
	Bytes int `json:"bytes"`
}

func (d *worldDispatcher) Dispatch(ctx context.Context, cred durable.ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallNow:
		payload, _ := json.Marshal(map[string]int64{"unix_ms": d.now().UTC().UnixMilli()})
		return sys.Result(payload), nil
	case sys.SyscallRandom:
		args := randomArgs{Bytes: 16}
		if err := json.Unmarshal(syscall.Args, &args); err != nil {
			return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.random: %v", err)), nil
		}
		buf := make([]byte, args.Bytes)
		if _, err := io.ReadFull(d.rand, buf); err != nil {
			return sys.Fail(fmt.Sprintf("sys.random: %v", err)), nil
		}
		payload, _ := json.Marshal(map[string]string{"hex": hex.EncodeToString(buf)})
		return sys.Result(payload), nil
	default:
		return d.next.Dispatch(ctx, cred, syscall, auth)
	}
}
