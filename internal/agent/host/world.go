package host

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
)

// worldDispatcher serves the journaled world sources, sys.now and sys.random.
// The processor pins the guest's ambient clock and RNG for determinism, so real
// time and entropy are capabilities: produced here on first execution — the
// dispatcher sits below the replay layer, so the value is journaled like any
// completion and replayed verbatim on resume. Everything else passes through.
type worldDispatcher[K any] struct {
	next sys.Dispatcher[K]
	now  func() time.Time
	rand io.Reader
}

type randomArgs struct {
	// Bytes is how much entropy to draw (default 16, max 64).
	Bytes int `json:"bytes"`
}

func (d *worldDispatcher[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallNow:
		payload, err := json.Marshal(map[string]int64{"unix_ms": d.now().UTC().UnixMilli()})
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		return sys.Result(payload), nil
	case sys.SyscallRandom:
		args := randomArgs{Bytes: 16}
		if len(syscall.Args) > 0 {
			if err := json.Unmarshal(syscall.Args, &args); err != nil {
				return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode sys.random: %v", err)), nil
			}
		}
		if args.Bytes <= 0 {
			args.Bytes = 16
		}
		if args.Bytes > 64 {
			return sys.FailCode(sys.ErrnoInvalidArgs, "sys.random: at most 64 bytes per call"), nil
		}
		buf := make([]byte, args.Bytes)
		if _, err := io.ReadFull(d.rand, buf); err != nil {
			return sys.Fail(fmt.Sprintf("sys.random: %v", err)), nil
		}
		payload, err := json.Marshal(map[string]string{"hex": hex.EncodeToString(buf)})
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		return sys.Result(payload), nil
	default:
		return d.next.Dispatch(ctx, cred, syscall, auth)
	}
}

func (d *worldDispatcher[K]) Capabilities() []sys.Capability {
	return append(d.next.Capabilities(),
		sys.Capability{
			Name:        sys.SyscallNow,
			Description: "read the wall clock (journaled: replay returns the recorded time)",
			InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
			Hidden:      true,
		},
		sys.Capability{
			Name:        sys.SyscallRandom,
			Description: "draw random bytes (journaled: replay returns the recorded bytes)",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"bytes":{"type":"integer","minimum":1,"maximum":64}},"additionalProperties":false}`),
			Hidden:      true,
		},
	)
}
