package agent

import (
	"testing"
	"time"
)

// The distribution must be bounded by default: an operator who wires a runtime
// without thinking about resource limits must still get a guest that cannot
// exhaust host memory or spin forever. This proves the policy in resolveGuestLimits
// — zero → safe default, positive → verbatim, negative → explicitly unbounded —
// so "accidentally unbounded" is not reachable through a zero-value Config.
func TestResolveGuestLimitsIsBoundedByDefault(t *testing.T) {
	cases := []struct {
		name        string
		pagesIn     int
		timeoutIn   time.Duration
		wantPages   uint32
		wantTimeout time.Duration
	}{
		{
			name:        "zero value yields the safe defaults",
			pagesIn:     0,
			timeoutIn:   0,
			wantPages:   defaultProcessMemoryPages,
			wantTimeout: defaultResumeQuantumTimeout,
		},
		{
			name:        "explicit positive values are used verbatim",
			pagesIn:     8192,
			timeoutIn:   30 * time.Second,
			wantPages:   8192,
			wantTimeout: 30 * time.Second,
		},
		{
			name:        "negative disables each limit",
			pagesIn:     -1,
			timeoutIn:   -1,
			wantPages:   0,
			wantTimeout: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pages, timeout := resolveGuestLimits(tc.pagesIn, tc.timeoutIn)
			if pages != tc.wantPages {
				t.Fatalf("pages = %d, want %d", pages, tc.wantPages)
			}
			if timeout != tc.wantTimeout {
				t.Fatalf("timeout = %s, want %s", timeout, tc.wantTimeout)
			}
		})
	}

	// The crown-jewel property: the default must be a real, finite bound, never
	// the kernel's "0 = unbounded" sentinel.
	pages, timeout := resolveGuestLimits(0, 0)
	if pages == 0 {
		t.Fatal("default memory cap is 0 (unbounded) — a zero-value Config must still bound guest memory")
	}
	if timeout <= 0 {
		t.Fatal("default quantum timeout is unbounded — a zero-value Config must still bound guest CPU")
	}
}
