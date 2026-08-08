package agent

// The runtime's two halves of the run queue's seam, tested without a guest.
// Everything here stops short of instantiating wasm, so these run even where the
// Rust toolchain and the program sources are unavailable — which is most places,
// and which is why the paths below used to go unexercised entirely.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
)

// seamRuntime is a runtime with no programs registered: enough to exercise
// activation's lookup, which fails at the program binding rather than at wasm.
func seamRuntime(t *testing.T) *Runtime {
	t.Helper()
	store := newRuntimeStore()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: &runtimeDispatchers{},
		Log:         store.log,
		Leases:      store,
		TaskSecret:  []byte("seam-secret"),
		IDSource:    sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})
	return runtime
}

// A processor outcome becomes a queue outcome. Anything unrecognised is a
// failure rather than a silent success: a status the runtime cannot name must
// not be mistaken for one that finished cleanly.
func TestQuantumResultRestatesProcessorOutcomes(t *testing.T) {
	cause := errors.New("boom")
	for _, test := range []struct {
		from capcompute.ResumeStatus
		want sched.Status
	}{
		{capcompute.ResumeCompleted, sched.Completed},
		{capcompute.ResumeYielded, sched.Yielded},
		{capcompute.ResumeStopped, sched.Stopped},
		{capcompute.ResumeFailed, sched.Failed},
		{capcompute.ResumeStatus("something new"), sched.Failed},
	} {
		got := toResult(capcompute.ResumeResult{Status: test.from, Err: cause})
		if got.Status != test.want {
			t.Errorf("%s became %s, want %s", test.from, got.Status, test.want)
		}
		if !errors.Is(got.Err, cause) {
			t.Errorf("%s lost its cause", test.from)
		}
	}
}

// Activation is keyed by process *revision*. A submission queued against a
// revision the process has since forked past is stale and must not run — that
// guard is the reason the queue's key carries a revision at all.
func TestActivateRefusesAStaleRevision(t *testing.T) {
	runtime := seamRuntime(t)
	runtime.mu.Lock()
	runtime.processes["p1"] = &processState{
		id:        "p1",
		sessionID: "s1",
		revision:  2,
		manifest:  manifest.Manifest{Version: manifest.Version, Program: "unloaded@1"},
	}
	runtime.mu.Unlock()

	activator := processActivator{runtime: runtime}
	for _, test := range []struct {
		name string
		key  processKey
	}{
		{"unknown process", processKey{processID: "nope", revision: 1}},
		{"superseded revision", processKey{processID: "p1", revision: 1}},
	} {
		if _, err := activator.Execute(context.Background(), test.key); !errors.Is(err, errs.NotFound) {
			t.Errorf("%s: err = %v, want NotFound", test.name, err)
		}
	}

	// The current revision gets past the lookup and fails later, on the program
	// binding — which is what proves the lookup itself matched.
	_, err := activator.Execute(context.Background(), processKey{processID: "p1", revision: 2})
	if err == nil || !strings.Contains(err.Error(), "unloaded@1") {
		t.Fatalf("err = %v, want the current revision to reach its program binding", err)
	}
	if errors.Is(err, errs.NotFound) {
		t.Fatalf("current revision was treated as missing: %v", err)
	}
}

// Both ways onto the CPU deliver an outcome on the same channel, including when
// activation fails. The root queues for a slot and the child runs off the queue,
// but nothing above them has to care which.
func TestStartQuantumDeliversAResultOnBothPaths(t *testing.T) {
	runtime := seamRuntime(t)
	key := processKey{processID: "absent", revision: 1}

	for _, test := range []struct {
		name    string
		isChild bool
	}{
		{"root queues for a slot", false},
		{"child runs off the queue", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			results, stop, err := runtime.startQuantum(context.Background(), key, 0, test.isChild)
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			if stop == nil {
				t.Fatal("no way to abort the quantum")
			}
			select {
			case result := <-results:
				if result.Status != sched.Failed {
					t.Fatalf("status = %s, want failed", result.Status)
				}
				if !errors.Is(result.Err, errs.NotFound) {
					t.Fatalf("err = %v, want the activation's cause", result.Err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no result delivered")
			}
		})
	}
}
