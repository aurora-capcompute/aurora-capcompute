package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/capcompute"
)

// seamRuntime is a runtime with no programs registered.
func seamRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(context.Background(), Config{
		Dispatchers: &runtimeDispatchers{},
		Log:         newMemLog(),
		TaskSecret:  []byte("seam-secret"),
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

// A quantum checks the program binding before it builds anything: a process
// whose program is not loaded, or is loaded under a different identity, fails
// that quantum rather than run under whatever bytes are registered now.
func TestQuantumRefusesAnUnboundProgram(t *testing.T) {
	runtime := seamRuntime(t)
	cred := durable.ProcessContext{SessionID: "s1", ProcessID: "p1", Revision: 1}

	result := runtime.runQuantum(context.Background(), cred, "unloaded@1", "digest")
	if result.status != capcompute.ResumeFailed || !errors.Is(result.err, errs.Conflict) {
		t.Fatalf("quantum of an unloaded program = %+v, want a failed conflict", result)
	}

	addTestProgram(t, runtime, "program@1", buildProgram(t))
	result = runtime.runQuantum(context.Background(), cred, "program@1", "stale")
	if result.status != capcompute.ResumeFailed || !errors.Is(result.err, errs.Conflict) {
		t.Fatalf("quantum under a stale digest = %+v, want a failed conflict", result)
	}
}
