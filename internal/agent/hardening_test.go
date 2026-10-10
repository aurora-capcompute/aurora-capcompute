package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// L6: the guest's sys.input payload must carry role/content only — the taint
// labels seed the flow monitor host-side and must never be serialized to the
// (untrusted) guest, so the property is host-enforced, not a guest struct shape.
func TestSysInputOmitsHistoryLabelsFromGuestPayload(t *testing.T) {
	history := []HistoryMessage{
		{Role: "user", Content: "q"},
		{Role: "assistant", Content: "a", Labels: []string{"untrusted_web", "credential:ONYX@abc"}},
	}
	l, _ := mustLifecycle(t, nopNext{}, "task", history, manifest.Manifest{}, 1, acceptAnswer)
	result, err := l.Dispatch(context.Background(), durable.ProcessContext{},
		sys.Syscall{Abi: sys.ABIVersion, Name: sys.SyscallInput}, sys.Authorization{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	for _, needle := range []string{"untrusted_web", "credential:ONYX@abc"} {
		if bytes.Contains(result.Result(), []byte(needle)) {
			t.Fatalf("SECURITY: %q reached the guest sys.input payload: %s", needle, result.Result())
		}
	}
	// sys.declassify's schema names a "labels" argument, so look at the history only.
	var payload struct {
		History []map[string]json.RawMessage `json:"history"`
	}
	if err := json.Unmarshal(result.Result(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, message := range payload.History {
		if _, leaked := message["labels"]; leaked {
			t.Fatalf("SECURITY: a history message carries labels: %s", result.Result())
		}
	}
	// The taint still seeds the run host-side: the result carries the labels for
	// the flow monitor even though the guest payload does not.
	if len(result.Labels()) == 0 {
		t.Fatal("sys.input result must carry the history taint for the flow monitor")
	}
}

// L4: Clone deep-copies the History pointer, so a caller that retains the
// input manifest cannot mutate a stored clone.
func TestCloneManifestDeepCopiesPointers(t *testing.T) {
	yes := true
	original := manifest.Manifest{History: &yes}
	clone := original.Clone()
	*original.History = false
	if !clone.SharesHistory() {
		t.Fatal("mutating the original manifest's pointer changed the clone's setting")
	}
}

// An old manifest may still name sys.declassify: a bare grant validates; one
// that carries settings is refused.
func TestValidateManifestDeclassifyGrant(t *testing.T) {
	if _, err := manifest.Validate(manifest.Manifest{
		Version:  manifest.Version,
		Program:  "root",
		Syscalls: []manifest.Syscall{{Syscall: manifest.DeclassifySyscall}},
	}, &testDispatchers{}); err != nil {
		t.Fatalf("a bare sys.declassify grant should validate: %v", err)
	}
	if _, err := manifest.Validate(manifest.Manifest{
		Version:  manifest.Version,
		Syscalls: []manifest.Syscall{{Syscall: manifest.DeclassifySyscall, Config: json.RawMessage(`{"x":1}`)}},
	}, &testDispatchers{}); err == nil {
		t.Fatal("sys.declassify with settings should be rejected")
	}
}

func TestLifecyclePublishesDeclassifyByDefault(t *testing.T) {
	_, table := mustLifecycle(t, nopNext{}, "msg", nil, manifest.Manifest{}, 1, acceptAnswer)
	cap, ok := table.Descriptor(manifest.DeclassifySyscall)
	if !ok {
		t.Fatal("sys.declassify must be in every process's grant set")
	}
	if cap.Hidden {
		t.Fatal("sys.declassify should be visible so the model can request it")
	}
	if len(cap.InputSchema) == 0 {
		t.Fatal("sys.declassify must carry an input schema for the Validator")
	}
}

// The timer's schema carries the maximum duration, so the Validator refuses a
// duration past the bound — including one large enough to overflow int64
// nanoseconds — before the timer converts it.
func TestTimerSchemaBoundsDuration(t *testing.T) {
	table := capability.NewTable()
	timer, err := newTimerDispatcher(nopNext{}, manifest.Syscall{Syscall: manifest.TimerSyscall}, table)
	if err != nil {
		t.Fatalf("new timer: %v", err)
	}
	validated := monitor.NewValidator(table, sys.Dispatcher[durable.ProcessContext](timer))
	dispatch := func(seconds int64) sys.SyscallResult {
		t.Helper()
		r, err := validated.Dispatch(context.Background(), durable.ProcessContext{},
			sys.Syscall{Abi: sys.ABIVersion, Name: manifest.TimerSyscall,
				Args: json.RawMessage(fmt.Sprintf(`{"duration_seconds":%d}`, seconds))},
			sys.Authorization{})
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		return r
	}
	if r := dispatch(1 << 62); r.Status() != sys.StatusFailed || r.Errno() != sys.ErrnoInvalidArgs {
		t.Fatalf("overflowing duration = %v/%v, want failed/invalid_args", r.Status(), r.Errno())
	}
	if r := dispatch(int64(defaultMaxTimer/time.Second) + 1); r.Status() != sys.StatusFailed {
		t.Fatalf("over-max duration = %v, want failed", r.Status())
	}
	if r := dispatch(60); r.Status() != sys.StatusYield {
		t.Fatalf("a valid 60s timer = %v, want yield", r.Status())
	}
}
