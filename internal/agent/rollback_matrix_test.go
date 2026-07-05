package agent

// The deterministic rollback matrix: crash the host at every journal append
// across register → abort → settle → park → fire → refork and prove the story
// converges — the task completes with exactly one charge and exactly one
// refund, and the journal chain verifies. A "crash" is fail-stop: from the
// chosen append on, nothing more becomes durable and the world dispatches
// nothing more; a fresh runtime over the surviving prefix is the restart.
// Drivers dedupe on the idempotency key (the exactly-once contract a crash
// window requires — ROADMAP #18's shape).

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

var errWorldCrashed = errors.New("world crashed")

// crashLog is a fail-stop event log: append number crashAt (0-based) and every
// append after it fail until heal — the durable prefix is exactly what a real
// crash would leave. Reads keep working (a restarted host reads its store).
type crashLog struct {
	inner *memLog

	mu      sync.Mutex
	count   int
	crashAt int // -1 = never
	down    bool
}

func newCrashLog(crashAt int) *crashLog {
	return &crashLog{inner: newMemLog(), crashAt: crashAt}
}

func (c *crashLog) Append(ctx context.Context, scope eventlog.Scope, events ...eventlog.Event) (uint64, error) {
	c.mu.Lock()
	if c.down || (c.crashAt >= 0 && c.count+len(events) > c.crashAt) {
		c.down = true
		c.mu.Unlock()
		return 0, errWorldCrashed
	}
	c.count += len(events)
	c.mu.Unlock()
	return c.inner.Append(ctx, scope, events...)
}

func (c *crashLog) Read(ctx context.Context, scope eventlog.Scope, from uint64) ([]eventlog.Event, error) {
	return c.inner.Read(ctx, scope, from)
}

func (c *crashLog) Streams(ctx context.Context, tenantID string) ([]eventlog.Scope, error) {
	return c.inner.Streams(ctx, tenantID)
}

// Compact passes through to the inner log, still honoring fail-stop: a crashed
// world accepts no writes of any shape. The matrix itself never compacts —
// this exists so crashLog keeps satisfying eventlog.Log.
func (c *crashLog) Compact(ctx context.Context, scope eventlog.Scope, events []eventlog.Event) error {
	c.mu.Lock()
	if c.down {
		c.mu.Unlock()
		return errWorldCrashed
	}
	c.mu.Unlock()
	return c.inner.Compact(ctx, scope, events)
}

func (c *crashLog) crashed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.down
}

func (c *crashLog) heal() {
	c.mu.Lock()
	c.down = false
	c.crashAt = -1
	c.mu.Unlock()
}

func (c *crashLog) appends() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// matrixDispatcher is the external world: a scripted model plus charge/refund
// effects that stop at the crash instant and dedupe on the idempotency key, so
// a re-driven intent re-reads its recorded result instead of re-executing.
type matrixDispatcher struct {
	world *crashLog
	// failMidSection scripts the guest-failure story instead of the abort one:
	// the first turn charges, registers the refund, then requests an ungranted
	// capability — the guest dies with the section open, right after the
	// effect and its registration.
	failMidSection bool

	mu      sync.Mutex
	seen    map[string]sys.SyscallResult
	charges int
	refunds int
}

func (*matrixDispatcher) Normalize(_ string, settings json.RawMessage) (json.RawMessage, error) {
	if len(settings) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return append(json.RawMessage(nil), settings...), nil
}

func (d *matrixDispatcher) NewDispatcher(_ context.Context, _ ProcessContext, _ Manifest) (sys.Dispatcher[ProcessContext], error) {
	return d, nil
}

func (d *matrixDispatcher) Capabilities() []sys.Capability {
	return []sys.Capability{
		llmCapability(),
		{Name: "billing.charge", Description: "charge a card", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "billing.refund", Description: "refund a charge", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (d *matrixDispatcher) effect(ctx context.Context, name string, count *int, result sys.SyscallResult) (sys.SyscallResult, error) {
	key, _ := sys.IdempotencyKey(ctx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if key != "" {
		if recorded, ok := d.seen[name+"/"+key]; ok {
			return recorded, nil
		}
	}
	*count++
	if key != "" {
		d.seen[name+"/"+key] = result
	}
	return result, nil
}

func (d *matrixDispatcher) Dispatch(ctx context.Context, _ ProcessContext, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	if d.world.crashed() {
		return sys.SyscallResult{}, errWorldCrashed
	}
	switch syscall.Name {
	case "billing.charge":
		return d.effect(ctx, "charge", &d.charges, sys.Result(json.RawMessage(`{"charge_id":"c1"}`)))
	case "billing.refund":
		return d.effect(ctx, "refund", &d.refunds, sys.Result(json.RawMessage(`{"refunded":true}`)))
	case "openai.chat":
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(syscall.Args, &req)
		if _, later := firstAndLaterUser(req.Messages); later {
			// The charge observation is in: give up and roll back.
			return chatActions(`{"actions":[{"action":"abort","content":{"reason":"provider busy","retry_seconds":3600}}]}`), nil
		}
		// A fresh turn: a model that checks the world first. Before any
		// rollback it places the order; after one it reports the recovery —
		// keyed on external state, not the attempt number, so a plain crash
		// resume retries the task while a post-rollback retry concludes it.
		d.mu.Lock()
		refunded := d.refunds > 0
		d.mu.Unlock()
		if refunded {
			return chatActions(`{"actions":[{"action":"final","content":{"answer":"recovered-after-rollback"}}]}`), nil
		}
		if d.failMidSection {
			return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"compensate","content":{"name":"billing.refund","args":{"charge_id":"c1"}}},{"action":"kaboom.unavailable","content":{}}]}`), nil
		}
		return chatActions(`{"actions":[{"action":"billing.charge","content":{"amount":100}},{"action":"compensate","content":{"name":"billing.refund","args":{"charge_id":"c1"}}}]}`), nil
	default:
		return sys.Fail("unsupported call: " + syscall.Name), nil
	}
}

func (d *matrixDispatcher) counts() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.charges, d.refunds
}

// fireRetryTimers resolves any pending timer task the way the distribution's
// timer service would. Errors are tolerated: the world may crash mid-resolve.
func fireRetryTimers(runtime *Runtime, processID string) {
	tasks, err := runtime.Tasks(processID)
	if err != nil {
		return
	}
	for _, pending := range tasks {
		if pending.State != task.StatePending || pending.Syscall.Name != "timer.set" {
			continue
		}
		_, _ = runtime.ResolveTask(pending.ID, pending.ResolutionToken, task.Resolution{
			Decision: task.StateCompleted, Data: json.RawMessage(`{"status":"fired"}`), Actor: "timer",
		})
	}
}

func newMatrixRuntime(t *testing.T, world *crashLog, disp *matrixDispatcher) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(context.Background(), Config{
		Programs: staticPrograms{
			defaultID: "program@1",
			sources:   []ProgramSource{{ID: "program@1", Wasm: buildProgram(t)}},
		},
		Dispatchers:  disp,
		Log:          world,
		Leases:       newRuntimeStore(), // fresh per life: a real restart outlives lease TTLs
		ProcessTable: newMemProcessTable(),
		TaskSecret:   []byte("stable-secret"),
		IDSource:     sequentialIDs(),
	})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	return runtime
}

type matrixOutcome struct {
	appends  int
	skipped  bool // the crash predates the process becoming durable
	charges  int
	refunds  int
	answer   string
	chainErr error
}

// runRollbackFlow drives the whole story once, crashing at the given append
// (-1 = never), then restarts and recovers to completion.
func runRollbackFlow(t *testing.T, crashAt int, failMidSection bool) matrixOutcome {
	t.Helper()
	world := newCrashLog(crashAt)
	disp := &matrixDispatcher{world: world, failMidSection: failMidSection, seen: make(map[string]sys.SyscallResult)}

	// Life 1: run until the crash stops the world or the task completes.
	first := newMatrixRuntime(t, world, disp)
	var processID string
	if session, err := first.CreateSession(nil); err == nil {
		if proc, err := first.CreateProcess(session.ID, "place the order", Manifest{
			Version: ManifestVersion,
			Program: "program@1",
			Tools: []Tool{
				{Name: "billing.charge", Type: "core.custom"},
				{Name: "billing.refund", Type: "core.custom"},
			},
		}); err == nil {
			processID = proc.ID
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for processID != "" && !world.crashed() && time.Now().Before(deadline) {
		snap, err := first.GetProcess(processID)
		if err != nil {
			break
		}
		switch snap.Status {
		case ProcessWaitingTask:
			fireRetryTimers(first, processID)
		case ProcessFailed:
			// The failure story's convergence: the section rolled back, a
			// retry re-runs it fresh (a human or a policy would drive this).
			_, _ = first.Retry(processID, RetryResume)
		}
		if snap.Status == ProcessCompleted {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = first.Close(closeCtx)
	cancel()

	charges, refunds := disp.counts()
	outcome := matrixOutcome{appends: world.appends(), charges: charges, refunds: refunds}
	if !world.crashed() && processID != "" {
		if snap, err := first.GetProcess(processID); err == nil && snap.Status == ProcessCompleted {
			outcome.answer = snap.Answer
			return outcome // the no-crash baseline
		}
	}

	// Life 2: restart over the surviving prefix and recover without a human —
	// resume interrupted work, fire timers, retry failed rollbacks.
	world.heal()
	second := newMatrixRuntime(t, world, disp)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = second.Close(ctx)
	}()

	if processID == "" {
		outcome.skipped = true
		return outcome
	}
	if _, err := second.GetProcess(processID); err != nil {
		outcome.skipped = true // crashed before the process became durable
		return outcome
	}
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := second.GetProcess(processID)
		if err != nil {
			t.Fatalf("crashAt=%d: get process after restart: %v", crashAt, err)
		}
		switch snap.Status {
		case ProcessCompleted:
			outcome.answer = snap.Answer
			outcome.charges, outcome.refunds = disp.counts()
			second.mu.Lock()
			if proc := second.processes[processID]; proc != nil && proc.journal != nil {
				outcome.chainErr = journaled.Verify(proc.journal)
			}
			second.mu.Unlock()
			return outcome
		case ProcessWaitingTask:
			fireRetryTimers(second, processID)
		case ProcessInterrupted, ProcessFailed, ProcessStopped:
			_, _ = second.Retry(processID, RetryResume)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("crashAt=%d: never recovered to completion", crashAt)
	return outcome
}

// TestRollbackCrashMatrix crashes at every append position of the abort
// story — the guest's own sys.abort — and requires convergence: the task
// completes, effects are exactly-once (one charge, one refund — never a lost
// or doubled inverse), and the journal chain verifies.
func TestRollbackCrashMatrix(t *testing.T) {
	runCrashMatrix(t, false)
}

// TestFailureRollbackCrashMatrix is the class the abort matrix cannot see: the
// guest FAILS mid-section — after the charge executed and its refund was
// registered — instead of aborting cleanly. The failure must abort the section
// (rollback-before-redo), and the retry must re-run it over compensated state;
// crashing at every append across fail → host abort → settle → retry → refork
// proves no window orphans the registration or doubles an effect.
func TestFailureRollbackCrashMatrix(t *testing.T) {
	runCrashMatrix(t, true)
}

func runCrashMatrix(t *testing.T, failMidSection bool) {
	if testing.Short() {
		t.Skip("matrix is not short")
	}
	baseline := runRollbackFlow(t, -1, failMidSection)
	if baseline.answer != "recovered-after-rollback" {
		t.Fatalf("baseline answer = %q", baseline.answer)
	}
	if baseline.charges != 1 || baseline.refunds != 1 {
		t.Fatalf("baseline charges=%d refunds=%d, want 1 and 1", baseline.charges, baseline.refunds)
	}

	for crashAt := 1; crashAt < baseline.appends; crashAt++ {
		outcome := runRollbackFlow(t, crashAt, failMidSection)
		if outcome.skipped {
			continue // the world ended before the task existed
		}
		if outcome.answer != "recovered-after-rollback" {
			t.Fatalf("crashAt=%d: answer = %q", crashAt, outcome.answer)
		}
		if outcome.charges != 1 || outcome.refunds != 1 {
			t.Fatalf("crashAt=%d: charges=%d refunds=%d, want exactly-once", crashAt, outcome.charges, outcome.refunds)
		}
		if outcome.chainErr != nil {
			t.Fatalf("crashAt=%d: chain verify: %v", crashAt, outcome.chainErr)
		}
	}
}
