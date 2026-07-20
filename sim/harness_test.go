// Package sim is the deterministic simulation harness for the processor's
// durability laws (FoundationDB/Antithesis-style, scaled to this processor). It
// models the parts of the world that survive a crash — the journal and the
// external effect store — and drives a scripted, deterministic guest program
// through the full dispatcher chain (Validator → FlowMonitor → replay →
// Labeler → driver) while injecting a crash at any chosen journal append.
// Tests run the crash across *every* position and assert the invariants:
// replay convergence, exactly-once effects under idempotency keys, an intact
// hash chain, and correct saga unwinding.
package sim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"
)

// ErrCrash is the injected fault: the process died at a journal append.
var ErrCrash = errors.New("simulated crash")

// PID is the simulated process identity.
type PID struct{ ID string }

func (p PID) PID() string { return p.ID }

// Journal is an in-memory journaled.Journal plus fault injection: when
// CrashAt equals the number of appends performed so far, the append fails
// atomically (nothing is persisted) with ErrCrash — the process died. The
// processor itself ships only the Journal interface; the harness owns this
// simulated store the way consumer modules own the durable ones.
type Journal struct {
	header    journaled.Header
	hasHeader bool
	records   []journaled.Record
	appends   int
	CrashAt   int // -1 = never
}

func NewJournal() *Journal {
	return &Journal{CrashAt: -1}
}

func (j *Journal) Header() (journaled.Header, bool, error) { return j.header, j.hasHeader, nil }

func (j *Journal) SetHeader(header journaled.Header) error {
	j.header = header
	j.hasHeader = true
	return nil
}

func (j *Journal) Load(idx int) (journaled.Record, error) {
	if idx < 0 || idx >= len(j.records) {
		return journaled.Record{}, fmt.Errorf("journal: no record at %d", idx)
	}
	return j.records[idx], nil
}

func (j *Journal) Length() int { return len(j.records) }

func (j *Journal) Append(record journaled.Record) error {
	if j.appends == j.CrashAt {
		return ErrCrash
	}
	j.appends++
	j.records = append(j.records, record)
	return nil
}

// Effects is the external world: a keyed effect store, the way a real driver
// dedups at-least-once dispatch. It survives crashes — an effect applied
// before the process died stays applied.
type Effects struct {
	// results by idempotency key: the dedup table.
	results map[string]sys.SyscallResult
	// Applied counts real (non-deduped) executions per syscall name. The
	// exactly-once invariant is Applied[name] == 1 for each journaled effect.
	Applied map[string]int
	// Dispatches counts every driver invocation (at-least-once is allowed here).
	Dispatches int
}

func NewEffects() *Effects {
	return &Effects{
		results: make(map[string]sys.SyscallResult),
		Applied: make(map[string]int),
	}
}

// World is everything that survives a crash.
type World struct {
	Journal *Journal
	Effects *Effects
}

func NewWorld() *World {
	return &World{Journal: NewJournal(), Effects: NewEffects()}
}

// Step is one scripted guest syscall.
type Step struct {
	Name string
	Args string
}

// Program is a deterministic scripted guest: it issues its steps in order,
// stopping at the first dispatch error (the crash).
type Program []Step

// Capabilities granted to every simulated process. clock.now is a read,
// internet.read carries taint, transfer.refund is transfer.out's inverse.
func Capabilities() []sys.Capability {
	return []sys.Capability{
		{Name: "clock.now"},
		{Name: "internet.read", Labels: []string{"untrusted_web"}},
		{Name: "transfer.out"},
		{Name: "mail.send"},
		{Name: "transfer.refund", Hidden: true},
	}
}

type driver struct {
	effects *Effects
}

func (d driver) Dispatch(ctx context.Context, _ PID, syscall sys.Syscall, _ sys.Authorization) (sys.SyscallResult, error) {
	d.effects.Dispatches++
	key, ok := sys.IdempotencyKey(ctx)
	if !ok {
		return sys.SyscallResult{}, fmt.Errorf("driver received no idempotency key for %q", syscall.Name)
	}
	if result, done := d.effects.results[key]; done {
		return result, nil // deduped: the effect already happened
	}
	d.effects.Applied[syscall.Name]++
	result := sys.Result(json.RawMessage(fmt.Sprintf(`{"applied":%q,"seq":%d}`, syscall.Name, d.effects.Applied[syscall.Name])))
	d.effects.results[key] = result
	return result, nil
}

func (d driver) Capabilities() []sys.Capability { return Capabilities() }

// Chain builds the canonical dispatcher stack over the world, exactly as a
// real deployment does — via Stack.ForProcess, so the sim's crash matrix
// exercises the same layer order production runs. Fails with
// journaled.ReplayIncompatibleError etc. via the returned error.
func Chain(world *World, process string) (sys.Dispatcher[PID], error) {
	tape, err := journaled.NewTape(world.Journal, journaled.Header{
		ABI:     sys.ABIVersion,
		Program: "sha256:sim",
		Process: process,
	})
	if err != nil {
		return nil, err
	}
	stack := monitor.Stack[string, PID]{
		Grants: func(PID) []sys.Capability { return Capabilities() },
		Taints: monitor.NewTaints[string](), // fresh per boot: a crash loses host memory
	}
	return stack.ForProcess(tape, driver{effects: world.Effects})
}

// Run boots a fresh host process over the surviving world and drives the
// program from the start (crash-restart semantics: all in-memory state is
// new; only World persisted). It returns ErrCrash if the injected fault
// fired, nil when the program ran to completion.
func Run(world *World, process string, program Program) error {
	chain, err := Chain(world, process)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, step := range program {
		syscall := sys.Syscall{Abi: sys.ABIVersion, Name: step.Name}
		if step.Args != "" {
			syscall.Args = json.RawMessage(step.Args)
		}
		result, err := chain.Dispatch(ctx, PID{ID: process}, syscall, sys.Authorization{})
		if err != nil {
			return err
		}
		if result.Status() == sys.StatusFailed && result.Errno() == sys.ErrnoInternal {
			return fmt.Errorf("step %q failed: %s", step.Name, result.Message())
		}
	}
	return nil
}
