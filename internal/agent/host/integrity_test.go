package host

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

type integrityPID struct{ id string }

func (p integrityPID) PID() string { return p.id }

type noopDispatcher struct{}

func (noopDispatcher) Dispatch(context.Context, integrityPID, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Result(nil), nil
}
func (noopDispatcher) Capabilities() []sys.Capability { return nil }

// memJournal is an in-memory journaled.Journal for these tests.
type memJournal struct {
	header journaled.Header
	has    bool
	recs   []journaled.Record
}

func (j *memJournal) Header() (journaled.Header, bool, error) { return j.header, j.has, nil }
func (j *memJournal) SetHeader(h journaled.Header) error      { j.header, j.has = h, true; return nil }
func (j *memJournal) Append(r journaled.Record) error         { j.recs = append(j.recs, r); return nil }
func (j *memJournal) Length() int                             { return len(j.recs) }
func (j *memJournal) Load(i int) (journaled.Record, error) {
	if i < 0 || i >= len(j.recs) {
		return journaled.Record{}, errors.New("no record")
	}
	return j.recs[i], nil
}

// stubStore satisfies task.Store; the integrity check returns before it is used.
type stubStore struct{}

func (stubStore) Find(context.Context, task.Scope, int, string) (task.Record, bool, error) {
	return task.Record{}, false, nil
}
func (stubStore) Create(context.Context, task.Record) error                { return nil }
func (stubStore) Get(context.Context, string, string) (task.Record, error) { return task.Record{}, nil }
func (stubStore) List(context.Context, string, string) ([]task.Record, error) {
	return nil, nil
}
func (stubStore) Resolve(context.Context, string, string, []byte, task.Resolution, time.Time) (task.Record, error) {
	return task.Record{}, nil
}
func (stubStore) MarkExecuted(context.Context, string, string, time.Time) error { return nil }

// integrityEnv is the application half of the seam, stubbed: the journal and
// header under test, and nothing else doing any work.
type integrityEnv struct {
	journal journaled.Journal
	header  journaled.Header
}

func (integrityEnv) Drivers(context.Context, integrityPID) (sys.Dispatcher[integrityPID], error) {
	return noopDispatcher{}, nil
}

func (e integrityEnv) ProcessJournal(context.Context, integrityPID) (journaled.Journal, error) {
	return e.journal, nil
}

func (e integrityEnv) Header(integrityPID) journaled.Header { return e.header }

func (integrityEnv) TaskScope(integrityPID) task.Scope { return task.Scope{} }

func integrityFactory(t *testing.T, journal journaled.Journal, header journaled.Header) *Factory[string, integrityPID] {
	t.Helper()
	factory, err := New(Config[string, integrityPID]{
		Environment: integrityEnv{journal: journal, header: header},
		Taints:      monitor.NewTaints[string](),
		Tasks:       stubStore{},
		TaskSecret:  []byte("secret"),
	})
	if err != nil {
		t.Fatalf("new factory: %v", err)
	}
	return factory
}

// A journal whose hash chain does not verify must be refused before replay: the
// Factory fails closed rather than serve a record a compromised or buggy durable
// store could have rewritten. This makes "tamper-evident" an enforced property,
// not merely an available check.
func TestNewDispatcherRefusesTamperedJournal(t *testing.T) {
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Process: "run"}
	tampered := &memJournal{}
	_ = tampered.SetHeader(header)
	sc := sys.Syscall{Abi: sys.ABIVersion, Name: "noop"}
	// A record whose PrevHash does not chain to the header digest — the exact
	// signature of a rewritten journal.
	_ = tampered.Append(journaled.Record{
		Position: 0, Kind: journaled.KindIntent, Syscall: &sc, PrevHash: "not-the-header-digest",
	})

	factory := integrityFactory(t, tampered, header)
	_, err := factory.NewDispatcher(context.Background(), integrityPID{id: "run"})
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("err = %v, want a journal integrity rejection", err)
	}
}

// A well-formed journal is admitted — the check is specific to a broken chain,
// not a blanket refusal.
func TestNewDispatcherAdmitsIntactJournal(t *testing.T) {
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Process: "run"}
	intact := &memJournal{}
	_ = intact.SetHeader(header) // an empty journal is a trivially intact chain
	factory := integrityFactory(t, intact, header)
	if _, err := factory.NewDispatcher(context.Background(), integrityPID{id: "run"}); err != nil {
		t.Fatalf("intact journal rejected: %v", err)
	}
}

// The wiring is checked once, when the factory is built — not on every process
// activation. A missing collaborator must fail the assembly at startup rather
// than surface as a broken process later.
func TestNewRequiresItsCollaborators(t *testing.T) {
	complete := Config[string, integrityPID]{
		Environment: integrityEnv{},
		Taints:      monitor.NewTaints[string](),
		Tasks:       stubStore{},
		TaskSecret:  []byte("secret"),
	}
	for name, drop := range map[string]func(*Config[string, integrityPID]){
		"environment": func(c *Config[string, integrityPID]) { c.Environment = nil },
		"taints":      func(c *Config[string, integrityPID]) { c.Taints = nil },
		"tasks":       func(c *Config[string, integrityPID]) { c.Tasks = nil },
		"task secret": func(c *Config[string, integrityPID]) { c.TaskSecret = nil },
	} {
		config := complete
		drop(&config)
		if _, err := New(config); err == nil {
			t.Errorf("New succeeded without %s, want an error", name)
		}
	}
	if _, err := New(complete); err != nil {
		t.Fatalf("complete config: %v", err)
	}
}

// The factory copies the secret it was given, so a caller reusing or clearing
// that slice afterwards cannot change the tokens tasks are stamped with.
func TestNewCopiesTheTaskSecret(t *testing.T) {
	secret := []byte("secret")
	factory, err := New(Config[string, integrityPID]{
		Environment: integrityEnv{},
		Taints:      monitor.NewTaints[string](),
		Tasks:       stubStore{},
		TaskSecret:  secret,
	})
	if err != nil {
		t.Fatalf("new factory: %v", err)
	}
	for i := range secret {
		secret[i] = 0
	}
	if string(factory.config.TaskSecret) != "secret" {
		t.Fatalf("task secret = %q, want the factory to hold its own copy", factory.config.TaskSecret)
	}
}
