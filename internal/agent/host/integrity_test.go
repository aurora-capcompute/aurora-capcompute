package host

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/aurora-capcompute/journaled"
	"github.com/aurora-capcompute/aurora-capcompute/monitor"
	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
)

type integrityPID struct{ id string }

func (p integrityPID) PID() string { return p.id }

type noopDispatcher struct{}

func (noopDispatcher) Dispatch(context.Context, integrityPID, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Result(nil), nil
}

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

// stubStore satisfies durable.TaskStore; the integrity check returns before it is used.
type stubStore struct{}

func (stubStore) Find(context.Context, durable.TaskScope, int, string) (durable.TaskRecord, bool, error) {
	return durable.TaskRecord{}, false, nil
}
func (stubStore) Create(context.Context, durable.TaskRecord) error { return nil }
func (stubStore) Get(context.Context, string, string) (durable.TaskRecord, error) {
	return durable.TaskRecord{}, nil
}
func (stubStore) List(context.Context, string, string) ([]durable.TaskRecord, error) {
	return nil, nil
}
func (stubStore) Resolve(context.Context, string, string, []byte, durable.TaskResolution, time.Time) (durable.TaskRecord, error) {
	return durable.TaskRecord{}, nil
}
func (stubStore) MarkExecuted(context.Context, string, time.Time) error { return nil }

// integrityEnv is the application half of the seam, stubbed: the journal and
// header under test, and nothing else doing any work.
type integrityEnv struct {
	journal journaled.Journal
	header  journaled.Header
}

func (integrityEnv) Drivers(context.Context, integrityPID) (sys.Dispatcher[integrityPID], *capability.Table, error) {
	return noopDispatcher{}, capability.NewTable(), nil
}

func (e integrityEnv) ProcessJournal(context.Context, integrityPID) (journaled.Journal, error) {
	return e.journal, nil
}

func (e integrityEnv) Header(integrityPID) journaled.Header { return e.header }

func (integrityEnv) TaskScope(integrityPID) durable.TaskScope { return durable.TaskScope{} }

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

// A journal replay cannot reason about must be refused before replay: the
// Factory fails closed rather than serve records the store handed back in a
// shape the tape never writes.
func TestNewDispatcherRefusesMalformedJournal(t *testing.T) {
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Process: "run"}
	malformed := &memJournal{}
	_ = malformed.SetHeader(header)
	result := sys.Result(nil)
	// A completion with no intent before it — the tape never writes this.
	_ = malformed.Append(journaled.Record{
		Position: 0, Kind: journaled.KindCompletion, Result: &result,
	})

	factory := integrityFactory(t, malformed, header)
	_, err := factory.NewDispatcher(context.Background(), integrityPID{id: "run"})
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("err = %v, want a journal integrity rejection", err)
	}
}

// A well-formed journal is admitted — the check is specific to damage, not a
// blanket refusal.
func TestNewDispatcherAdmitsIntactJournal(t *testing.T) {
	header := journaled.Header{ABI: sys.ABIVersion, Program: "prog", Process: "run"}
	intact := &memJournal{}
	_ = intact.SetHeader(header) // an empty journal is trivially well-formed
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
