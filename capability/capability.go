// Package capability is the runtime's capability vocabulary: a flat index of every
// operation a process may reach, keyed by (syscall, operation).
//
// The kernel deliberately owns none of this. capcompute/sys says what a syscall
// is and what a dispatcher does; what a syscall *means* — which cases it has,
// how to tell them apart, what their results are labelled, what may not flow
// into them, what performs them — is the runtime's security model, and it lives
// here.
//
// One table answers every one of those questions, which is the point: the
// routing dispatcher below the journal and the reference monitor above it call
// the same resolve on the same index, so a call cannot be one case to the
// monitor and a different case to the handler. That divergence would not fail
// loudly — it would apply no policy at all.
package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Key indexes one operation of one syscall family. Operation is empty for a
// syscall that has no discriminator — it is one operation by itself.
type Key struct {
	Syscall   string
	Operation string
}

func (k Key) String() string {
	if k.Operation == "" {
		return k.Syscall
	}
	return k.Syscall + "/" + k.Operation
}

// Handler performs one operation's effect. It is reached only after the table
// has resolved a call to an entry, so it never routes: one handler may back
// several entries (a single internet client serving GET and POST), and the
// entry — not the handler — is what the call was matched against.
type Handler interface {
	DispatchCall(ctx context.Context, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error)
}

// Entry is one dispatchable operation: what it is, the shape of its arguments,
// the policy that applies to it alone, and the thing that performs it.
//
// The policy lives here rather than on the Handler because one handler may back
// several entries with different policy — a single internet client serving a
// labelled GET and a forbidding POST — and because it is the entry, not the
// handler, that a monitor above the journal can see.
type Entry struct {
	Key Key
	// Discriminator names the argument property whose value is Key.Operation —
	// the other half of what makes this entry a case. An entry that carried only
	// the value would not say what it is a value of, and could not be read
	// without its family standing next to it.
	//
	// Empty means the syscall is one operation and Key.Operation is empty too.
	//
	// It is read, never canonicalized: the value the guest sent is matched
	// exactly, so a near miss is a refusal naming the alternatives rather than a
	// silent correction.
	Discriminator string
	Description   string
	Input         json.RawMessage
	// Labels are the source classes this operation's results carry; Forbid are
	// the labels barred from flowing into its arguments. Both are enforced by the
	// runtime's flow monitor — never by the handler, which is reached only once
	// the policy has already been applied.
	//
	// Policy is per case and only per case. A bar that should cover a whole
	// family is written on each of its entries, so there is one place to read
	// and no second, wider set to remember.
	Labels []string
	Forbid []string
	// RequireApproval parks the call until a human resolves it. It is enforced
	// below the replay tape, so the yield is journaled exactly once.
	RequireApproval bool
	Handler         Handler
}

// Family is everything one contributor has to say about one syscall: the cases
// themselves, and the prose that introduces them. It carries neither policy nor
// schema of its own — the first is the Entry's, and the second is projected from
// the entries by the table (see menuSchema). A contributor returns this and
// touches nothing else — the table is the assembler's, so no contributor can
// reach past its own grant.
type Family struct {
	Description string
	// Hidden keeps the family dispatchable but off the guest's discoverable menu.
	Hidden  bool
	Entries []Entry
}

// served is what this family is for — the syscall it grants and the property
// its cases are told apart by — taken from the entries rather than declared
// alongside them. There is then no way for the two to disagree, and no way to
// index an entry whose own account of itself the table does not use.
func (f Family) served() (syscall, discriminator string, err error) {
	if len(f.Entries) == 0 {
		return "", "", fmt.Errorf("a family must grant at least one operation")
	}
	syscall = f.Entries[0].Key.Syscall
	discriminator = f.Entries[0].Discriminator
	for _, entry := range f.Entries {
		if entry.Key.Syscall != syscall {
			return "", "", fmt.Errorf("family mixes syscalls %q and %q", syscall, entry.Key.Syscall)
		}
		if entry.Discriminator != discriminator {
			return "", "", fmt.Errorf("syscall %q tells its cases apart by %q and %q at once",
				syscall, discriminator, entry.Discriminator)
		}
		// A named case with nothing to read it out of is unreachable: caseName
		// would always resolve to "" and the entry would never be indexed.
		if discriminator == "" && entry.Key.Operation != "" {
			return "", "", fmt.Errorf("operation %s names a case but declares no discriminator to select it", entry.Key)
		}
	}
	return syscall, discriminator, nil
}

// menuSchema is the family-level argument schema — the shape a guest is handed
// and the reference monitor admits a call against — projected from the cases
// themselves rather than declared beside them. A contributor that wrote both
// would be writing the same branches twice, and the copy that drifted would be
// the one advertising an operation this table does not route.
func menuSchema(entries []Entry) json.RawMessage {
	branches := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		// A case with no shape of its own constrains nothing, and unioning it with
		// a sibling's branch would reject that case's own valid arguments. So the
		// whole family goes unvalidated: resolve below still denies an operation
		// this table does not serve.
		if len(entry.Input) == 0 {
			return nil
		}
		if !slices.ContainsFunc(branches, func(b json.RawMessage) bool { return bytes.Equal(b, entry.Input) }) {
			branches = append(branches, entry.Input)
		}
	}
	if len(branches) == 0 {
		return nil
	}
	// Cases told apart by a property their own shape does not pin — an internet
	// method — share one branch. A oneOf over two copies of it matches every
	// instance twice, which is exactly one too many: the union would admit
	// nothing at all.
	if len(branches) == 1 {
		return branches[0]
	}
	union, _ := json.Marshal(branches)
	return json.RawMessage(fmt.Sprintf(`{"oneOf":%s}`, union))
}

// caseName reads the discriminator property out of a call's arguments. An
// absent property reads as empty — that is a case in its own right, not a
// failure. It fails only when the arguments are not an object, or the property
// is present but not a string.
//
// This is the single case resolution in the system. Both the routing dispatcher
// and the flow monitor reach it through Table.resolve.
func caseName(discriminator string, args json.RawMessage) (string, error) {
	if discriminator == "" {
		return "", nil // a syscall that is one operation
	}
	malformed := fmt.Errorf("arguments must be an object with a string %q", discriminator)
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(args, &envelope); err != nil {
		return "", malformed
	}
	raw, present := envelope[discriminator]
	if !present {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", malformed
	}
	return value, nil
}

// Table is one process's whole grant surface: every operation it may reach, how
// to find the operation in a call, and the capabilities those operations add up
// to.
type Table struct {
	entries map[Key]Entry
	// routes is one entry per syscall this table serves. Everything in it is
	// projected from that syscall's entries at indexing time — nothing anyone
	// declares, and nothing to keep in step with the index it came from.
	routes map[string]route
	// reserved holds syscalls this table admits but does not route — served by a
	// decorator above the routing dispatcher. They are deliberately a separate
	// map: resolve never sees them, so a reserved name cannot be dispatched to a
	// handler it does not have.
	reserved map[string]Descriptor
	order    []string // added order, so the grant set and the menu are stable
}

// route is what the table knows about one syscall it serves: how to find the
// case in a call, and how the syscall presents itself to the monitor and to the
// guest. The entries it was derived from are not held beside it — they live in
// the flat index, which is the one place anything reads them.
type route struct {
	// discriminator is the property resolution reads before it knows which entry
	// the call is: the lookup order, not a second place anyone declares it.
	discriminator string
	descriptor    Descriptor
}

func NewTable() *Table {
	return &Table{
		entries:  make(map[Key]Entry),
		routes:   make(map[string]route),
		reserved: make(map[string]Descriptor),
	}
}

// Add indexes one family's entries. A duplicate key is an error rather than a
// silent first-wins: two grants serving one operation is a manifest that means
// two things at once, and a linear scan would answer that by picking whichever
// was appended first.
func (t *Table) Add(family Family) error {
	syscall, discriminator, err := family.served()
	if err != nil {
		return err
	}
	if _, taken := t.routes[syscall]; taken {
		return fmt.Errorf("syscall %q is served twice", syscall)
	}
	if _, taken := t.reserved[syscall]; taken {
		return fmt.Errorf("syscall %q is already reserved by a layer above", syscall)
	}
	for _, entry := range family.Entries {
		if entry.Handler == nil {
			return fmt.Errorf("entry %s has no handler", entry.Key)
		}
		if _, taken := t.entries[entry.Key]; taken {
			return fmt.Errorf("operation %s is granted twice", entry.Key)
		}
		t.entries[entry.Key] = entry
	}
	t.routes[syscall] = route{
		discriminator: discriminator,
		descriptor: Descriptor{
			Name:        syscall,
			Description: family.Description,
			InputSchema: menuSchema(family.Entries),
			Hidden:      family.Hidden,
		},
	}
	t.order = append(t.order, syscall)
	return nil
}

// resolve maps a call to the single entry that serves it. The two errors are
// different refusals: an unserved syscall or unknown case is a denial, a
// discriminator that cannot be read is bad input.
func (t *Table) resolve(call sys.Syscall) (Entry, error) {
	route, served := t.routes[call.Name]
	if !served {
		return Entry{}, &DenialError{Syscall: call.Name}
	}
	operation, err := caseName(route.discriminator, call.Args)
	if err != nil {
		return Entry{}, &ArgsError{Syscall: call.Name, Err: err}
	}
	entry, granted := t.entries[Key{Syscall: call.Name, Operation: operation}]
	if !granted {
		return Entry{}, &DenialError{Syscall: call.Name, Operation: operation, Granted: t.Operations(call.Name)}
	}
	return entry, nil
}

// DenialError is a call that names no granted operation. It carries what was
// asked for and what is available, so a caller can tell a typo from a missing
// grant without reading the manifest back.
type DenialError struct {
	Syscall   string
	Operation string
	Granted   []string
}

func (e *DenialError) Error() string {
	if e.Operation == "" {
		return fmt.Sprintf("capability %q is not granted", e.Syscall)
	}
	if len(e.Granted) == 0 {
		return fmt.Sprintf("%q grants no operations", e.Syscall)
	}
	return fmt.Sprintf("operation %q is not granted on %q; granted: %s",
		e.Operation, e.Syscall, strings.Join(e.Granted, ", "))
}

// ArgsError is a call whose discriminator could not be read at all.
type ArgsError struct {
	Syscall string
	Err     error
}

func (e *ArgsError) Error() string { return fmt.Sprintf("%s: %v", e.Syscall, e.Err) }
func (e *ArgsError) Unwrap() error { return e.Err }

// Forbidden reports the labels barred from flowing into a call, and the name to
// blame in the refusal. It is deliberately conservative where resolve is exact:
// a call this table cannot resolve to a case still answers with the family's own
// bar, so a malformed discriminator is never a way to reach a forbidding family
// with no check applied. An unserved syscall has no policy — it is about to be
// denied outright.
func (t *Table) Forbidden(call sys.Syscall) (forbid []string, sink string) {
	if _, served := t.routes[call.Name]; !served {
		return nil, call.Name
	}
	if entry, err := t.resolve(call); err == nil {
		return entry.Forbid, entry.Key.String()
	}
	// The case could not be read, so no single entry's bar is the right one.
	// Answer with every case's, unioned — the strictest reading of what the call
	// might have been. A discriminator the table cannot parse must not be the
	// cheapest way past a sink guard.
	return t.strictest(call.Name), call.Name
}

// strictest is the union of every bar under one syscall: what applies when the
// table cannot tell which case a call is.
func (t *Table) strictest(syscall string) []string {
	seen := make(map[string]struct{})
	var forbid []string
	for key, entry := range t.entries {
		if key.Syscall != syscall {
			continue
		}
		for _, label := range entry.Forbid {
			if _, dup := seen[label]; dup {
				continue
			}
			seen[label] = struct{}{}
			forbid = append(forbid, label)
		}
	}
	sort.Strings(forbid)
	return forbid
}

// Labels reports the source classes a call's result carries. Unlike Forbidden
// this is exact: a call that resolves to no case is about to fail anyway, and
// labelling it from the family would stamp provenance on a result no operation
// produced.
func (t *Table) Labels(call sys.Syscall) []string {
	entry, err := t.resolve(call)
	if err != nil {
		return nil
	}
	return entry.Labels
}

// Hide keeps a syscall dispatchable but off the guest's discoverable menu.
func (t *Table) Hide(syscall string) {
	if route, served := t.routes[syscall]; served {
		route.descriptor.Hidden = true
		t.routes[syscall] = route
	}
}

// Operations lists the operations granted for one syscall — what a refusal owes
// the caller.
func (t *Table) Operations(syscall string) []string {
	out := make([]string, 0, len(t.entries))
	for key := range t.entries {
		if key.Syscall == syscall && key.Operation != "" {
			out = append(out, key.Operation)
		}
	}
	sort.Strings(out)
	return out
}

// Descriptor is one syscall seen descriptively: what a guest is told it can
// call, and what the reference monitor admits it against. It is a projection of
// a Family (or of a Reserve), never a thing anyone declares twice — which is
// why nothing constructs one outside this package.
type Descriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	// Hidden keeps a syscall dispatchable but excluded from the guest's
	// discoverable menu (e.g. the cognition tool a program calls by a name it
	// already knows).
	Hidden bool `json:"hidden,omitempty"`
}

// Reserve records a syscall this table admits but does not route: one served by
// a decorator stacked above the routing dispatcher (sys.now, sys.log,
// sys.declassify — the runtime's own protocol). Reserved names never resolve to
// an entry, so a decorator that forgets to intercept its own syscall fails
// closed at the leaf rather than reaching a handler that was never there.
func (t *Table) Reserve(descriptor Descriptor) error {
	if descriptor.Name == "" {
		return fmt.Errorf("a reserved syscall must be named")
	}
	if _, taken := t.routes[descriptor.Name]; taken {
		return fmt.Errorf("syscall %q is already served by a handler", descriptor.Name)
	}
	if _, taken := t.reserved[descriptor.Name]; taken {
		return fmt.Errorf("syscall %q is reserved twice", descriptor.Name)
	}
	t.reserved[descriptor.Name] = descriptor
	t.order = append(t.order, descriptor.Name)
	return nil
}

// Descriptors is the process's whole admissible surface — routed families and
// reserved syscalls alike — in the order they were added. It is both the grant
// set the Validator enforces and, filtered to the visible ones, the menu the
// guest is handed.
func (t *Table) Descriptors() []Descriptor {
	out := make([]Descriptor, 0, len(t.order))
	for _, syscall := range t.order {
		if descriptor, ok := t.Descriptor(syscall); ok {
			out = append(out, descriptor)
		}
	}
	return out
}

// Descriptor answers what one name means in this table — the question every
// monitor layer asks.
func (t *Table) Descriptor(syscall string) (Descriptor, bool) {
	if route, served := t.routes[syscall]; served {
		return route.descriptor, true
	}
	descriptor, reserved := t.reserved[syscall]
	return descriptor, reserved
}

// Entries returns every indexed operation, ordered — the enumerable surface a
// capability set could not give, since its operations only ever existed inside a
// oneOf schema.
func (t *Table) Entries() []Entry {
	out := make([]Entry, 0, len(t.entries))
	for _, entry := range t.entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// Dispatcher routes one process's leaf syscalls to the operation that serves
// them. It is the bottom of the dispatcher chain and knows nothing about any
// particular capability: routing is a table lookup, and the table is the grant.
type Dispatcher[K any] struct {
	table *Table
}

func NewDispatcher[K any](table *Table) *Dispatcher[K] {
	return &Dispatcher[K]{table: table}
}

// Dispatch resolves a call to exactly one entry and hands it over. A miss is a
// denial rather than a routing failure — the table is the grant.
func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	entry, err := d.table.resolve(call)
	if err != nil {
		if _, bad := errors.AsType[*ArgsError](err); bad {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
		return sys.FailCode(sys.ErrnoDenied, err.Error()), nil
	}
	// Approval is enforced here, in one place, below the replay tape: the yield
	// and the human's answer are journaled exactly once, and no handler has to
	// remember to ask.
	if entry.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield(approvalPrompt(entry)), nil
	}
	return entry.Handler.DispatchCall(ctx, call, auth)
}

// approvalPrompt is what a human is asked to approve.
func approvalPrompt(entry Entry) string {
	if entry.Description != "" {
		return fmt.Sprintf("Approve %s: %s", entry.Key, entry.Description)
	}
	return fmt.Sprintf("Approve %s", entry.Key)
}

// ReserveMissing reserves a descriptor unless the name is already known. It
// exists for sys.log, which an assembly may serve as an ordinary driver grant —
// the runtime's own reservation must then defer to it rather than collide.
//
// Use it only where that is genuinely possible. A syscall the manifest layer
// marks runtime-served can never arrive as a driver family, so reserving one of
// those with Reserve makes a broken invariant fail loudly instead of silently
// leaving a driver's schema in force.
func (t *Table) ReserveMissing(descriptor Descriptor) error {
	if _, known := t.Descriptor(descriptor.Name); known {
		return nil
	}
	return t.Reserve(descriptor)
}
