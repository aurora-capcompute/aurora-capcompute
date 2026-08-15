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
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Key         Key
	Description string
	Input       json.RawMessage
	// Labels are the source classes this operation's results carry; Forbid are
	// the labels barred from flowing into its arguments. Both are enforced by the
	// runtime's flow monitor — never by the handler.
	//
	// After indexing, both include the family's own sets: see Family.
	Labels []string
	Forbid []string
	// RequireApproval parks the call until a human resolves it. It is enforced
	// below the replay tape, so the yield is journaled exactly once.
	RequireApproval bool
	Handler         Handler
}

// Family is everything one contributor has to say about one syscall: how to
// tell its cases apart, the cases themselves, and what the family as a whole
// means. A contributor returns this and touches nothing else — the table is the
// assembler's, so no contributor can reach past its own grant.
type Family struct {
	Description string
	// Input is the family-level argument schema the reference monitor validates
	// against before any case is resolved.
	Input json.RawMessage
	// Hidden keeps the family dispatchable but off the guest's discoverable menu.
	Hidden bool
	// Labels and Forbid apply to every case. They are folded into each entry at
	// indexing time, so a family-wide bar cannot be escaped by declaring an
	// operation that omits it, and one lookup answers the whole policy.
	Labels []string
	Forbid []string
	// Discriminator names the argument property whose value selects a case.
	// Empty means the syscall is one operation.
	//
	// It is read, never canonicalized: the value the guest sent is matched
	// exactly, so a near miss is a refusal naming the alternatives rather than a
	// silent correction.
	Discriminator string
	Entries       []Entry
}

// syscall is the one this family is for, taken from the entries rather than
// passed alongside them — there is then no way for the two to disagree.
func (f Family) syscall() (string, error) {
	if len(f.Entries) == 0 {
		return "", fmt.Errorf("a family must grant at least one operation")
	}
	syscall := f.Entries[0].Key.Syscall
	for _, entry := range f.Entries {
		if entry.Key.Syscall != syscall {
			return "", fmt.Errorf("family mixes syscalls %q and %q", syscall, entry.Key.Syscall)
		}
	}
	return syscall, nil
}

// caseName reads the discriminator property out of a call's arguments. An
// absent property reads as empty — that is a case in its own right, not a
// failure. It fails only when the arguments are not an object, or the property
// is present but not a string.
//
// This is the single case resolution in the system. Both the routing dispatcher
// and the flow monitor reach it through Table.resolve.
func (f Family) caseName(args json.RawMessage) (string, error) {
	if f.Discriminator == "" {
		return "", nil // a syscall that is one operation
	}
	malformed := fmt.Errorf("arguments must be an object with a string %q", f.Discriminator)
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(args, &envelope); err != nil {
		return "", malformed
	}
	raw, present := envelope[f.Discriminator]
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
	entries  map[Key]Entry
	families map[string]Family
	// reserved holds syscalls this table admits but does not route — served by a
	// decorator above the routing dispatcher. They are deliberately a separate
	// map: resolve never sees them, so a reserved name cannot be dispatched to a
	// handler it does not have.
	reserved map[string]Descriptor
	order    []string // added order, so the grant set and the menu are stable
}

func NewTable() *Table {
	return &Table{
		entries:  make(map[Key]Entry),
		families: make(map[string]Family),
		reserved: make(map[string]Descriptor),
	}
}

// Add indexes one family's entries. A duplicate key is an error rather than a
// silent first-wins: two grants serving one operation is a manifest that means
// two things at once, and a linear scan would answer that by picking whichever
// was appended first.
func (t *Table) Add(family Family) error {
	syscall, err := family.syscall()
	if err != nil {
		return err
	}
	if _, taken := t.families[syscall]; taken {
		return fmt.Errorf("syscall %q is served twice", syscall)
	}
	if _, taken := t.reserved[syscall]; taken {
		return fmt.Errorf("syscall %q is already reserved by a layer above", syscall)
	}
	indexed := make([]Entry, 0, len(family.Entries))
	for _, entry := range family.Entries {
		if entry.Handler == nil {
			return fmt.Errorf("entry %s has no handler", entry.Key)
		}
		if _, taken := t.entries[entry.Key]; taken {
			return fmt.Errorf("operation %s is granted twice", entry.Key)
		}
		// Fold the family's policy in now, so every later question is one lookup
		// and no case can be reached with less than the family's own bar.
		entry.Labels = union(family.Labels, entry.Labels)
		entry.Forbid = union(family.Forbid, entry.Forbid)
		t.entries[entry.Key] = entry
		indexed = append(indexed, entry)
	}
	family.Entries = indexed
	t.families[syscall] = family
	t.order = append(t.order, syscall)
	return nil
}

// resolve maps a call to the single entry that serves it. The two errors are
// different refusals: an unserved syscall or unknown case is a denial, a
// discriminator that cannot be read is bad input.
func (t *Table) resolve(call sys.Syscall) (Entry, error) {
	family, served := t.families[call.Name]
	if !served {
		return Entry{}, &DenialError{Syscall: call.Name}
	}
	operation, err := family.caseName(call.Args)
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
	family, served := t.families[call.Name]
	if !served {
		return nil, call.Name
	}
	if entry, err := t.resolve(call); err == nil {
		return entry.Forbid, entry.Key.String()
	}
	return family.Forbid, call.Name
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
	if family, served := t.families[syscall]; served {
		family.Hidden = true
		t.families[syscall] = family
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
	if _, taken := t.families[descriptor.Name]; taken {
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
	if family, served := t.families[syscall]; served {
		return Descriptor{
			Name:        syscall,
			Description: family.Description,
			InputSchema: family.Input,
			Hidden:      family.Hidden,
		}, true
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

// union appends the entry's own set to the family's, dropping repeats. Order is
// the family's first, which keeps a refusal's message stable.
func union(family, own []string) []string {
	if len(family) == 0 {
		return own
	}
	seen := make(map[string]struct{}, len(family)+len(own))
	out := make([]string, 0, len(family)+len(own))
	for _, set := range [][]string{family, own} {
		for _, label := range set {
			if _, dup := seen[label]; dup {
				continue
			}
			seen[label] = struct{}{}
			out = append(out, label)
		}
	}
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
// exists because an assembly may serve one of the runtime's protocol syscalls
// itself (sys.log is the case in practice); the runtime's own reservation must
// then defer rather than collide.
func (t *Table) ReserveMissing(descriptor Descriptor) error {
	if _, known := t.Descriptor(descriptor.Name); known {
		return nil
	}
	return t.Reserve(descriptor)
}
