package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Table is one process's whole grant: every operation it may reach, how to find
// the operation in a call, and the descriptors those operations add up to.
type Table struct {
	entries map[Key]Entry
	// routes has one route per syscall a handler serves.
	routes map[string]route
	// reserved holds the syscalls a layer above the routing dispatcher serves
	// (the runtime's own protocol). resolve never looks here, so a reserved name
	// cannot reach a handler.
	reserved map[string]Descriptor
	// order is the order syscalls were added, so the menu is stable.
	order []string
}

// route is what the table knows about one routed syscall: the property that
// names its case, and its descriptor.
type route struct {
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

// Add indexes one family's entries. A syscall or an operation granted twice is
// an error: the manifest would mean two things at once.
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
		},
	}
	t.order = append(t.order, syscall)
	return nil
}

// Reserve admits a syscall that a layer above the routing dispatcher serves
// (sys.now, sys.log, sys.timer: the runtime's own protocol). A reserved
// name never resolves to an entry, so a layer that forgets to intercept its
// syscall fails closed at the bottom of the chain.
func (t *Table) Reserve(descriptor Descriptor) error {
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

// Hide keeps a syscall dispatchable but off the guest's tool menu.
func (t *Table) Hide(syscall string) {
	if route, served := t.routes[syscall]; served {
		route.descriptor.Hidden = true
		t.routes[syscall] = route
	}
}

// served is the syscall a family grants and the property that names its cases,
// read from the entries. Every entry must agree on both.
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
		// Without a discriminator a call can never name this case.
		if discriminator == "" && entry.Key.Operation != "" {
			return "", "", fmt.Errorf("operation %s names a case but declares no discriminator to select it", entry.Key)
		}
	}
	return syscall, discriminator, nil
}

// menuSchema is a syscall's argument schema, built from its entries: the one
// shape they share, or a oneOf over their distinct shapes.
func menuSchema(entries []Entry) json.RawMessage {
	branches := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		// An entry with no schema accepts anything, and a oneOf would refuse its
		// valid arguments. So the syscall goes unvalidated: resolve still denies
		// an operation the table does not serve.
		if len(entry.Input) == 0 {
			return nil
		}
		if !slices.ContainsFunc(branches, func(b json.RawMessage) bool { return bytes.Equal(b, entry.Input) }) {
			branches = append(branches, entry.Input)
		}
	}
	// Entries told apart by a property their schema does not pin (the internet
	// method) share one schema. Two equal oneOf branches would both match every
	// call, and oneOf would then refuse it, so one shared schema stands alone.
	if len(branches) == 1 {
		return branches[0]
	}
	union, _ := json.Marshal(branches)
	return json.RawMessage(fmt.Sprintf(`{"oneOf":%s}`, union))
}

// resolve finds the entry that serves a call. An unserved syscall or an
// ungranted operation is a DenialError. A discriminator that cannot be read is
// an ArgsError.
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

// caseName reads the discriminator property out of a call's arguments. An
// absent property reads as "". It fails only when the arguments are not an
// object, or the property is not a string.
func caseName(discriminator string, args json.RawMessage) (string, error) {
	if discriminator == "" {
		return "", nil
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

// DenialError is a call that names no granted operation. It lists what is
// granted, so a caller can tell a typo from a missing grant.
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

// ArgsError is a call whose discriminator could not be read.
type ArgsError struct {
	Syscall string
	Err     error
}

func (e *ArgsError) Error() string { return fmt.Sprintf("%s: %v", e.Syscall, e.Err) }
func (e *ArgsError) Unwrap() error { return e.Err }

// Labels returns the source classes a call's result carries. A call that
// resolves to no operation gets none: it is about to fail, and no operation
// produced its result.
func (t *Table) Labels(call sys.Syscall) []string {
	entry, err := t.resolve(call)
	if err != nil {
		return nil
	}
	return entry.Labels
}

// Operations lists the operations granted on one syscall, sorted.
func (t *Table) Operations(syscall string) []string {
	var out []string
	for key := range t.entries {
		if key.Syscall == syscall && key.Operation != "" {
			out = append(out, key.Operation)
		}
	}
	slices.Sort(out)
	return out
}

// Descriptors is the process's whole grant, routed and reserved syscalls
// alike, in the order they were added. It is the grant set the Validator
// enforces and, without the hidden ones, the guest's tool menu.
func (t *Table) Descriptors() []Descriptor {
	out := make([]Descriptor, 0, len(t.order))
	for _, syscall := range t.order {
		if descriptor, ok := t.Descriptor(syscall); ok {
			out = append(out, descriptor)
		}
	}
	return out
}

// Descriptor returns one syscall's descriptor, if the table admits it.
func (t *Table) Descriptor(syscall string) (Descriptor, bool) {
	if route, served := t.routes[syscall]; served {
		return route.descriptor, true
	}
	descriptor, reserved := t.reserved[syscall]
	return descriptor, reserved
}

// Entries returns every indexed operation, sorted by key.
func (t *Table) Entries() []Entry {
	out := slices.Collect(maps.Values(t.entries))
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Key.String(), b.Key.String()) })
	return out
}
