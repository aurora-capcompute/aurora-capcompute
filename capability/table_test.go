package capability

import (
	"bytes"
	"context"
	"testing"

	"github.com/aurora-capcompute/capcompute/sys"
)

type nopHandler struct{}

func (nopHandler) DispatchCall(context.Context, sys.Syscall, sys.Authorization) (sys.SyscallResult, error) {
	return sys.Result(nil), nil
}

func entry(syscall, discriminator, operation string) Entry {
	return Entry{
		Key:           Key{Syscall: syscall, Operation: operation},
		Discriminator: discriminator,
		Handler:       nopHandler{},
	}
}

// A case is (property, value): the property it is read from is as much a part of
// an entry as the value that selects it. Because the table derives the property
// from the entries rather than taking it declared alongside them, an entry that
// disagrees with its siblings is refused instead of being silently indexed under
// somebody else's discriminator.
func TestFamilyRefusesCasesToldApartTwoWays(t *testing.T) {
	table := NewTable()
	err := table.Add(Family{Entries: []Entry{
		entry("core.internet", "method", "GET"),
		entry("core.internet", "operation", "POST"),
	}})
	if err == nil {
		t.Fatal("a family whose cases name two different discriminators was indexed")
	}
	if _, served := table.Descriptor("core.internet"); served {
		t.Fatal("the refused family was indexed anyway")
	}
}

// An entry that names a case but no property to read it from can never be
// reached: resolution would always produce the empty case. That is a wiring bug
// worth refusing at indexing time rather than a grant that silently does nothing.
func TestFamilyRefusesANamedCaseWithNoDiscriminator(t *testing.T) {
	err := NewTable().Add(Family{Entries: []Entry{entry("core.internet", "", "GET")}})
	if err == nil {
		t.Fatal("an unreachable case was indexed")
	}
}

// The ordinary shapes still index: one syscall that is a single operation, and
// one told apart by a property its cases agree on.
func TestFamilyIndexesBothShapes(t *testing.T) {
	table := NewTable()
	if err := table.Add(Family{Entries: []Entry{entry("sys.ping", "", "")}}); err != nil {
		t.Fatalf("single-operation syscall refused: %v", err)
	}
	if err := table.Add(Family{Entries: []Entry{
		entry("core.internet", "method", "GET"),
		entry("core.internet", "method", "POST"),
	}}); err != nil {
		t.Fatalf("discriminated syscall refused: %v", err)
	}

	resolved, err := table.resolve(sys.Syscall{Name: "core.internet", Args: []byte(`{"method":"POST"}`)})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Key.Operation != "POST" {
		t.Fatalf("resolved %s, want the POST case", resolved.Key)
	}
	if resolved.Discriminator != "method" {
		t.Fatalf("resolved entry says it is told apart by %q, want method", resolved.Discriminator)
	}
}

// Hiding is a property of the record the table holds, not of the family the
// contributor handed over — that copy is gone once the entries are indexed. So
// Hide has to write its change back, and the menu has to be read from what it
// wrote: a grant the manifest marks hidden but the table still advertises is a
// capability the guest was never meant to discover.
func TestHideKeepsTheSyscallOffTheMenu(t *testing.T) {
	table := NewTable()
	if err := table.Add(Family{Description: "cognition", Entries: []Entry{entry("core.openaiApi", "", "")}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	table.Hide("core.openaiApi")

	descriptor, served := table.Descriptor("core.openaiApi")
	if !served || !descriptor.Hidden {
		t.Fatalf("descriptor = %+v, want it served and hidden", descriptor)
	}
	if descriptors := table.Descriptors(); len(descriptors) != 1 || !descriptors[0].Hidden {
		t.Fatalf("menu = %+v, want the hidden grant reported hidden", descriptors)
	}
	// Hidden is not ungranted: the agent still calls it by a name it knows.
	if _, err := table.resolve(sys.Syscall{Name: "core.openaiApi"}); err != nil {
		t.Fatalf("a hidden syscall must stay dispatchable: %v", err)
	}
}

// The menu is a union only when there is a choice to make. One case publishes
// that case's own shape: a oneOf of one branch says nothing more, and a oneOf
// over repeated copies of one shape — cases told apart by a property the shape
// does not pin — matches every instance more than once and so admits nothing.
func TestMenuIsAUnionOnlyWhenThereIsAChoice(t *testing.T) {
	shape := []byte(`{"type":"object"}`)
	withInput := func(e Entry) Entry { e.Input = shape; return e }

	one := NewTable()
	if err := one.Add(Family{Entries: []Entry{withInput(entry("core.filesystem", "operation", "read"))}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if descriptor, _ := one.Descriptor("core.filesystem"); string(descriptor.InputSchema) != string(shape) {
		t.Fatalf("menu = %s, want the single case's own shape", descriptor.InputSchema)
	}

	shared := NewTable()
	if err := shared.Add(Family{Entries: []Entry{
		withInput(entry("core.internet", "method", "GET")),
		withInput(entry("core.internet", "method", "POST")),
	}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if descriptor, _ := shared.Descriptor("core.internet"); string(descriptor.InputSchema) != string(shape) {
		t.Fatalf("menu = %s, want one copy of the shape both cases share", descriptor.InputSchema)
	}

	distinct := NewTable()
	get := withInput(entry("core.thing", "operation", "get"))
	put := entry("core.thing", "operation", "put")
	put.Input = []byte(`{"type":"object","properties":{"value":{}}}`)
	if err := distinct.Add(Family{Entries: []Entry{get, put}}); err != nil {
		t.Fatalf("add: %v", err)
	}
	descriptor, _ := distinct.Descriptor("core.thing")
	if !bytes.Contains(descriptor.InputSchema, []byte(`"oneOf"`)) {
		t.Fatalf("menu = %s, want a union over the two distinct shapes", descriptor.InputSchema)
	}
}
