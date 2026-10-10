// Package capability is the runtime's capability vocabulary: a flat index of
// every operation a process may reach, keyed by (syscall, operation).
//
// capcompute/sys says what a syscall is. This package says what a syscall
// means: its cases, how a call names its case, which labels its results carry,
// which labels may not flow into it, and what performs it.
//
// One Table answers all of those questions. The routing dispatcher below the
// journal and the flow monitor above it resolve a call through the same Table,
// so a call cannot be one case to the monitor and another case to the handler.
//
// The files: capability.go is the vocabulary (Key, Entry, Family, Descriptor),
// table.go the index and its queries, dispatcher.go the routing dispatcher and
// the approval gate, labels.go the label rules, context.go the taint handoff.
package capability

import (
	"context"
	"encoding/json"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Key names one operation of one syscall. Operation is empty for a syscall
// that is a single operation.
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

// Handler performs one operation's effect. The table resolved the call and the
// entry's policy held, approval included, before a handler runs: a handler
// never routes and never authorizes.
type Handler interface {
	DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error)
}

// HandlerFunc lets a function serve an entry.
type HandlerFunc func(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error)

func (f HandlerFunc) DispatchCall(ctx context.Context, call sys.Syscall) (sys.SyscallResult, error) {
	return f(ctx, call)
}

// Entry is one dispatchable operation: its key, the shape of its arguments,
// its own policy, and its handler.
//
// Policy belongs to the entry, not the handler: one handler may serve several
// entries with different policy (one internet client serves a labelled GET and
// a forbidding POST), and the monitor above the journal sees entries only.
type Entry struct {
	Key Key
	// Discriminator names the argument property that holds Key.Operation, for
	// example "operation" or "method". It is empty for a single-operation
	// syscall. The value the guest sent is matched exactly.
	Discriminator string
	Description   string
	// Input is the JSON Schema of this operation's arguments.
	Input json.RawMessage
	// Labels are the source classes this operation's results carry. Forbid are
	// the labels that may not flow into its arguments. The flow monitor enforces
	// both. A bar that covers a whole syscall is written on each of its entries.
	Labels []string
	Forbid []string
	// RequireApproval parks the call until a human resolves it.
	RequireApproval bool
	// Prompt renders a call for the human who approves it, when the arguments
	// alone do not show what will run. Nil quotes the arguments.
	Prompt  func(sys.Syscall) string
	Handler Handler
}

// Family is what one driver contributes for one syscall: its entries and the
// text that introduces them. The table derives the syscall's schema from the
// entries (see menuSchema), so a family carries no schema of its own.
type Family struct {
	Description string
	Entries     []Entry
}

// Descriptor is a syscall as the guest and the Validator see it: its name, what
// it does, and the schema its arguments must match. The table builds every
// descriptor, from a Family or from a Reserve.
type Descriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	// Hidden keeps a syscall dispatchable but off the guest's tool menu, for
	// example the LLM call a program makes by a name it already knows.
	Hidden bool `json:"hidden,omitempty"`
}
