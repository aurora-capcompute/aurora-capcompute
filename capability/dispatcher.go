package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Dispatcher is the bottom of the dispatcher chain: it routes a call to the
// entry that serves it. Routing is a table lookup, and the table is the grant.
type Dispatcher[K any] struct {
	table *Table
}

func NewDispatcher[K any](table *Table) *Dispatcher[K] {
	return &Dispatcher[K]{table: table}
}

// Dispatch resolves a call to its entry, asks for approval when the entry
// requires it, and runs the handler. A call the table cannot route is denied.
func (d *Dispatcher[K]) Dispatch(ctx context.Context, _ K, call sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	entry, err := d.table.resolve(call)
	if err != nil {
		if _, bad := errors.AsType[*ArgsError](err); bad {
			return sys.FailCode(sys.ErrnoInvalidArgs, err.Error()), nil
		}
		return sys.FailCode(sys.ErrnoDenied, err.Error()), nil
	}
	// Approval is asked here, below the replay tape, so the yield and the
	// human's answer are journaled once, and no handler has to remember to ask.
	if entry.RequireApproval && auth.Decision != sys.Approved {
		return sys.Yield(approvalPrompt(entry, call)), nil
	}
	return entry.Handler.DispatchCall(ctx, call)
}

// approvalPromptArgsLimit caps the detail quoted in a prompt. The task's
// syscall always keeps the complete arguments.
const approvalPromptArgsLimit = 4096

// approvalPrompt is what a human is asked to approve: the operation, and what
// it would run with — the entry's own rendering, else the arguments.
func approvalPrompt(entry Entry, call sys.Syscall) string {
	prompt := fmt.Sprintf("Approve %s", entry.Key)
	if entry.Description != "" {
		prompt += ": " + entry.Description
	}
	var detail string
	if entry.Prompt != nil {
		detail = entry.Prompt(call)
	} else if args := compactArgs(call.Args); args != "" {
		detail = "args: " + args
	}
	if detail == "" {
		return prompt
	}
	if len(detail) > approvalPromptArgsLimit {
		cut := approvalPromptArgsLimit
		for cut > 0 && !utf8.RuneStart(detail[cut]) {
			cut--
		}
		detail = fmt.Sprintf("%s… (%d more bytes; the task's syscall holds them all)", detail[:cut], len(detail)-cut)
	}
	return prompt + "\n" + detail
}

// compactArgs renders call arguments on one line. Arguments that are not JSON
// are quoted as they came.
func compactArgs(raw json.RawMessage) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return strconv.Quote(string(raw))
	}
	return out.String()
}
