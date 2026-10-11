package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// Dispatch resolves a call to its entry, asks for approval when the call needs
// it, and runs the handler. A call the table cannot route is denied.
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
	crossing := crossingTaint(entry, TaintFrom(ctx))
	if (entry.RequireApproval || len(crossing) > 0) && auth.Decision != sys.Approved {
		return sys.Yield(approvalPrompt(entry, call, crossing)), nil
	}
	return entry.Handler.DispatchCall(ctx, call)
}

// crossingTaint is the part of the run's taint that an operation forbids: the
// data a call could carry out of the run. Such a call runs only with a human's
// approval. The approval lets this one call through. The run keeps its labels,
// so the next such call asks again.
func crossingTaint(entry Entry, taint Taint) Taint {
	crossing := Taint{}
	for _, label := range entry.Forbid {
		if sources, held := taint[label]; held {
			crossing[label] = sources
		}
	}
	return crossing
}

// approvalPromptArgsLimit caps the detail quoted in a prompt. The task's
// syscall always keeps the complete arguments.
const approvalPromptArgsLimit = 4096

// approvalSourcesShown caps the calls a prompt lists for one label.
const approvalSourcesShown = 5

// approvalPrompt is what a human is asked to approve: the operation, the data
// it could carry out of the run, and what it would run with — the entry's own
// rendering, else the arguments.
func approvalPrompt(entry Entry, call sys.Syscall, crossing Taint) string {
	prompt := fmt.Sprintf("Approve %s", entry.Key)
	if entry.Description != "" {
		prompt += ": " + entry.Description
	}
	if len(crossing) > 0 {
		// Before the call's detail, so cutting a long detail never cuts it.
		prompt += "\n" + crossingNotice(crossing)
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

// crossingNotice tells the human which labeled data the call could carry out of
// the run, and which calls produced it.
func crossingNotice(crossing Taint) string {
	labels := crossing.Labels()
	var b strings.Builder
	fmt.Fprintf(&b, "This run has read data labeled %s. This call can send that data out of the run.", strings.Join(labels, ", "))
	for _, label := range labels {
		sources := crossing[label]
		fmt.Fprintf(&b, "\n%s came from:", label)
		for _, source := range sources[:min(len(sources), approvalSourcesShown)] {
			fmt.Fprintf(&b, "\n- %s", source)
		}
		if more := len(sources) - approvalSourcesShown; more > 0 {
			fmt.Fprintf(&b, "\n- %d more calls", more)
		}
	}
	return b.String()
}
