package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"unicode/utf8"

	"github.com/aurora-capcompute/aurora-capcompute/capability"
	"github.com/aurora-capcompute/capcompute/sys"
)

// Flow is the information-flow monitor. It reads two things, neither of them
// durable: the labels each process has observed (its taint, rebuilt by replay
// on resume) and what each operation's results carry (the grant table).
//
// The guest is opaque, so flow is judged conservatively: every label a process
// observes taints everything it sends later. Labels only accumulate. A call
// whose operation forbids a label the run holds waits for a human's approval,
// which the routing dispatcher asks for. The approval lets that one call
// through and lifts nothing.
//
// It has two decorators, on the two sides of the replay layer. Track sits above:
// it hands the run's taint down and folds every result's labels into it, so a
// replayed result rebuilds the taint as a fresh one does. Stamp sits below:
// some labels come from the handlers themselves (which credential an internet
// fetch used, what a session's earlier runs read), so they cannot be derived
// again and are journaled with the result.
type Flow[K comparable] struct {
	taints *Taints[K]
	table  *capability.Table
}

// NewFlow binds the shared taint state to one process's grant table.
func NewFlow[K comparable](taints *Taints[K], table *capability.Table) *Flow[K] {
	return &Flow[K]{taints: taints, table: table}
}

// Track hands the run's taint to the calls below and folds each result's
// labels into it. It belongs above the replay layer.
func (f *Flow[K]) Track(next sys.Dispatcher[K]) sys.Dispatcher[K] {
	return &flowTrack[K]{flow: f, next: next}
}

// Stamp records the source classes an operation's results carry. It belongs
// below the replay layer.
func (f *Flow[K]) Stamp(next sys.Dispatcher[K]) sys.Dispatcher[K] {
	return &flowStamp[K]{flow: f, next: next}
}

type flowTrack[K comparable] struct {
	flow *Flow[K]
	next sys.Dispatcher[K]
}

// Dispatch hands the run's taint down, then folds the result's labels into it,
// with the call that produced them.
func (t *flowTrack[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit:
		return t.next.Dispatch(ctx, cred, syscall, auth)
	}

	// The routing dispatcher asks for approval when the call's operation
	// forbids a label in this taint. Handlers that store guest-derived data
	// persist the labels with the value, so provenance survives into later
	// sessions instead of being laundered.
	result, err := t.next.Dispatch(capability.WithTaint(ctx, t.flow.taints.taint(cred)), cred, syscall, auth)
	if err != nil {
		return result, err
	}
	t.flow.taints.observe(cred, result.Labels(), source(syscall))
	return result, nil
}

// sourceLimit caps how much of a call a source names. A human reads the source
// in an approval prompt, and a call's arguments can be a whole conversation.
const sourceLimit = 200

// source names a call for the human who approves a later crossing: the syscall
// and its arguments.
func source(call sys.Syscall) string {
	var args bytes.Buffer
	if err := json.Compact(&args, call.Args); err != nil || args.Len() == 0 {
		return call.Name
	}
	text := call.Name + " " + args.String()
	if len(text) <= sourceLimit {
		return text
	}
	cut := sourceLimit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}

type flowStamp[K comparable] struct {
	flow *Flow[K]
	next sys.Dispatcher[K]
}

// Dispatch stamps a result with its provenance: the syscall that produced it,
// and the source classes its operation declares.
func (s *flowStamp[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	result, err := s.next.Dispatch(ctx, cred, syscall, auth)
	if err != nil {
		return result, err
	}
	switch syscall.Name {
	case sys.SyscallBegin, sys.SyscallCommit:
		return result, nil // control syscalls carry no data provenance
	}
	labels := append([]string{capability.SyscallLabelPrefix + syscall.Name}, s.flow.table.Labels(syscall)...)
	return result.WithLabels(labels...), nil
}
