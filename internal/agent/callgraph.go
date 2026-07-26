package agent

import (
	"context"
	"fmt"
	"sort"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/durable"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/errs"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// SessionGraphProcess is a process within a session graph: its metadata and the flat
// journal of every syscall entry ever written, across all revisions. The fork
// structure is derivable from duplicate positions with different revision
// numbers.
type SessionGraphProcess struct {
	ProcessID       string
	Input           string
	ParentProcessID string
	Status          durable.ProcessStatus
	Answer          string
	Error           string
	Attempt         int
	CurrentRevision uint64
	ChildProcessIDs []string
	Entries         []JournalEntry
}

// SessionGraph projects a whole session for exploration: its processes in order, each
// with its complete flat entry history across all revisions.
type SessionGraph struct {
	SessionID string
	Title     string
	Processes []SessionGraphProcess
}

// SessionGraph builds the execution graph of a session by reading each process's
// syscall.recorded events directly from the log, pairing intents with their
// completions per revision. The flat entry list carries per-entry revision
// numbers so the caller can reconstruct the fork graph.
func (r *Runtime) SessionGraph(sessionID string) (SessionGraph, error) {
	r.mu.Lock()
	session := r.sessions[sessionID]
	if session == nil {
		r.mu.Unlock()
		return SessionGraph{}, fmt.Errorf("%w: session %s", errs.NotFound, sessionID)
	}
	graph := SessionGraph{SessionID: session.id, Title: session.title}
	type runMeta struct {
		id, input, parentProcessID string
		status                     durable.ProcessStatus
		answer, err                string
		attempt                    int
		currentRevision            uint64
		childProcessIDs            []string
	}
	metas := make([]runMeta, 0, len(session.processIDs))
	for _, processID := range session.processIDs {
		proc := r.processes[processID]
		if proc == nil {
			continue
		}
		metas = append(metas, runMeta{
			id: proc.id, input: proc.input, parentProcessID: proc.parentProcessID,
			status: proc.status, answer: proc.answer, err: proc.err,
			attempt: proc.attempt, currentRevision: proc.revision,
			childProcessIDs: append([]string(nil), proc.childProcessIDs...),
		})
	}
	tenantID := r.tenantID
	r.mu.Unlock()

	ctx := context.Background()
	scope := eventlog.Scope{TenantID: tenantID, SessionID: sessionID}
	events, err := r.log.Read(ctx, scope, 0)
	if err != nil {
		return SessionGraph{}, err
	}

	// One folder, one pairer: rebuild every revision's journal view the same
	// way restore does, and pair intents with completions the same way the
	// single-journal read does (entries). A revision's view resolves every
	// position's writing revision, so keeping only the entries a revision
	// wrote itself unions to the all-revisions set with no duplicates —
	// abandoned branches included.
	journals, _, err := foldJournals(events, r.log, scope, r.journalNow, r.journalAppendPublisher(sessionID))
	if err != nil {
		return SessionGraph{}, err
	}

	for _, meta := range metas {
		var entries []JournalEntry
		for _, journal := range journals[meta.id] {
			all, err := journal.entries()
			if err != nil {
				return SessionGraph{}, err
			}
			for _, entry := range all {
				if entry.Revision == journal.rev {
					entries = append(entries, entry)
				}
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Position != entries[j].Position {
				return entries[i].Position < entries[j].Position
			}
			return entries[i].Revision < entries[j].Revision
		})
		graph.Processes = append(graph.Processes, SessionGraphProcess{
			ProcessID:       meta.id,
			Input:           meta.input,
			ParentProcessID: meta.parentProcessID,
			Status:          meta.status,
			Answer:          meta.answer,
			Error:           meta.err,
			Attempt:         meta.attempt,
			CurrentRevision: meta.currentRevision,
			ChildProcessIDs: meta.childProcessIDs,
			Entries:         entries,
		})
	}
	return graph, nil
}

// ProcessGraphNode is a node in the projected call graph: a process together with
// the delegated child processes it spawned, in spawn order.
type ProcessGraphNode struct {
	ProcessID       string
	Name            string
	SessionID       string
	ParentProcessID string
	Status          durable.ProcessStatus
	Attempt         int
	Revision        uint64
	Answer          string
	Error           string
	Children        []ProcessGraphNode
}

// CallGraph projects a process and its delegated child processes (recursively) into a
// tree, using the recorded parent/child links.
func (r *Runtime) CallGraph(processID string) (ProcessGraphNode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.processes[processID]; !ok {
		return ProcessGraphNode{}, fmt.Errorf("%w: process %s", errs.NotFound, processID)
	}
	return r.callGraphLocked(processID, make(map[string]bool)), nil
}

func (r *Runtime) callGraphLocked(processID string, visited map[string]bool) ProcessGraphNode {
	proc := r.processes[processID]
	if proc == nil || visited[processID] {
		return ProcessGraphNode{ProcessID: processID}
	}
	visited[processID] = true
	node := ProcessGraphNode{
		ProcessID:       proc.id,
		Name:            proc.manifest.Program,
		SessionID:       proc.sessionID,
		ParentProcessID: proc.parentProcessID,
		Status:          proc.status,
		Attempt:         proc.attempt,
		Revision:        proc.revision,
		Answer:          proc.answer,
		Error:           proc.err,
	}
	for _, childID := range proc.childProcessIDs {
		node.Children = append(node.Children, r.callGraphLocked(childID, visited))
	}
	return node
}
