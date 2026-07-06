package agent

import (
	"context"
	"fmt"
	"sort"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// SessionGraphProcess is a process within a session graph: its metadata and the flat
// journal of every syscall entry ever written, across all revisions. The fork
// structure is derivable from duplicate positions with different revision
// numbers.
type SessionGraphProcess struct {
	ProcessID       string         `json:"process_id"`
	Message         string         `json:"message"`
	ParentProcessID string         `json:"parent_process_id,omitempty"`
	Status          ProcessStatus  `json:"status"`
	Answer          string         `json:"answer,omitempty"`
	Error           string         `json:"error,omitempty"`
	Attempt         int            `json:"attempt"`
	CurrentRevision uint64         `json:"current_revision"`
	ChildProcessIDs []string       `json:"child_process_ids,omitempty"`
	Entries         []JournalEntry `json:"entries"`
}

// SessionGraph projects a whole session for exploration: its processes in order, each
// with its complete flat entry history across all revisions.
type SessionGraph struct {
	SessionID string                `json:"session_id"`
	Title     string                `json:"title"`
	Processes []SessionGraphProcess `json:"processes"`
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
		return SessionGraph{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	graph := SessionGraph{SessionID: session.id, Title: session.title}
	type runMeta struct {
		id, message, parentProcessID string
		status                       ProcessStatus
		answer, err                  string
		attempt                      int
		currentRevision              uint64
		childProcessIDs              []string
	}
	metas := make([]runMeta, 0, len(session.processIDs))
	for _, processID := range session.processIDs {
		proc := r.processes[processID]
		if proc == nil {
			continue
		}
		metas = append(metas, runMeta{
			id: proc.id, message: proc.message, parentProcessID: proc.parentProcessID,
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
			Message:         meta.message,
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
	ProcessID       string             `json:"process_id"`
	Name            string             `json:"name,omitempty"`
	SessionID       string             `json:"session_id"`
	ParentProcessID string             `json:"parent_process_id,omitempty"`
	Status          ProcessStatus      `json:"status"`
	Attempt         int                `json:"attempt"`
	Revision        uint64             `json:"revision"`
	Answer          string             `json:"answer,omitempty"`
	Error           string             `json:"error,omitempty"`
	Children        []ProcessGraphNode `json:"children,omitempty"`
}

// CallGraph projects a process and its delegated child processes (recursively) into a
// tree, using the recorded parent/child links.
func (r *Runtime) CallGraph(processID string) (ProcessGraphNode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.processes[processID]; !ok {
		return ProcessGraphNode{}, fmt.Errorf("%w: process %s", ErrNotFound, processID)
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
		Name:            proc.manifest.Name,
		SessionID:       proc.sessionID,
		ParentProcessID: proc.parentProcessID,
		Status:          proc.status,
		Attempt:         proc.attempt,
		Revision:        proc.revision,
		Answer:          proc.answer,
		Error:           proc.err,
	}
	// Build a program→name index from the parent's agent tools as a backfill: a
	// child process with an empty Name can infer it from the parent's `core.agent`
	// tool whose program (settings.code) matches.
	childNameByProgram := make(map[string]string)
	for _, tool := range proc.manifest.agentTools() {
		if s, err := decodeAgentSettings(tool); err == nil && s.Program != "" && tool.Name != "" {
			childNameByProgram[s.Program] = tool.Name
		}
	}
	for _, childID := range proc.childProcessIDs {
		childNode := r.callGraphLocked(childID, visited)
		if childNode.Name == "" {
			if cr := r.processes[childID]; cr != nil {
				childNode.Name = childNameByProgram[cr.manifest.Program]
			}
		}
		node.Children = append(node.Children, childNode)
	}
	return node
}
