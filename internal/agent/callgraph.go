package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aurora-capcompute/capcompute/sys"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
)

// SessionGraphRun is a run within a session graph: its metadata and the flat
// journal of every syscall entry ever written, across all revisions. The fork
// structure is derivable from duplicate positions with different revision
// numbers.
type SessionGraphRun struct {
	RunID           string         `json:"run_id"`
	Message         string         `json:"message"`
	ParentRunID     string         `json:"parent_run_id,omitempty"`
	Status          RunStatus      `json:"status"`
	Answer          string         `json:"answer,omitempty"`
	Error           string         `json:"error,omitempty"`
	Attempt         int            `json:"attempt"`
	CurrentRevision uint64         `json:"current_revision"`
	ChildRunIDs     []string       `json:"child_run_ids,omitempty"`
	Entries         []JournalEntry `json:"entries"`
}

// SessionGraph projects a whole session for exploration: its runs in order, each
// with its complete flat entry history across all revisions.
type SessionGraph struct {
	SessionID string            `json:"session_id"`
	Title     string            `json:"title"`
	Runs      []SessionGraphRun `json:"runs"`
}

// SessionGraph builds the execution graph of a session by reading each run's
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
		id, message, parentRunID string
		status                   RunStatus
		answer, err              string
		attempt                  int
		currentRevision          uint64
		childRunIDs              []string
	}
	metas := make([]runMeta, 0, len(session.runIDs))
	for _, runID := range session.runIDs {
		run := r.runs[runID]
		if run == nil {
			continue
		}
		metas = append(metas, runMeta{
			id: run.id, message: run.message, parentRunID: run.parentRunID,
			status: run.status, answer: run.answer, err: run.err,
			attempt: run.attempt, currentRevision: run.revision,
			childRunIDs: append([]string(nil), run.childRunIDs...),
		})
	}
	tenantID := r.tenantID
	r.mu.Unlock()

	ctx := context.Background()
	events, err := r.log.Read(ctx, eventlog.Scope{TenantID: tenantID, SessionID: sessionID}, 0)
	if err != nil {
		return SessionGraph{}, err
	}

	// Pair each revision's intent records with their completions. Records
	// arrive in append order per revision, so a completion always follows its
	// intent within the same revision's sub-sequence.
	type entryKey struct {
		position int
		revision uint64
	}
	allEntries := map[string]map[entryKey]JournalEntry{} // run → key → entry
	openIntent := map[string]map[uint64]entryKey{}       // run → revision → open intent key

	for _, ev := range events {
		if ev.Kind != evSyscall {
			continue
		}
		var sd syscallRecordData
		if err := json.Unmarshal(ev.Data, &sd); err != nil {
			return SessionGraph{}, fmt.Errorf("decode syscall.recorded: %w", err)
		}
		if allEntries[ev.Run] == nil {
			allEntries[ev.Run] = make(map[entryKey]JournalEntry)
			openIntent[ev.Run] = make(map[uint64]entryKey)
		}
		rec := sd.Record
		if rec.Syscall != nil {
			key := entryKey{rec.Position, ev.Rev}
			allEntries[ev.Run][key] = JournalEntry{
				Position:    rec.Position,
				Revision:    ev.Rev,
				Syscall:     *rec.Syscall,
				Outcome:     JournalOutcome{Status: sys.StatusYield, Message: "in flight"},
				Compensates: rec.Compensates,
			}
			openIntent[ev.Run][ev.Rev] = key
			continue
		}
		if rec.Result != nil {
			if key, ok := openIntent[ev.Run][ev.Rev]; ok {
				entry := allEntries[ev.Run][key]
				entry.Outcome = encodeOutcome(*rec.Result)
				allEntries[ev.Run][key] = entry
				delete(openIntent[ev.Run], ev.Rev)
			}
		}
	}

	for _, meta := range metas {
		entries := make([]JournalEntry, 0, len(allEntries[meta.id]))
		for _, e := range allEntries[meta.id] {
			entries = append(entries, e)
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Position != entries[j].Position {
				return entries[i].Position < entries[j].Position
			}
			return entries[i].Revision < entries[j].Revision
		})
		graph.Runs = append(graph.Runs, SessionGraphRun{
			RunID:           meta.id,
			Message:         meta.message,
			ParentRunID:     meta.parentRunID,
			Status:          meta.status,
			Answer:          meta.answer,
			Error:           meta.err,
			Attempt:         meta.attempt,
			CurrentRevision: meta.currentRevision,
			ChildRunIDs:     meta.childRunIDs,
			Entries:         entries,
		})
	}
	return graph, nil
}

// RunGraphNode is a node in the projected call graph: a run together with the
// delegated child runs it spawned, in spawn order.
type RunGraphNode struct {
	RunID     string         `json:"run_id"`
	Name      string         `json:"name,omitempty"`
	SessionID string         `json:"session_id"`
	ParentID  string         `json:"parent_id,omitempty"`
	Status    RunStatus      `json:"status"`
	Attempt   int            `json:"attempt"`
	Revision  uint64         `json:"revision"`
	Answer    string         `json:"answer,omitempty"`
	Error     string         `json:"error,omitempty"`
	Children  []RunGraphNode `json:"children,omitempty"`
}

// CallGraph projects a run and its delegated child runs (recursively) into a
// tree, using the recorded parent/child links.
func (r *Runtime) CallGraph(runID string) (RunGraphNode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.runs[runID]; !ok {
		return RunGraphNode{}, fmt.Errorf("%w: run %s", ErrNotFound, runID)
	}
	return r.callGraphLocked(runID, make(map[string]bool)), nil
}

func (r *Runtime) callGraphLocked(runID string, visited map[string]bool) RunGraphNode {
	run := r.runs[runID]
	if run == nil || visited[runID] {
		return RunGraphNode{RunID: runID}
	}
	visited[runID] = true
	node := RunGraphNode{
		RunID:     run.id,
		Name:      run.manifest.Name,
		SessionID: run.sessionID,
		ParentID:  run.parentRunID,
		Status:    run.status,
		Attempt:   run.attempt,
		Revision:  run.revision,
		Answer:    run.answer,
		Error:     run.err,
	}
	// Build a program→name index from the parent's agent tools as a backfill: a
	// child run with an empty Name can infer it from the parent's `core.agent`
	// tool whose program (settings.code) matches.
	childNameByProgram := make(map[string]string)
	for _, tool := range run.manifest.agentTools() {
		if s, err := decodeAgentSettings(tool); err == nil && s.Program != "" && tool.Name != "" {
			childNameByProgram[s.Program] = tool.Name
		}
	}
	for _, childID := range run.childRunIDs {
		childNode := r.callGraphLocked(childID, visited)
		if childNode.Name == "" {
			if cr := r.runs[childID]; cr != nil {
				childNode.Name = childNameByProgram[cr.manifest.Program]
			}
		}
		node.Children = append(node.Children, childNode)
	}
	return node
}
