package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// agentRouter is the dispatcher for `core.agent` tools. It processes each sub-agent
// as a tracked child process of the runtime; its Dispatch forwards a syscall to
// that process and returns the child's answer (or propagates a yield for HITL). It
// sits above the task layer — a delegated child's park suspends the parent
// transparently, it never becomes a human-approvable task — and below the
// savepoint markers and replay, so delegation results are journaled effects.
type agentRouter struct {
	next     sys.Dispatcher[ProcessContext]
	children map[string]agentChild
}

type agentChild struct {
	tool     Tool
	settings AgentSettings
	runtime  *Runtime
}

type delegateArgs struct {
	Message      string `json:"message"`
	SystemPrompt string `json:"system_prompt,omitempty"`
}

type delegateResult struct {
	Answer string `json:"answer"`
}

func newAgentRouter(next sys.Dispatcher[ProcessContext], agents []Tool, runtime *Runtime) (*agentRouter, error) {
	m := make(map[string]agentChild, len(agents))
	for _, tool := range agents {
		settings, err := decodeAgentSettings(tool)
		if err != nil {
			return nil, fmt.Errorf("agent tool %q settings: %w", tool.Name, err)
		}
		m[tool.Name] = agentChild{tool: tool, settings: settings, runtime: runtime}
	}
	return &agentRouter{next: next, children: m}, nil
}

func (r *agentRouter) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if child, ok := r.children[syscall.Name]; ok {
		return child.dispatch(ctx, cred, syscall)
	}
	return r.next.Dispatch(ctx, cred, syscall, auth)
}

func (r *agentRouter) Capabilities() []sys.Capability {
	caps := r.next.Capabilities()
	for name, child := range r.children {
		caps = append(caps, agentCapability(name, child))
	}
	return caps
}

// onChildFailure applies the child's failure-mode policy. OnFailurePropagate
// forces the parent run to fail (a failed result alone only surfaces a
// recoverable observation to the program); otherwise the failure is reported to
// the parent program as a recoverable failed observation.
func (c *agentChild) onChildFailure(parentProcessID string, err error) (sys.SyscallResult, error) {
	if c.settings.OnFailure == OnFailurePropagate {
		c.runtime.requestProcessFailure(parentProcessID, fmt.Errorf("child %q failed: %w", c.tool.Name, err))
	}
	return sys.Fail(err.Error()), nil
}

func (c *agentChild) dispatch(ctx context.Context, parent ProcessContext, syscall sys.Syscall) (sys.SyscallResult, error) {
	var args delegateArgs
	if err := json.Unmarshal(syscall.Args, &args); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode delegation args: %v", err)), nil
	}

	// Deep cascade resume: when the parent process is being restarted (or re-driven
	// after a child's HITL approval), re-execution re-issues the same deterministic
	// sequence of delegation calls. Rather than spawning a fresh child each time,
	// reuse the existing child process recorded at this position (in spawn order).
	if childID, sessionID, cascadeMode, reuse, ok := c.runtime.nextCascadeChild(parent.ProcessID); ok {
		if reuse {
			// HITL reconnect: the child already finished (e.g. after its approval was
			// resolved while the parent was suspended). Reuse its terminal result
			// directly instead of re-running it, which would fork a new revision and
			// re-create the child's approval task.
			snap, err := c.runtime.GetProcess(childID)
			if err != nil {
				return sys.Fail(fmt.Sprintf("reconnect child: %v", err)), nil
			}
			answer, _, procErr := childTerminal(snap)
			if procErr != nil {
				return c.onChildFailure(parent.ProcessID, procErr)
			}
			return delegationResult(answer)
		}
		if _, err := c.runtime.Retry(childID, cascadeMode); err != nil {
			return sys.Fail(fmt.Sprintf("cascade retry child: %v", err)), nil
		}
		answer, parked, err := c.runtime.waitForCompletion(ctx, childID, sessionID)
		if err != nil {
			return c.onChildFailure(parent.ProcessID, err)
		}
		if parked {
			return sys.Yield(fmt.Sprintf("waiting on child %s", c.tool.Name)), nil
		}
		return delegationResult(answer)
	}

	childManifest := buildChildManifest(c.tool, c.settings, args.SystemPrompt)
	slog.Info("spawning child process in parent session", "parent", parent.ProcessID, "child", c.tool.Name)
	proc, err := c.runtime.createChildProcess(parent.ProcessID, parent.SessionID, args.Message, childManifest)
	if err != nil {
		return sys.Fail(fmt.Sprintf("create child process: %v", err)), nil
	}
	answer, parked, err := c.runtime.waitForCompletion(ctx, proc.ID, parent.SessionID)
	if err != nil {
		return c.onChildFailure(parent.ProcessID, err)
	}
	if parked {
		// The child parked for human approval. Yield so the parent process suspends
		// durably; the child→parent finish hook re-drives this call once the child
		// finishes, and the reconnect branch above returns its answer.
		return sys.Yield(fmt.Sprintf("waiting on child %s", c.tool.Name)), nil
	}
	return delegationResult(answer)
}

// delegationResult marshals a child's answer into the delegate result envelope.
func delegationResult(answer string) (sys.SyscallResult, error) {
	result, err := json.Marshal(delegateResult{Answer: answer})
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(result), nil
}

// buildChildManifest lifts a `core.agent` tool node into a Manifest for the child
// process: program/system_prompt come from the tool's AgentSettings, composition from
// its nested Tools.
func buildChildManifest(tool Tool, settings AgentSettings, systemPromptOverride string) Manifest {
	prompt := settings.SystemPrompt
	if systemPromptOverride != "" {
		prompt = systemPromptOverride
	}
	return Manifest{
		Version:      ManifestVersion,
		Name:         tool.Name,
		Program:      settings.Program,
		BindingRef:   settings.BindingRef,
		SystemPrompt: prompt,
		OnFailure:    settings.OnFailure,
		Tools:        cloneTools(tool.Tools),
	}
}

func agentCapability(name string, child agentChild) sys.Capability {
	var desc strings.Builder
	desc.WriteString("Delegate work to the ")
	desc.WriteString(name)
	desc.WriteString(" agent.")
	visible := make([]string, 0, len(child.tool.Tools))
	for _, t := range child.tool.Tools {
		if !t.Hidden {
			visible = append(visible, t.Name)
		}
	}
	if len(visible) > 0 {
		desc.WriteString(" It can: ")
		desc.WriteString(strings.Join(visible, ", "))
		desc.WriteString(".")
	} else {
		desc.WriteString(" Pure computation agent, no external tools.")
	}
	return sys.Capability{
		Name:        name,
		Description: desc.String(),
		InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string","description":"Task description for the child agent"},"system_prompt":{"type":"string","description":"Optional system prompt override"}},"required":["message"],"additionalProperties":false}`),
		Hidden:      child.tool.Hidden,
	}
}

// nextCascadeChild returns the next existing child to reuse when a parent process
// is being retried with cascade enabled, advancing through the parent's children
// in spawn order. It returns ok=false once cascade is off or the recorded children
// are exhausted, in which case the caller spawns a fresh child.
//
// The returned cascadeMode is the effective retry mode to use on the child:
// it mirrors the parent's cascadeMode except that completed children are always
// restarted (RetryResume is invalid for completed processes).
func (r *Runtime) nextCascadeChild(parentProcessID string) (childID, sessionID string, cascadeMode RetryMode, reuse, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	parent := r.processes[parentProcessID]
	if parent == nil || !parent.cascade || parent.cascadeCursor >= len(parent.childProcessIDs) {
		if parent != nil {
			slog.Debug("cascade skip: off or exhausted",
				"process", parentProcessID,
				"cascade", parent.cascade,
				"cursor", parent.cascadeCursor,
				"children", len(parent.childProcessIDs),
			)
		}
		return "", "", "", false, false
	}
	childID = parent.childProcessIDs[parent.cascadeCursor]
	parent.cascadeCursor++
	child := r.processes[childID]
	if child == nil {
		slog.Warn("cascade child not resident; spawning fresh",
			"parent", parentProcessID,
			"child", childID,
			"cursor", parent.cascadeCursor-1,
		)
		return "", "", "", false, false
	}
	// HITL reconnect: a parent re-driven after a child finished its approval reuses
	// the child's terminal result directly. Re-running it would fork a new revision
	// and, for a HITL child, re-create the now-resolved approval task.
	if parent.reconnectChildren && isTerminal(child.status) {
		return childID, child.sessionID, parent.cascadeMode, true, true
	}
	// A resume-mode cascade should also resume the child so only the failed step
	// gets a new revision. Completed children cannot be resumed, so fall back to
	// restart in that case.
	mode := parent.cascadeMode
	if mode == RetryResume && child.status == ProcessCompleted {
		mode = RetryRestart
	}
	return childID, child.sessionID, mode, false, true
}

func (r *Runtime) createChildProcess(parentProcessID string, sessionID string, message string, manifest Manifest) (ProcessSnapshot, error) {
	if message == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: message is required", ErrInvalid)
	}
	program, err := r.programs.Resolve(manifest.Program)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	processID, err := r.idSource("proc_")
	if err != nil {
		return ProcessSnapshot{}, err
	}
	now := r.now().UTC()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: runtime is closed", ErrConflict)
	}
	session := r.sessions[sessionID]
	if session == nil {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session %s", ErrNotFound, sessionID)
	}
	if session.activeProcessID != "" && session.activeProcessID != parentProcessID {
		r.mu.Unlock()
		return ProcessSnapshot{}, fmt.Errorf("%w: session already has active process %s", ErrConflict, session.activeProcessID)
	}
	proc := &processState{
		id:              processID,
		sessionID:       sessionID,
		message:         message,
		history:         append([]HistoryMessage(nil), session.history...),
		status:          ProcessQueued,
		attempt:         1,
		createdAt:       now,
		updatedAt:       now,
		manifest:        manifest,
		revision:        1,
		programDigest:   program.Digest,
		parentProcessID: parentProcessID,
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	r.processes[processID] = proc
	session.processIDs = append(session.processIDs, processID)
	if len(session.processIDs) == 1 {
		session.title = sessionTitle(message)
	}
	prevActiveRunID := session.activeProcessID
	session.activeProcessID = processID
	session.updatedAt = now
	if err := r.appendProcess(proc); err != nil {
		delete(r.processes, processID)
		session.processIDs = session.processIDs[:len(session.processIDs)-1]
		session.activeProcessID = prevActiveRunID
		r.mu.Unlock()
		return ProcessSnapshot{}, err
	}
	if parent := r.processes[parentProcessID]; parent != nil {
		spawnOffset := 0
		if parent.journal != nil {
			// One past the delegation intent this child was spawned under; the
			// completion is recorded once the dispatch returns.
			spawnOffset = parent.journal.Length()
		}
		parent.childProcessIDs = append(parent.childProcessIDs, processID)
		parent.childSpawnOffsets = append(parent.childSpawnOffsets, spawnOffset)
		_ = r.appendProcess(parent)
	}
	snapshot := r.processSnapshotLocked(proc)
	r.mu.Unlock()

	r.publish(sessionID, Event{Type: "process.updated", Data: snapshot})
	r.wg.Add(1)
	go r.execute(processID)
	return snapshot, nil
}

// waitForCompletion blocks until the child reaches a terminal state or parks
// awaiting its own out-of-band approval. parked=true means the caller should
// yield (suspend the parent durably) rather than treat the result as final;
// there is deliberately no timeout, since a human approval may take arbitrarily
// long. ctx cancellation (shutdown/stop) still stops the child.
func (r *Runtime) waitForCompletion(ctx context.Context, processID, sessionID string) (answer string, parked bool, err error) {
	_, events, unsubscribe, err := r.Subscribe(sessionID)
	if err != nil {
		return "", false, fmt.Errorf("subscribe to child session: %w", err)
	}
	defer unsubscribe()

	if snapshot, err := r.GetProcess(processID); err == nil {
		if ans, done, procErr := childTerminal(snapshot); done {
			return ans, false, procErr
		}
		if childParked(snapshot) {
			return "", true, nil
		}
	}

	for {
		select {
		case <-ctx.Done():
			_, _ = r.Stop(processID)
			return "", false, ctx.Err()
		case event, ok := <-events:
			if !ok {
				return "", false, fmt.Errorf("child event stream closed")
			}
			if event.Type != "process.updated" {
				continue
			}
			snapshot, ok := event.Data.(ProcessSnapshot)
			if !ok || snapshot.ID != processID {
				continue
			}
			if ans, done, procErr := childTerminal(snapshot); done {
				return ans, false, procErr
			}
			if childParked(snapshot) {
				return "", true, nil
			}
		}
	}
}

// childTerminal reports whether a child process snapshot has reached a terminal state,
// returning its answer (on completion) or the corresponding error. done is false
// while the process is still in flight.
func childTerminal(snapshot ProcessSnapshot) (answer string, done bool, err error) {
	switch snapshot.Status {
	case ProcessCompleted:
		return snapshot.Answer, true, nil
	case ProcessFailed:
		return "", true, fmt.Errorf("child process failed: %s", snapshot.Error)
	case ProcessStopped:
		return "", true, fmt.Errorf("child process stopped")
	case ProcessInterrupted:
		return "", true, fmt.Errorf("child process interrupted")
	case ProcessCompensated:
		return "", true, fmt.Errorf("child process rolled back: %s", snapshot.Answer)
	default:
		return "", false, nil
	}
}

// childParked reports whether a child process is durably suspended awaiting out-of-band
// resolution (its own HITL approval) rather than terminal or still in flight.
func childParked(s ProcessSnapshot) bool {
	return s.Status == ProcessWaitingTask || s.Status == ProcessYielded
}

// resumeParentIfWaiting re-drives a parent that suspended on a delegated child's
// HITL approval, once that child has reached a terminal state. It is a no-op when
// the parent is not parked — e.g. a parent still actively blocked in a synchronous
// delegation call observes the child's completion through its own subscription.
// The parent is re-driven by replay (reconnectChildren) so the un-committed
// delegation intent re-executes and reconnects to the finished child.
func (r *Runtime) resumeParentIfWaiting(parentProcessID string) {
	r.mu.Lock()
	parent := r.processes[parentProcessID]
	resumable := parent != nil && (parent.status == ProcessYielded || parent.status == ProcessWaitingTask)
	if resumable {
		parent.reconnectChildren = true
	}
	r.mu.Unlock()
	if !resumable {
		return
	}
	if _, err := r.Retry(parentProcessID, RetryResume); err != nil {
		slog.Warn("resume parent on child completion failed", "parent", parentProcessID, "err", err)
	}
}

// isTerminal reports whether a process status is a final state (no further execution).
func isTerminal(status ProcessStatus) bool {
	switch status {
	case ProcessCompleted, ProcessFailed, ProcessStopped, ProcessInterrupted, ProcessCompensated:
		return true
	default:
		return false
	}
}
