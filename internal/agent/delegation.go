package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// spawnRouter serves the spawn syscall. The manifest's core.spawn grant
// lists the only programs this process may spawn — each a full manifest of
// its own, the recursive grant tree — and dispatching `spawn` starts the
// requested program as a tracked child process, forwards the input, and
// returns the child's answer (or propagates a yield for HITL). It sits above
// the task layer — a spawned child's park suspends the parent transparently,
// it never becomes a human-approvable task — and below the savepoint markers
// and replay, so spawn results are journaled effects.
type spawnRouter struct {
	next     sys.Dispatcher[ProcessContext]
	programs []Manifest
	hidden   bool
	runtime  *Runtime
}

type spawnArgs struct {
	Program string          `json:"program"`
	Input   json.RawMessage `json:"input"`
}

type spawnResult struct {
	Answer string `json:"answer"`
}

func newSpawnRouter(next sys.Dispatcher[ProcessContext], grant Syscall, runtime *Runtime) *spawnRouter {
	return &spawnRouter{
		next:     next,
		programs: grant.Programs,
		hidden:   grant.Hidden,
		runtime:  runtime,
	}
}

func (r *spawnRouter) Dispatch(ctx context.Context, cred ProcessContext, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != SpawnSyscall {
		return r.next.Dispatch(ctx, cred, syscall, auth)
	}
	var args spawnArgs
	if err := json.Unmarshal(syscall.Args, &args); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode spawn args: %v", err)), nil
	}
	spec, ok := r.program(args.Program)
	if !ok {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf(
			"spawn: program %q is not granted (granted: %s)", args.Program, strings.Join(r.programNames(), ", "))), nil
	}
	// The spawn ADT types `input` per the child's declared input schema; collapse
	// it to the canonical process-input string (the inverse of the string-first
	// rule) before validating and spawning.
	input, err := spawnInputToString(args.Input)
	if err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("spawn: %v", err)), nil
	}
	if strings.TrimSpace(input) == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "spawn: an input is required"), nil
	}
	// Validate the input against the child program's declared input schema
	// before spawning — a mismatch is a recoverable observation the parent can
	// correct, not a born-invalid child.
	if err := r.runtime.programs.ValidateInput(args.Program, input); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("spawn: %v", err)), nil
	}
	return r.spawn(ctx, cred, spec, input)
}

// spawnInputToString collapses the typed spawn `input` value into the canonical
// process-input string — the inverse of the string-first rule (validateText in
// program.go): a JSON string input carries its plain text; any other JSON value
// carries its compact text, which the child re-parses under the same rule.
func spawnInputToString(input json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("an input is required")
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return "", fmt.Errorf("decode input string: %w", err)
		}
		return text, nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, trimmed); err != nil {
		return "", fmt.Errorf("invalid input JSON: %w", err)
	}
	return buf.String(), nil
}

func (r *spawnRouter) program(name string) (Manifest, bool) {
	for _, spec := range r.programs {
		if spec.Program == name {
			return spec, true
		}
	}
	return Manifest{}, false
}

func (r *spawnRouter) programNames() []string {
	names := make([]string, 0, len(r.programs))
	for _, spec := range r.programs {
		names = append(names, spec.Program)
	}
	return names
}

func (r *spawnRouter) Capabilities() []sys.Capability {
	return append(r.next.Capabilities(), r.capability())
}

// capability publishes the spawn menu as a typed ADT: for each granted program,
// what it does (its bundled description), what it can use (its visible grants),
// and the shape of the input it expects and the answer it returns (its interface
// schemas). The arg schema is a oneOf over the programs — each branch pins
// `program` to a const and types `input` with that program's declared input
// schema — so a well-formed call names a granted program and carries an input
// matching it. (The kernel Validator enforces this schema before dispatch.)
func (r *spawnRouter) capability() sys.Capability {
	var desc strings.Builder
	desc.WriteString("Spawn a child process running one of the granted programs and wait for its answer. Programs:")
	branches := make([]json.RawMessage, 0, len(r.programs))
	for i, spec := range r.programs {
		if i > 0 {
			desc.WriteString(";")
		}
		desc.WriteString("\n- " + spec.Program)
		iface, known := r.runtime.programs.Interface(spec.Program)
		if known && iface.Description != "" {
			desc.WriteString(": " + iface.Description)
		}
		if grants := visibleGrantNames(spec); len(grants) > 0 {
			desc.WriteString(" [can use: " + strings.Join(grants, ", ") + "]")
		} else {
			desc.WriteString(" [pure computation]")
		}
		// This program's declared input schema types its `input` branch; a
		// not-yet-loaded program falls back to a permissive schema (Dispatch
		// then fails cleanly with "program is not registered").
		inputSchema := json.RawMessage(`{}`)
		if known {
			desc.WriteString(" input=" + compactSchema(iface.Input) + " output=" + compactSchema(iface.Output))
			if len(iface.Input) > 0 {
				inputSchema = iface.Input
			}
		}
		branches = append(branches, spawnBranchSchema(spec.Program, inputSchema))
	}
	desc.WriteString("\nCall {\"program\":\"<name>\",\"input\":<value>} where input matches the chosen program's declared input schema: a JSON string for a string schema, a JSON document for a structured one.")
	return sys.Capability{
		Name:        SpawnSyscall,
		Description: desc.String(),
		InputSchema: spawnADTSchema(branches),
		Hidden:      r.hidden,
	}
}

// spawnBranchSchema is one oneOf branch of the spawn ADT: the program pinned to
// a const and `input` typed by that program's declared input schema, embedded
// verbatim (it is already independently schema-compilable, which the kernel
// Validator requires).
func spawnBranchSchema(program string, inputSchema json.RawMessage) json.RawMessage {
	programConst, _ := json.Marshal(program)
	return json.RawMessage(fmt.Sprintf(
		`{"type":"object","properties":{"program":{"const":%s},"input":%s},"required":["program","input"],"additionalProperties":false}`,
		programConst, inputSchema))
}

// spawnADTSchema wraps the per-program branches in a discriminated oneOf — the
// input schema the guest is shown and the kernel Validator enforces.
func spawnADTSchema(branches []json.RawMessage) json.RawMessage {
	arr, _ := json.Marshal(branches)
	return json.RawMessage(fmt.Sprintf(`{"oneOf":%s}`, arr))
}

// compactSchema renders an interface schema for the spawn menu, collapsing
// insignificant whitespace. An unknown or empty schema renders as "any".
func compactSchema(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "any"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// visibleGrantNames summarizes a spawnable program's non-hidden grants for
// the spawn menu.
func visibleGrantNames(spec Manifest) []string {
	out := make([]string, 0, len(spec.Syscalls))
	for _, grant := range spec.Syscalls {
		if !grant.Hidden {
			out = append(out, grant.Syscall)
		}
	}
	return out
}

func (r *spawnRouter) spawn(ctx context.Context, parent ProcessContext, spec Manifest, input string) (sys.SyscallResult, error) {
	// Deep cascade resume: when the parent process is being restarted (or
	// re-driven after a child's HITL approval), re-execution re-issues the
	// same deterministic sequence of spawn calls. Rather than spawning a
	// fresh child each time, reuse the existing child process recorded at
	// this position (in spawn order).
	if childID, sessionID, cascadeMode, reuse, ok := r.runtime.nextCascadeChild(parent.ProcessID); ok {
		if reuse {
			// HITL reconnect: the child already finished (e.g. after its approval was
			// resolved while the parent was suspended). Reuse its terminal result
			// directly instead of re-running it, which would fork a new revision and
			// re-create the child's approval task.
			snap, err := r.runtime.GetProcess(childID)
			if err != nil {
				return sys.Fail(fmt.Sprintf("reconnect child: %v", err)), nil
			}
			answer, _, procErr := childTerminal(snap)
			if procErr != nil {
				return sys.Fail(procErr.Error()), nil
			}
			return spawnAnswer(answer)
		}
		if _, err := r.runtime.Retry(childID, cascadeMode); err != nil {
			return sys.Fail(fmt.Sprintf("cascade retry child: %v", err)), nil
		}
		answer, parked, err := r.runtime.waitForCompletion(ctx, childID, sessionID)
		if err != nil {
			return sys.Fail(err.Error()), nil
		}
		if parked {
			return sys.Yield(fmt.Sprintf("waiting on child %s", spec.Program)), nil
		}
		return spawnAnswer(answer)
	}

	// History and capability sharing are the child program's own settings now.
	childManifest := buildChildManifest(spec, spec.sharesCapabilities())
	slog.Info("spawning child process in parent session", "parent", parent.ProcessID, "child", spec.Program)
	proc, err := r.runtime.createChildProcess(parent.ProcessID, parent.SessionID, input, childManifest, spec.sharesHistory())
	if err != nil {
		return sys.Fail(fmt.Sprintf("create child process: %v", err)), nil
	}
	answer, parked, err := r.runtime.waitForCompletion(ctx, proc.ID, parent.SessionID)
	if err != nil {
		return sys.Fail(err.Error()), nil
	}
	if parked {
		// The child parked for human approval. Yield so the parent process suspends
		// durably; the child→parent finish hook re-drives this call once the child
		// finishes, and the reconnect branch above returns its answer.
		return sys.Yield(fmt.Sprintf("waiting on child %s", spec.Program)), nil
	}
	return spawnAnswer(answer)
}

// spawnAnswer marshals a child's answer into the spawn result envelope.
func spawnAnswer(answer string) (sys.SyscallResult, error) {
	result, err := json.Marshal(spawnResult{Answer: answer})
	if err != nil {
		return sys.SyscallResult{}, err
	}
	return sys.Result(result), nil
}

// buildChildManifest turns a spawnable program's manifest into the child's
// own: a clone with the version filled in (the root's governs the tree). The
// embedded manifest is a 1-level projection — a complete manifest for that
// program. When the sys.spawn grant withholds the capability menu
// (Capabilities:false), every grant is hidden so the child's sys.input
// advertises no tools; the grants stay dispatchable, just off the menu.
func buildChildManifest(spec Manifest, shareCapabilities bool) Manifest {
	child := cloneManifest(spec)
	child.Version = ManifestVersion
	if !shareCapabilities {
		for i := range child.Syscalls {
			child.Syscalls[i].Hidden = true
		}
	}
	return child
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

func (r *Runtime) createChildProcess(parentProcessID string, sessionID string, input string, manifest Manifest, shareHistory bool) (ProcessSnapshot, error) {
	if input == "" {
		return ProcessSnapshot{}, fmt.Errorf("%w: input is required", ErrInvalid)
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
		input:           input,
		history:         append([]HistoryMessage(nil), session.history...),
		status:          ProcessQueued,
		attempt:         1,
		createdAt:       now,
		updatedAt:       now,
		manifest:        manifest,
		revision:        1,
		programDigest:   program.Digest,
		parentProcessID: parentProcessID,
		hideHistory:     !shareHistory,
	}
	proc.journal = r.newJournal(proc, newProcessHistory(), 0)
	r.processes[processID] = proc
	// The parent is already in session.processIDs (it is the active process that
	// spawned this child), so the child is never the session's first process and
	// never sets its title — a child's input is a delegated sub-task, not the
	// session's headline.
	session.processIDs = append(session.processIDs, processID)
	prevActiveProcessID := session.activeProcessID
	session.activeProcessID = processID
	session.updatedAt = now
	if err := r.appendProcess(proc); err != nil {
		delete(r.processes, processID)
		session.processIDs = session.processIDs[:len(session.processIDs)-1]
		session.activeProcessID = prevActiveProcessID
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
