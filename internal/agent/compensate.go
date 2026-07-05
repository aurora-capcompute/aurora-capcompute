package agent

// Rolling a critical section back. A guest registers an effect's undo with
// sys.compensate — a deferred syscall journaled with concrete guest-supplied
// args, never executed on the spot — and ends the section with sys.abort
// instead of sys.commit when the work must be undone. The runtime then executes
// the registered compensations newest-first (each journaled as a compensation
// intent/completion pair with an idempotency key, so a crash mid-rollback
// resumes the rollback), and applies the abort's retry policy: fork the journal
// at the section's begin and re-run it after the declared delay, or finish the
// process as compensated. The whole story — registrations, abort, executed
// compensations — lives in the journal, in order.
//
// Scope is positional: an abort rolls back everything registered since the
// outermost-open sys.begin (committed inner sections included — a section
// inside a failed section failed with it), or since the beginning of the
// process when no section is open. This is the deliberate, backward counterpart
// of the automatic forward crash-resume: a host failure re-drives a process;
// sys.abort undoes it.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

const (
	// abortRetryCall is the syscall shape of the host-authored retry task. It
	// matches the timer driver's contract, so the distribution's existing timer
	// service arms and fires abort retries with no special handling.
	abortRetryCall = "timer.set"
	// maxAbortRetryDelay caps a guest-supplied retry delay.
	maxAbortRetryDelay = 24 * time.Hour
	// defaultMaxAbortRetries bounds how many times a process may abort-and-retry
	// before the runtime stops it — the guard against a guest that aborts forever.
	defaultMaxAbortRetries = 10
)

// compensationRegistration is one guest-registered undo: the deferred call
// recorded by a sys.compensate at Position.
type compensationRegistration struct {
	Position int
	Name     string
	Args     json.RawMessage
}

// abortState is the journal's view of a terminal sys.abort: the abort itself,
// the rollback scope, and how far the rollback has progressed.
type abortState struct {
	Position     int // the sys.abort intent's journal position
	Reason       string
	RetrySeconds *int64
	// Cause is who ended the section: empty for the guest's own sys.abort
	// (whose retry policy then applies), abortCauseFailure or abortCauseStop
	// for a host-authored abort (which settles into failed or stopped).
	Cause string
	// ScopeStart is where the rollback scope begins and where a retry forks:
	// one past the open section's sys.begin, or 0 with no section open.
	ScopeStart int
	// Registrations are the in-scope deferred undos, in registration order.
	Registrations []compensationRegistration
	// Compensated holds registration positions whose compensation has begun.
	Compensated map[int]bool
	// Resume is an open compensation intent left by a crash mid-rollback; it
	// must be re-dispatched under its original idempotency key first.
	Resume *journaled.OpenCompensation
}

// settled reports whether the rollback has fully run: no compensation is open
// and every in-scope registration has been compensated.
func (a *abortState) settled() bool {
	if a.Resume != nil {
		return false
	}
	for _, reg := range a.Registrations {
		if !a.Compensated[reg.Position] {
			return false
		}
	}
	return true
}

// abortTail reads the journal's abort state: it exists when the last lifecycle
// call is a completed sys.abort, followed only by compensation records. A
// journal still mid-run (or one whose tail is a normal completion) has none.
func (j *logJournal) abortTail() (*abortState, bool) {
	length := j.Length()
	abortPos := -1
	compensated := map[int]bool{}
	for i := 0; i < length; i++ {
		rec, err := j.Load(i)
		if err != nil {
			return nil, false
		}
		switch rec.Kind {
		case journaled.KindIntent:
			if rec.Syscall == nil {
				return nil, false
			}
			// Only the journal's last word rolls back: any later call abandons
			// a previous abort. And an abort counts only once its completion
			// succeeded — a rejected one (a guest forging the host's cause
			// field) is an ordinary failed call, never a rollback trigger.
			abortPos = -1
			if rec.Syscall.Name == callSysAbort && i+1 < length {
				next, err := j.Load(i + 1)
				if err != nil {
					return nil, false
				}
				if next.Kind == journaled.KindCompletion && next.Result != nil &&
					next.Result.Status() == sys.StatusResult {
					abortPos = i
				}
			}
		case journaled.KindCompensationIntent:
			// A registration counts as compensated only when its inverse
			// completed successfully: a failed inverse stays outstanding (a
			// later settle re-attempts it) and an open one resumes under its
			// original idempotency key via the compensator.
			if rec.Compensates == nil || i+1 >= length {
				continue
			}
			next, err := j.Load(i + 1)
			if err != nil {
				return nil, false
			}
			if next.Kind == journaled.KindCompensationCompletion && next.Result != nil &&
				next.Result.Status() == sys.StatusResult {
				compensated[*rec.Compensates] = true
			}
		}
	}
	if abortPos < 0 {
		return nil, false
	}

	abortIntent, err := j.Load(abortPos)
	if err != nil || abortIntent.Syscall == nil {
		return nil, false
	}
	var args abortArgs
	_ = json.Unmarshal(abortIntent.Syscall.Args, &args)

	state := &abortState{
		Position:     abortPos,
		Reason:       args.Reason,
		RetrySeconds: args.RetrySeconds,
		Cause:        args.Cause,
		Compensated:  compensated,
	}
	if off, ok := j.outermostOpenBegin(); ok {
		state.ScopeStart = off
	}
	for i := state.ScopeStart; i < abortPos; i++ {
		rec, err := j.Load(i)
		if err != nil {
			return nil, false
		}
		if rec.Kind != journaled.KindIntent || rec.Syscall == nil || rec.Syscall.Name != callSysCompensate {
			continue
		}
		if i+1 >= abortPos {
			continue
		}
		next, err := j.Load(i + 1)
		if err != nil || next.Kind != journaled.KindCompletion || next.Result == nil ||
			next.Result.Status() != sys.StatusResult {
			continue // a rejected registration never armed
		}
		var reg compensateArgs
		if json.Unmarshal(rec.Syscall.Args, &reg) != nil {
			continue
		}
		state.Registrations = append(state.Registrations, compensationRegistration{
			Position: rec.Position,
			Name:     reg.Name,
			Args:     reg.Args,
		})
	}
	return state, true
}

// hasAbortTail reports whether a process's journal ends in a sys.abort — the
// completion path's cheap dispatch test.
func (r *Runtime) hasAbortTail(processID string) bool {
	r.mu.Lock()
	proc := r.processes[processID]
	var journal *logJournal
	if proc != nil {
		journal = proc.journal
	}
	r.mu.Unlock()
	if journal == nil {
		return false
	}
	_, ok := journal.abortTail()
	return ok
}

// beginHostAbort prepares a host-initiated rollback and reports whether one is
// due: true means the process's journal holds an open critical section and now
// ends in a completed abort — either the one just appended (carrying the cause
// and reason) or one already there (a guest abort this transition raced, whose
// own policy then wins). False means nothing partial is at stake: no open
// section, or the abort record could not be made durable — in which case the
// process finishes plainly and a later retry re-drives the section instead.
func (r *Runtime) beginHostAbort(processID, cause, reason string) bool {
	r.mu.Lock()
	proc := r.processes[processID]
	var journal *logJournal
	if proc != nil {
		journal = proc.journal
	}
	r.mu.Unlock()
	if journal == nil {
		return false
	}
	if _, open := journal.outermostOpenBegin(); !open {
		return false
	}
	if _, aborted := journal.abortTail(); aborted {
		return true
	}
	args, err := json.Marshal(abortArgs{Reason: reason, Cause: cause})
	if err == nil {
		err = journaled.Abort(journal, args)
	}
	if err != nil {
		slog.Warn("append host abort record; finishing without rollback",
			"process_id", processID, "cause", cause, "error", err)
		return false
	}
	return true
}

// failProcess finishes a failing process. A failure inside an open critical
// section is an implicit abort: the section can never commit, so the runtime
// closes it exactly as sys.abort would — the abort record journaled with cause
// "failure", the registered compensations run newest-first — before the
// process reports failed. Every crash window resumes from the journal, and a
// later retry forks at the section's begin over rolled-back state instead of
// orphaning a half-executed attempt. Without an open section the failure is
// terminal as-is: nothing partial is awaiting a commit that will never come.
func (r *Runtime) failProcess(processID string, failure error) {
	if failure == nil {
		failure = errors.New("process failed")
	}
	if r.beginHostAbort(processID, abortCauseFailure, failure.Error()) {
		r.settleAbort(processID)
		return
	}
	r.finish(processID, ProcessFailed, "", failure)
}

// stopProcess finishes a stopped process, first rolling back its open critical
// section — a stop is an abort without a retry. When the stop raced the
// guest's own sys.abort (the quantum was killed right after the abort was
// journaled), the guest's record is already the journal's last word and its
// policy wins: the stop dissolves into the guest's rollback.
func (r *Runtime) stopProcess(processID string, cause error) {
	if r.beginHostAbort(processID, abortCauseStop, "stopped") {
		r.settleAbort(processID)
		return
	}
	r.finish(processID, ProcessStopped, "", cause)
}

// errRollbackParked marks a rollback suspended on a human: an inverse yielded,
// its durable task is pending, and the open compensation intent at the journal
// tail is the park. Resolving the task resumes settlement.
var errRollbackParked = errors.New("rollback parked on an external task")

// settleAbort drives an aborted process to its post-rollback state: it executes
// the remaining registered compensations newest-first (resuming any compensation
// a crash left open, under its original idempotency key), then applies the
// abort's retry policy — re-run the section now, park on a durable retry timer,
// or finish as compensated. Inverses dispatch through the task layer, so an
// undo that needs sign-off yields into a durable task like any forward call:
// the rollback parks, the human is the terminal compensator inside it, and the
// resolution resumes settlement (approved executes the inverse; denied fails
// the rollback). A compensation that fails semantically stops the rollback and
// fails the process with the rollback report: the remaining undos need a
// human, and the journal is the remediation map. settleAbort is idempotent —
// every step is journaled before it executes, so calling it again (after a
// crash, a resolution, or a manual retry of a failed rollback) continues where
// the last attempt stopped.
func (r *Runtime) settleAbort(processID string) {
	r.mu.Lock()
	proc := r.processes[processID]
	var cred ProcessContext
	var journal *logJournal
	if proc != nil {
		cred = r.processContextLocked(proc)
		journal = proc.journal
	}
	r.mu.Unlock()
	if proc == nil || journal == nil {
		r.finish(processID, ProcessFailed, "", errors.New("rollback: process journal is unavailable"))
		return
	}
	state, ok := journal.abortTail()
	if !ok {
		r.finish(processID, ProcessFailed, "", errors.New("rollback: journal does not end in sys.abort"))
		return
	}

	ctx := context.Background()
	drivers, err := r.processDrivers(ctx, cred)
	if err != nil {
		r.finish(processID, ProcessFailed, "", fmt.Errorf("rollback: %w", err))
		return
	}
	// The task layer over the same journal: a yielding inverse becomes a
	// durable task whose identity is the open compensation intent at the tail —
	// the same position trick forward calls use, so approval composes for free.
	chain := &task.Dispatcher[ProcessContext]{
		Next:        drivers,
		Store:       r.tasks,
		Journal:     journal,
		Scope:       ProcessContext.taskScope,
		TokenSecret: append([]byte(nil), r.taskSecret...),
		TaskTTL:     r.taskTTL,
		OnTaskCreated: func(record task.Record) {
			r.publish(record.Scope.SessionID, Event{Type: "task.created", Data: r.taskSnapshot(record)})
		},
	}
	compensator, err := journaled.NewCompensator(journal)
	if err != nil {
		r.finish(processID, ProcessFailed, "", fmt.Errorf("rollback: %w", err))
		return
	}
	// Effects arms the compensator's pending state and surfaces a compensation
	// a crash left open; the effect list itself is unused — the rollback plan is
	// the guest's registrations, not the executed effects.
	_, resume, err := compensator.Effects(0)
	if err != nil {
		r.finish(processID, ProcessFailed, "", fmt.Errorf("rollback: %w", err))
		return
	}
	state.Resume = resume

	var undone []string
	dispatchInverse := func(inverse sys.Syscall, key string) error {
		result, err := chain.Dispatch(sys.WithIdempotencyKey(ctx, key), cred, inverse, sys.Authorization{})
		if err != nil {
			// Infrastructure error: the intent stays open in the journal; a
			// later settle resumes it under the same idempotency key.
			return fmt.Errorf("%s: %w", inverse.Name, err)
		}
		if result.Status() == sys.StatusYield {
			// The inverse needs a human: its durable task is pending and the
			// compensation intent stays open — the park. Do not commit.
			return errRollbackParked
		}
		if commitErr := compensator.Commit(result); commitErr != nil {
			return fmt.Errorf("%s: record compensation: %w", inverse.Name, commitErr)
		}
		if result.Status() != sys.StatusResult {
			return fmt.Errorf("%s: %s", inverse.Name, result.Message())
		}
		undone = append(undone, inverse.Name)
		return nil
	}
	settleStopped := func(err error) {
		if errors.Is(err, errRollbackParked) {
			r.finish(processID, ProcessWaitingTask, "", nil)
			return
		}
		r.finish(processID, ProcessFailed, rollbackReport(state, undone), fmt.Errorf("rollback stopped: %w", err))
	}

	if state.Resume != nil {
		if err := dispatchInverse(state.Resume.Syscall, state.Resume.Key); err != nil {
			settleStopped(err)
			return
		}
		state.Compensated[state.Resume.Compensates] = true
	}
	for i := len(state.Registrations) - 1; i >= 0; i-- {
		reg := state.Registrations[i]
		if state.Compensated[reg.Position] {
			continue
		}
		inverse := sys.Syscall{Abi: sys.ABIVersion, Name: reg.Name, Args: reg.Args}
		key, err := compensator.Begin(inverse, reg.Position)
		if err != nil {
			settleStopped(err)
			return
		}
		if err := dispatchInverse(inverse, key); err != nil {
			settleStopped(err)
			return
		}
	}

	report := rollbackReport(state, undone)
	switch state.Cause {
	case abortCauseFailure:
		// The host aborted the section because the guest failed: the rollback
		// is done, the failure stands. The reason carried the original error
		// across every crash window; a later retry re-runs the section fresh.
		r.finish(processID, ProcessFailed, report, errors.New(state.Reason))
		return
	case abortCauseStop:
		r.finish(processID, ProcessStopped, report, context.Canceled)
		return
	}
	if state.RetrySeconds == nil {
		r.finish(processID, ProcessCompensated, report, nil)
		return
	}
	r.mu.Lock()
	attempt := 0
	if p := r.processes[processID]; p != nil {
		attempt = p.attempt
	}
	limit := r.maxAbortRetries
	r.mu.Unlock()
	if attempt >= limit {
		r.finish(processID, ProcessCompensated, report,
			fmt.Errorf("abort retry budget exhausted after %d attempts", attempt))
		return
	}
	delay := time.Duration(*state.RetrySeconds) * time.Second
	if delay < 0 {
		delay = 0
	}
	if delay > maxAbortRetryDelay {
		delay = maxAbortRetryDelay
	}
	if delay == 0 {
		r.retrySection(processID, state.ScopeStart)
		return
	}
	if err := r.parkForRetry(ctx, cred, state, delay); err != nil {
		r.finish(processID, ProcessFailed, report, fmt.Errorf("schedule abort retry: %w", err))
		return
	}
	r.finish(processID, ProcessWaitingTask, "", nil)
}

// retrySection re-runs an aborted process from its section's begin: the journal
// forks there as a new revision (the rolled-back attempt stays in the log as a
// closed, audited transaction) and the section re-executes fresh.
func (r *Runtime) retrySection(processID string, forkOffset int) {
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return
	}
	r.forkJournalLocked(proc, forkOffset, RetryResume)
	if _, err := r.relaunchLocked(proc); err != nil {
		slog.Warn("abort retry relaunch", "process_id", processID, "error", err)
	}
}

// parkForRetry authors the durable retry timer: a pending timer.set task whose
// fire time is the rollback plus the abort's delay. The distribution's timer
// service arms and fires it like any timer task — restart-safe for free — and
// its resolution resumes the process, which then re-runs the aborted section.
func (r *Runtime) parkForRetry(ctx context.Context, cred ProcessContext, state *abortState, delay time.Duration) error {
	taskID, err := r.idSource("task_")
	if err != nil {
		return err
	}
	args, err := json.Marshal(map[string]any{
		"duration_seconds": int64(delay / time.Second),
		"label":            "abort retry",
	})
	if err != nil {
		return err
	}
	now := r.now().UTC()
	expires := now.Add(delay + r.taskTTL)
	record := task.Record{
		Scope:           cred.taskScope(),
		ID:              taskID,
		JournalPosition: state.Position,
		Syscall:         sys.Syscall{Abi: sys.ABIVersion, Name: abortRetryCall, Args: args},
		Summary:         summaryFor(state.Reason),
		State:           task.StatePending,
		CreatedAt:       now,
		ExpiresAt:       &expires,
	}
	token := task.Token(r.taskSecret, cred.TenantID, record.ID)
	sum := sha256.Sum256([]byte(token))
	record.TokenHash = sum[:]
	if err := r.tasks.Create(ctx, record); err != nil {
		return err
	}
	r.publish(cred.SessionID, Event{Type: "task.created", Data: r.taskSnapshot(record)})
	return nil
}

func summaryFor(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "abort retry"
	}
	return "abort retry: " + reason
}

// rollbackReport renders what the rollback did — the abort reason, the undos
// that ran, and any registrations still outstanding. It is the compensated
// process's answer and a failed rollback's remediation map.
func rollbackReport(state *abortState, undone []string) string {
	var remaining []string
	for _, reg := range state.Registrations {
		if !state.Compensated[reg.Position] {
			remaining = append(remaining, reg.Name)
		}
	}
	var b strings.Builder
	b.WriteString("rolled back")
	if strings.TrimSpace(state.Reason) != "" {
		b.WriteString(": ")
		b.WriteString(state.Reason)
	}
	fmt.Fprintf(&b, " — %d compensation(s) executed", len(undone))
	if len(undone) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(undone, ", "))
	}
	if len(remaining) > 0 {
		fmt.Fprintf(&b, "; outstanding: %s", strings.Join(remaining, ", "))
	}
	return b.String()
}
