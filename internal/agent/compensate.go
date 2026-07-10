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
// The revision laws. A revision is one attempt; abandoning it — deciding it
// can never run again — is the only source of rollback, and a settled
// rollback is the only license to fork:
//
//  1. A fork happens only over a settled rollback: at the abandoned scope's
//     start (one past the open section's begin, or 0 when no section was
//     open — the whole process is the zone), or at 0 on an explicit restart.
//     A resume never forks: it continues the same revision by replay.
//  2. Before any fork, every registration in the abandoned scope has run to
//     a successful completion — the settled() gate; an unsettled rollback
//     resumes settlement, never the guest.
//  3. A revision is abandoned exactly when it can never run again: the
//     guest's own sys.abort, a failure whose re-drive made no journal
//     progress (the deterministic wall), a stop, or a restart. An
//     interruption is not abandonment — the revision resumes: recorded
//     effects served, open intents re-driven under their original keys, the
//     registrations the cut-off guest was about to make landing in the
//     journal, which is what makes registering an undo after its effect safe.
//
// The journal carries only the guest's narrative: its calls (sys.abort
// included — the guest's own abandonment, with its retry policy), and the
// execution of the undos it registered — the compensation section, which is
// itself the rollback marker. A host abandonment writes no journal record:
// the decision is management state (processState.abandoning, durable in the
// process stream), the restart's fork at 0 and the failure's error are its
// visible records, and only the compensations it executes touch the journal.
//
// Scope is positional: a rollback covers everything registered since the
// outermost-open sys.begin (committed inner sections included — a section
// inside a failed section failed with it), or since the beginning of the
// process when no section is open; a restart widens the scope to the whole
// revision, since the fork at 0 severs everything. This is the deliberate,
// backward counterpart of the automatic forward crash-resume: a host failure
// re-drives a process; abandonment undoes it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aurora-capcompute/capcompute/sys"
	"github.com/aurora-capcompute/capcompute/sys/replay/tape/journaled"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

const (
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

// rollbackState is the journal's view of a rollback — due, in progress, or
// settled: the scope of registrations to run and how far their execution has
// progressed. A guest sys.abort tail carries the guest's reason and retry
// policy; a host abandonment has no journal record of its own — its appended
// compensation section is the marker, and its kind lives in the process's
// management state.
type rollbackState struct {
	// GuestAbort is true when the journal's last word is the guest's own
	// completed sys.abort; Reason and RetrySeconds are its args.
	GuestAbort   bool
	Reason       string
	RetrySeconds *int64
	// ScopeEnd bounds the registration scan: the guest abort's position, the
	// first compensation record's, or the journal length when the rollback
	// has not appended anything yet.
	ScopeEnd int
	// ScopeStart is the journal-derived scope: one past the open section's
	// sys.begin, or 0 with no section open. It is where a section retry
	// forks. A restart widens the effective scope to 0 via widenToRevision —
	// the journal cannot know the abandonment kind.
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
func (s *rollbackState) settled() bool {
	if s.Resume != nil {
		return false
	}
	for _, reg := range s.Registrations {
		if !s.Compensated[reg.Position] {
			return false
		}
	}
	return true
}

// widenToRevision widens the scope to the whole revision — a restart's
// abandonment: every uncommitted registration, top-level ones included.
func (s *rollbackState) widenToRevision(j *logJournal) {
	s.ScopeStart = 0
	s.Registrations = j.registrationsIn(0, s.ScopeEnd)
}

// rollbackView reads the journal's rollback picture. started reports whether
// a rollback is already marked in the journal: the guest's own completed
// sys.abort as the last word, or an appended compensation section (a host
// abandonment's only journal trace). A nil state means the journal is
// unreadable. When no rollback is marked, the returned state is the scope a
// fresh abandonment would roll back — registrations scanned to the journal's
// end — so the settle path reads one shape either way.
func (j *logJournal) rollbackView() (*rollbackState, bool) {
	length := j.Length()
	abortPos := -1
	firstCompensation := -1
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
			// succeeded — a rejected sys.abort is an ordinary failed call.
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
			if firstCompensation < 0 {
				firstCompensation = rec.Position
			}
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

	state := &rollbackState{ScopeEnd: length, Compensated: compensated}
	started := false
	switch {
	case abortPos >= 0:
		// The guest's own abandonment: reason and retry policy from its args.
		started = true
		state.GuestAbort = true
		state.ScopeEnd = abortPos
		if intent, err := j.Load(abortPos); err == nil && intent.Syscall != nil {
			var args abortArgs
			_ = json.Unmarshal(intent.Syscall.Args, &args)
			state.Reason = args.Reason
			state.RetrySeconds = args.RetrySeconds
		}
	case firstCompensation >= 0:
		// A compensation section with no guest abort: a host abandonment's
		// rollback, in progress or settled.
		started = true
		state.ScopeEnd = firstCompensation
	}
	if off, ok := j.outermostOpenBegin(); ok {
		state.ScopeStart = off
	}
	state.Registrations = j.registrationsIn(state.ScopeStart, state.ScopeEnd)
	return state, started
}

// unsettledRollback reads the process's rollback picture together with the
// gate Stop and Retry share: whether an abandonment or a journal-marked
// rollback owns the process and has not yet settled. An unsettled rollback
// resumes settlement, never the guest, and refuses a restart. Called with the
// runtime mutex held.
func (p *processState) unsettledRollback() (state *rollbackState, started, unsettled bool) {
	state, started = p.journal.rollbackView()
	unsettled = (p.abandoning != "" || started) && (state == nil || !state.settled())
	return state, started, unsettled
}

// registrationsIn scans [start, end) for armed registrations: completed
// sys.compensate calls, in registration order. A rejected registration never
// armed.
func (j *logJournal) registrationsIn(start, end int) []compensationRegistration {
	var out []compensationRegistration
	for i := start; i < end; i++ {
		rec, err := j.Load(i)
		if err != nil {
			return nil
		}
		if rec.Kind != journaled.KindIntent || rec.Syscall == nil || rec.Syscall.Name != callSysCompensate {
			continue
		}
		if i+1 >= end {
			continue
		}
		next, err := j.Load(i + 1)
		if err != nil || next.Kind != journaled.KindCompletion || next.Result == nil ||
			next.Result.Status() != sys.StatusResult {
			continue
		}
		var reg compensateArgs
		if json.Unmarshal(rec.Syscall.Args, &reg) != nil {
			continue
		}
		out = append(out, compensationRegistration{
			Position: rec.Position,
			Name:     reg.Name,
			Args:     reg.Args,
		})
	}
	return out
}

// liveJournal fetches a process's live journal under the runtime lock.
func (r *Runtime) liveJournal(processID string) (*logJournal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil || proc.journal == nil {
		return nil, false
	}
	return proc.journal, true
}

// guestAborted reports whether a process's journal ends in the guest's own
// completed sys.abort — the completion path's cheap dispatch test.
func (r *Runtime) guestAborted(processID string) bool {
	journal, ok := r.liveJournal(processID)
	if !ok {
		return false
	}
	state, started := journal.rollbackView()
	return started && state != nil && state.GuestAbort
}

// abandonRevision begins abandoning a process's current revision and reports
// whether a rollback is due. The decision is management state, never a
// journal record: abandoning is stamped on the process — durably, via the
// process stream — so a crash mid-rollback resumes the abandonment to its
// recorded conclusion; the journal will carry only the compensations the
// rollback executes. False means nothing partial is at stake (no open
// section for a failure or stop — the revision stays resumable) and the
// caller proceeds plainly. When the guest's own sys.abort is already the
// journal's last word, a failure or stop dissolves into it — the guest's
// policy wins. A restart instead stamps its own kind over whatever stands —
// a guest abort's settled remains or a standing host abandonment: those
// rollbacks already ran, and what is still uncommitted widens into the
// restart.
func (r *Runtime) abandonRevision(processID, kind, reason string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	proc := r.processes[processID]
	if proc == nil || proc.journal == nil {
		return false
	}
	if proc.abandoning != "" && kind != abandonRestart {
		return true // already abandoning; the settle resumes it
	}
	state, started := proc.journal.rollbackView()
	if state == nil {
		return false
	}
	if started && state.GuestAbort && kind != abandonRestart {
		return true // the guest's own abandonment; its policy wins
	}
	// Failure and stop abandon only when a section is open: without one the
	// revision stays resumable, and its top-level registrations stay armed
	// for it. A restart abandons unconditionally — the fork at 0 severs the
	// revision, so its whole uncommitted scope (top-level registrations
	// included) rolls back first.
	if _, open := proc.journal.outermostOpenBegin(); !open && kind != abandonRestart {
		return false
	}
	proc.abandoning = kind
	if kind == abandonFailure && reason != "" {
		proc.err = reason
	}
	proc.updatedAt = r.now().UTC()
	if err := r.appendProcess(proc); err != nil {
		// Degraded: the stamp is in memory only. A crash before the rollback
		// concludes loses it — restore folds the process to interrupted, the
		// re-drive hits the wall again, and the abandonment is re-detected.
		slog.Warn("persist abandonment", "process_id", processID, "kind", kind, "error", err)
	}
	return true
}

// failProcess finishes a failing process. A failure inside an open critical
// section is first treated like any interruption: re-drive by replay, because
// most failures are transient and a resume completes what the failure cut
// short — the recorded effects are served, an open intent re-drives under its
// original key, and the registrations the guest was about to make land in the
// journal. This is what makes registering an undo after its effect safe: the
// rollback can only run once every registration reachable from the recorded
// history is durable. A re-drive that appends nothing has hit a deterministic
// wall — resume is impossible — and only then is the revision abandoned: the
// registered compensations run newest-first, the process reports failed with
// the original error, and a later retry forks at the section's begin over
// rolled-back state. Without an open section the failure is terminal as-is:
// nothing partial is awaiting a commit that will never come.
func (r *Runtime) failProcess(processID string, failure error) {
	if r.redriveAfterFailure(processID) {
		return
	}
	r.failNow(processID, failure)
}

// failNow rolls an open section back and finishes the process as failed, with
// no re-drive — the path for a failure that has already earned its re-drive and
// hit the wall (a deterministic failure the resume cannot get past).
func (r *Runtime) failNow(processID string, failure error) {
	if failure == nil {
		failure = errors.New("process failed")
	}
	if r.abandonRevision(processID, abandonFailure, failure.Error()) {
		r.settleRollback(processID)
		return
	}
	r.finish(processID, ProcessFailed, "", failure)
}

// redriveAfterFailure relaunches a process that failed inside an open critical
// section, at most once per journal length: the progress guard. It reports
// false — fall through to the rollback — when no section is open, a rollback
// is already the journal's last word, a stop or shutdown is in flight, or the
// journal did not grow since the previous failure (the deterministic wall).
func (r *Runtime) redriveAfterFailure(processID string) bool {
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil || proc.journal == nil || proc.stopRequested || r.closed {
		r.mu.Unlock()
		return false
	}
	journal := proc.journal
	if _, open := journal.outermostOpenBegin(); !open {
		r.mu.Unlock()
		return false
	}
	if proc.abandoning != "" {
		r.mu.Unlock()
		return false
	}
	if state, started := journal.rollbackView(); started || state == nil {
		r.mu.Unlock()
		return false
	}
	length := journal.Length()
	if proc.lastFailureLength == length {
		r.mu.Unlock()
		return false
	}
	proc.lastFailureLength = length
	if _, err := r.relaunchLocked(proc); err != nil {
		slog.Warn("re-drive after failure", "process_id", processID, "error", err)
		return false
	}
	return true
}

// stopProcess finishes a stopped process, first rolling back its open critical
// section — a stop is an abandonment without a retry. When the stop raced the
// guest's own sys.abort (the quantum was killed right after the abort was
// journaled), the guest's record is the journal's last word and its policy
// wins: the stop dissolves into the guest's rollback.
func (r *Runtime) stopProcess(processID string, cause error) {
	if r.abandonRevision(processID, abandonStop, "") {
		r.settleRollback(processID)
		return
	}
	r.finish(processID, ProcessStopped, "", cause)
}

// restartProcess abandons the current revision on behalf of an explicit
// restart — its whole uncommitted scope rolls back like any abandonment —
// and then re-runs the process from scratch.
func (r *Runtime) restartProcess(processID string) {
	if r.abandonRevision(processID, abandonRestart, "") {
		r.settleRollback(processID)
		return
	}
	r.retrySection(processID, 0, RetryRestart)
}

// errRollbackParked marks a rollback suspended on a human: an inverse yielded,
// its durable task is pending, and the open compensation intent at the journal
// tail is the park. Resolving the task resumes settlement.
var errRollbackParked = errors.New("rollback parked on an external task")

// settleRollback drives an abandoned revision's rollback to its conclusion:
// it executes the remaining registered compensations newest-first (resuming
// any compensation a crash left open, under its original idempotency key),
// then concludes by the abandonment's recorded kind — or, for the guest's own
// sys.abort, by its declared retry policy. Inverses dispatch through the task
// layer, so an undo that needs sign-off yields into a durable task like any
// forward call: the rollback parks, the human is the terminal compensator
// inside it, and the resolution resumes settlement (approved executes the
// inverse; denied fails the rollback). A compensation that fails semantically
// stops the rollback and fails the process with the rollback report: the
// remaining undos need a human, and the journal is the remediation map.
// settleRollback is idempotent — every step is journaled before it executes,
// so calling it again (after a crash, a resolution, or a manual retry of a
// failed rollback) continues where the last attempt stopped.
func (r *Runtime) settleRollback(processID string) {
	fail := func(err error) {
		r.finish(processID, ProcessFailed, "", fmt.Errorf("rollback: %w", err))
	}
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil || proc.journal == nil {
		r.mu.Unlock()
		fail(errors.New("process journal is unavailable"))
		return
	}
	cred := r.processContextLocked(proc)
	journal := proc.journal
	kind, reason := proc.abandoning, proc.err
	r.mu.Unlock()
	state, started := journal.rollbackView()
	if state == nil {
		fail(errors.New("journal is unreadable"))
		return
	}
	if kind == "" && !(started && state.GuestAbort) {
		fail(errors.New("no rollback is in progress"))
		return
	}
	if kind == abandonRestart {
		// A restart abandons the whole revision: the fork at 0 severs
		// everything, so everything uncommitted rolls back.
		state.widenToRevision(journal)
	}
	// The report names the guest's declared reason; a host abandonment
	// reports the error recorded when it was stamped, or failing that its kind.
	reportReason := state.Reason
	if kind != "" {
		reportReason = reason
		if reportReason == "" {
			reportReason = kind
		}
	}

	// Derive from the runtime lifecycle context so Close can interrupt an
	// in-flight compensation (a driver call that could otherwise run to its own
	// timeout); a cancelled compensation leaves its intent open for a restart to
	// resume. Fall back to Background for a runtime built without NewRuntime.
	ctx := r.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	drivers, err := r.processDrivers(ctx, cred)
	if err != nil {
		fail(err)
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
		fail(err)
		return
	}
	// Effects arms the compensator's pending state and surfaces a compensation
	// a crash left open; the effect list itself is unused — the rollback plan is
	// the guest's registrations, not the executed effects.
	_, resume, err := compensator.Effects(0)
	if err != nil {
		fail(err)
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
		r.finish(processID, ProcessFailed, rollbackReport(state, reportReason, undone), fmt.Errorf("rollback stopped: %w", err))
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
	r.concludeRollback(ctx, processID, cred, kind, reason, state, rollbackReport(state, reportReason, undone))
}

// concludeRollback finishes a fully settled rollback. A host abandonment
// follows its recorded kind — failed (the error recorded when the revision
// was abandoned, standing), stopped, or restarted from scratch. The guest's
// own abort applies its declared retry policy: re-run the section now, park
// on a durable retry timer, or finish as compensated — with the retry budget
// as the guard against a guest that aborts forever.
func (r *Runtime) concludeRollback(ctx context.Context, processID string, cred ProcessContext, kind, reason string, state *rollbackState, report string) {
	switch kind {
	case abandonFailure:
		if reason == "" {
			reason = "process failed"
		}
		r.finish(processID, ProcessFailed, report, errors.New(reason))
		return
	case abandonStop:
		r.finish(processID, ProcessStopped, report, context.Canceled)
		return
	case abandonRestart:
		// Cleaned up, now re-run from scratch. The abandonment was recorded
		// durably before the rollback ran — a crash anywhere in it resumes
		// the settlement and still restarts.
		r.retrySection(processID, 0, RetryRestart)
		return
	}
	if state.RetrySeconds == nil {
		r.finish(processID, ProcessCompensated, report, nil)
		return
	}
	// The retry budget counts rollback cycles, not quanta: every abort retry
	// forks a new revision (the only minting events are rollback re-runs and
	// restarts), while re-drives and approval parks merely bump the attempt.
	// Budgeting on attempt would let a flaky-but-recovering section exhaust
	// its rollbacks without ever looping.
	r.mu.Lock()
	rollbacks := uint64(0)
	if p := r.processes[processID]; p != nil {
		rollbacks = p.revision - 1
	}
	limit := uint64(r.maxAbortRetries)
	r.mu.Unlock()
	if rollbacks >= limit {
		r.finish(processID, ProcessCompensated, report,
			fmt.Errorf("abort retry budget exhausted after %d rollbacks", rollbacks))
		return
	}
	delay := min(max(time.Duration(*state.RetrySeconds)*time.Second, 0), maxAbortRetryDelay)
	if delay == 0 {
		r.retrySection(processID, state.ScopeStart, RetryResume)
		return
	}
	if err := r.parkForRetry(ctx, cred, state, delay); err != nil {
		r.finish(processID, ProcessFailed, report, fmt.Errorf("schedule abort retry: %w", err))
		return
	}
	r.finish(processID, ProcessWaitingTask, "", nil)
}

// retrySection re-runs an abandoned-and-settled process as a fresh revision
// forked at forkOffset — the aborted section's begin for a retry, 0 for a
// restart. The rolled-back attempt stays in the log as a closed, audited
// transaction.
func (r *Runtime) retrySection(processID string, forkOffset int, mode RetryMode) {
	r.mu.Lock()
	proc := r.processes[processID]
	if proc == nil {
		r.mu.Unlock()
		return
	}
	r.forkJournalLocked(proc, forkOffset, mode)
	if _, err := r.relaunchLocked(proc); err != nil {
		slog.Warn("abort retry relaunch", "process_id", processID, "error", err)
	}
}

// parkForRetry authors the durable retry timer: a pending sys.timer task whose
// fire time is the rollback plus the abort's delay. The distribution's timer
// service arms and fires it like any timer task — restart-safe for free — and
// its resolution resumes the process, which then re-runs the aborted section.
func (r *Runtime) parkForRetry(ctx context.Context, cred ProcessContext, state *rollbackState, delay time.Duration) error {
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
		JournalPosition: state.ScopeEnd,
		// The retry task speaks sys.timer — the runtime's own syscall — so
		// the distribution's timer service arms and fires abort retries with
		// no special handling.
		Syscall:   sys.Syscall{Abi: sys.ABIVersion, Name: TimerSyscall, Args: args},
		Summary:   retrySummary(state.Reason),
		State:     task.StatePending,
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	task.StampToken(&record, r.taskSecret)
	if err := r.tasks.Create(ctx, record); err != nil {
		return err
	}
	r.publish(cred.SessionID, Event{Type: "task.created", Data: r.taskSnapshot(record)})
	return nil
}

// retrySummary is the retry timer task's human-facing one-liner.
func retrySummary(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "abort retry"
	}
	return "abort retry: " + reason
}

// rollbackReport renders what the rollback did — its reason, the undos that
// ran, and any registrations still outstanding. It is the compensated
// process's answer and a failed rollback's remediation map.
func rollbackReport(state *rollbackState, reason string, undone []string) string {
	var remaining []string
	for _, reg := range state.Registrations {
		if !state.Compensated[reg.Position] {
			remaining = append(remaining, reg.Name)
		}
	}
	var b strings.Builder
	b.WriteString("rolled back")
	if strings.TrimSpace(reason) != "" {
		b.WriteString(": ")
		b.WriteString(reason)
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
