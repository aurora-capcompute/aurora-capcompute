// Package durable is a session's persisted vocabulary and how it is rebuilt: the
// state a session.state or process.state event carries, the event kinds a stream
// is made of, and Fold, which replays a stream back into the state the runtime
// left behind.
//
// The append-only log is the only durable store — there is no row table to read —
// so this package is the whole schema of what survives a restart. A field absent
// here does not come back. Process status lives here for the same reason: what a
// process is doing is exactly what has to be restored, and a status the fold
// cannot round-trip would silently resurrect a process in the wrong state.
package durable

import (
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

type ProcessStatus string

const (
	ProcessQueued      ProcessStatus = "queued"
	ProcessRunning     ProcessStatus = "running"
	ProcessStopping    ProcessStatus = "stopping"
	ProcessYielded     ProcessStatus = "yielded"
	ProcessWaitingTask ProcessStatus = "waiting_for_task"
	ProcessInterrupted ProcessStatus = "interrupted"
	ProcessCompleted   ProcessStatus = "completed"
	ProcessStopped     ProcessStatus = "stopped"
	ProcessFailed      ProcessStatus = "failed"
	// ProcessCompensated is terminal: the guest rolled the process back with
	// sys.abort — its registered compensations ran — and declared no retry,
	// or exhausted the retry budget.
	ProcessCompensated ProcessStatus = "compensated"
)

// Session is a session's durable state, derived from the process projection
// and folded back into memory on restore.
type Session struct {
	TenantID string
	ID       string
	// Name is the session's explicit, renamable handle (empty if unnamed). It is
	// carried by session.state events, not derived from the process projection.
	Name            string
	Title           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ActiveProcessID string
	// Tags are arbitrary key-value labels set at creation time. Applications
	// use them to correlate sessions with their own identifiers (e.g. a
	// conversation or channel id) from the log without maintaining a separate
	// mapping store; the runtime never interprets them.
	Tags map[string]string
}

// Process is a process's durable state, carried by process.state events and folded
// back into memory on restore.
type Process struct {
	TenantID      string
	ID            string
	SessionID     string
	Revision      uint64
	Input         string
	Status        ProcessStatus
	Attempt       int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	StartedAt     *time.Time
	CompletedAt   *time.Time
	Answer        string
	Error         string
	Manifest      manifest.Manifest
	ProgramDigest string
	// HideHistory records that this process was spawned under a sys.spawn grant
	// with history:false — its sys.input omits the session history. Persisted so
	// a restart re-serves the same isolated input.
	HideHistory bool `json:",omitempty"`
	// Labels is the run's final taint, persisted so the session-history entry this
	// process contributes is rebuilt with its provenance on restore — the
	// cross-run flow policy survives a restart.
	Labels []string `json:",omitempty"`
	// InputLabels is the provenance the process's input arrived with — a
	// delegated child's parent-taint snapshot at spawn. Persisted so a restart or
	// revision restart re-serves sys.input with the same taint seed; the
	// parent→child flow policy survives a restart exactly like the cross-run one.
	InputLabels []string `json:",omitempty"`
	// Tags carries the owning session's tags. A session.state event now carries
	// them too; this copy is retained so sessions from pre-session.state streams
	// (which have no such event) still restore their tags.
	Tags map[string]string
	// ParentProcessID links a delegated child back to the process that spawned
	// it; ChildProcessIDs records, in spawn order, the children this process
	// delegated to.
	ParentProcessID string
	ChildProcessIDs []string
	// ChildSpawnOffsets records the journal length at each child's spawn,
	// parallel to ChildProcessIDs. ForkOffset is the current revision's copy-on-write
	// fork point; it is persisted so a revision that was forked but crashed before
	// logging any record can be reconstructed on restore.
	ChildSpawnOffsets []int
	ForkOffset        int
	// Abandoning is the host's abandonment of the current revision (failure,
	// stop, or restart), persisted so a crash mid-rollback resumes the
	// abandonment to its recorded conclusion, and standing until the fork
	// that opens the successor revision. Management state: the journal
	// carries only the guest's narrative.
	Abandoning string `json:",omitempty"`
}

// DefaultSessionTitle is the placeholder headline a session carries until one of
// its processes supplies one. It is applied identically on creation and on
// restore so a process-less named session round-trips to the same title.
const DefaultSessionTitle = "New session"

// SessionTitle derives a session's headline from its first process input.
func SessionTitle(input string) string {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return DefaultSessionTitle
	}
	title := strings.Join(fields, " ")
	runes := []rune(title)
	if len(runes) <= 60 {
		return title
	}
	return string(runes[:60]) + "…"
}

// CloneTags copies a session's labels, so a caller cannot mutate stored state.
func CloneTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}
