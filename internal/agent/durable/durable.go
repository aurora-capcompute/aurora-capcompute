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
	"maps"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/manifest"
)

type ProcessStatus string

const (
	ProcessQueued      ProcessStatus = "queued"
	ProcessRunning     ProcessStatus = "running"
	ProcessStopping    ProcessStatus = "stopping"
	ProcessWaitingTask ProcessStatus = "waiting_for_task"
	ProcessInterrupted ProcessStatus = "interrupted"
	ProcessCompleted   ProcessStatus = "completed"
	ProcessStopped     ProcessStatus = "stopped"
	ProcessFailed      ProcessStatus = "failed"
)

// ProcessContext names one revision of one process: the credential its
// dispatcher chain runs under, the key its taint is kept by, and the scope a
// task record belongs to.
type ProcessContext struct {
	SessionID string
	ProcessID string
	Revision  uint64
}

// Session is a session's durable state, carried by session.state events and
// folded back into memory on restore.
type Session struct {
	ID string
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
	// Labels is the run's final taint, persisted so the session-history entry this
	// process contributes is rebuilt with its provenance on restore — the
	// cross-run flow policy survives a restart.
	Labels []string `json:",omitempty"`
	// ForkOffset is the current revision's copy-on-write fork point; it is
	// persisted so a revision that was forked but crashed before logging any
	// record can be reconstructed on restore.
	ForkOffset int
	// AbortRetries is how many times the guest has aborted and re-run a section.
	// Persisted because it is the budget bounding that loop: an in-memory counter
	// would hand a restart a fresh one, and a guest that aborts forever would
	// never exhaust it.
	AbortRetries int `json:",omitempty"`
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
	maps.Copy(out, tags)
	return out
}
