package agent

import (
	"context"
	"time"
)

const DefaultTenantID = "local"

// StoredSession is a session's durable state, derived from the process projection
// and folded back into memory on restore.
type StoredSession struct {
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

// StoredProcess is a process's durable state, carried by process.state events and folded
// back into memory on restore.
type StoredProcess struct {
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
	Manifest      Manifest
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

// Leases coordinates exclusive process and task execution across runtime instances.
// It is deliberately separate from the event log: a lease is ephemeral
// coordination (a fencing token with a TTL), not part of a session's immutable
// history.
type Leases interface {
	Acquire(ctx context.Context, tenantID, kind, resourceID, holder string, now time.Time, ttl time.Duration) (bool, error)
	Release(ctx context.Context, tenantID, kind, resourceID, holder string) error
}
