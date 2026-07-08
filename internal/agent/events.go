package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/task"
)

// Domain event kinds appended to a session's eventlog stream. Lifecycle payloads
// are state-carried: a process event holds the process's full durable state at that
// point, so folding is last-writer-wins per id. A session.state event carries the
// session's explicit identity — its name (renamable, hence a first-class event
// rather than derived), tags, and creation time; the rest of a session's summary
// (title, active process) is still derived from the process projection. Task
// events are semantic (created / resolved / executed). Capability-journal events
// (syscall.recorded, journal.header) are defined alongside the journal view.
const (
	evSessionState = "session.state"
	evProcessState = "process.state"
	evTaskCreated  = "task.created"
	evTaskResolved = "task.resolved"
	evTaskExecuted = "task.executed"
)

// taskEventData carries a task record plus its token hash, which task.Record
// deliberately omits from JSON (json:"-") since it is a secret-derived value the
// store must persist out of band.
type taskEventData struct {
	Record    task.Record `json:"record"`
	TokenHash []byte      `json:"token_hash,omitempty"`
}

type taskExecutedData struct {
	TaskID string `json:"task_id"`
}

func processStateEvent(now time.Time, r StoredProcess) (eventlog.Event, error) {
	return encodeEvent(evProcessState, r.ID, r.Revision, now, r)
}

// sessionStateEvent records a session's explicit identity (name, tags, creation
// time). It is not tied to a process, so it carries no proc/rev.
func sessionStateEvent(now time.Time, s StoredSession) (eventlog.Event, error) {
	return encodeEvent(evSessionState, "", 0, now, s)
}

func taskCreatedEvent(now time.Time, record task.Record) (eventlog.Event, error) {
	return encodeEvent(evTaskCreated, record.Scope.ProcessID, record.Scope.Revision, now,
		taskEventData{Record: record, TokenHash: record.TokenHash})
}

func taskResolvedEvent(now time.Time, record task.Record) (eventlog.Event, error) {
	return encodeEvent(evTaskResolved, record.Scope.ProcessID, record.Scope.Revision, now,
		taskEventData{Record: record, TokenHash: record.TokenHash})
}

func taskExecutedEvent(now time.Time, processID string, rev uint64, taskID string) (eventlog.Event, error) {
	return encodeEvent(evTaskExecuted, processID, rev, now, taskExecutedData{TaskID: taskID})
}

func encodeEvent(kind, proc string, rev uint64, now time.Time, payload any) (eventlog.Event, error) {
	data, err := marshalVerbatim(payload)
	if err != nil {
		return eventlog.Event{}, fmt.Errorf("encode %s event: %w", kind, err)
	}
	return eventlog.Event{Kind: kind, Time: now.UTC(), Proc: proc, Rev: rev, Data: data}, nil
}

// marshalVerbatim encodes without HTML escaping, so json.RawMessage payloads
// (journaled syscall args and results, task syscalls) round-trip through the
// event log byte-identically. json.Marshal would rewrite <, >, and & to
// \u003c-style escapes inside raw messages; a restored journal would then
// hold different bytes than the guest re-issues, and replay would refuse its
// own history as a divergence.
func marshalVerbatim(payload any) (json.RawMessage, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// Projection is the durable state folded from a session's event stream: the same
// StoredState + task records the runtime previously loaded from the CRUD stores,
// now derived from the append-only log.
type Projection struct {
	Session   StoredSession
	Processes map[string]StoredProcess
	Tasks     map[string]task.Record
}

// Fold reconstructs a session's durable projection from its event stream. Events
// must be in append order (ascending Seq). Session state is derived from the process
// projection rather than stored in a dedicated event; folding is
// last-writer-wins per id.
func Fold(events []eventlog.Event) (Projection, error) {
	proj := Projection{
		Processes: make(map[string]StoredProcess),
		Tasks:     make(map[string]task.Record),
	}
	var sessionEvent *StoredSession
	for _, ev := range events {
		switch ev.Kind {
		case evSessionState:
			var s StoredSession
			if err := json.Unmarshal(ev.Data, &s); err != nil {
				return Projection{}, fmt.Errorf("decode session.state: %w", err)
			}
			sessionEvent = &s
		case evProcessState:
			var r StoredProcess
			if err := json.Unmarshal(ev.Data, &r); err != nil {
				return Projection{}, fmt.Errorf("decode proc.state: %w", err)
			}
			proj.Processes[r.ID] = r
		case evTaskCreated, evTaskResolved:
			var td taskEventData
			if err := json.Unmarshal(ev.Data, &td); err != nil {
				return Projection{}, fmt.Errorf("decode %s: %w", ev.Kind, err)
			}
			td.Record.TokenHash = td.TokenHash
			proj.Tasks[td.Record.ID] = td.Record
		case evTaskExecuted:
			var x taskExecutedData
			if err := json.Unmarshal(ev.Data, &x); err != nil {
				return Projection{}, fmt.Errorf("decode task.executed: %w", err)
			}
			if rec, ok := proj.Tasks[x.TaskID]; ok {
				rec.State = task.StateExecuted
				proj.Tasks[x.TaskID] = rec
			}
		}
		// syscall.recorded / journal.header belong to the journal view
		// (foldJournals); any other kind is skipped.
	}
	proj.Session = deriveStoredSession(proj.Processes)
	if sessionEvent != nil {
		// The session.state event is authoritative for the session's explicit
		// identity — id, name, tags, creation time — while the title and active
		// process stay derived from the process projection. This is what lets a
		// named session with no processes persist, and a rename survive a restart.
		merged := *sessionEvent
		merged.Title = proj.Session.Title
		merged.ActiveProcessID = proj.Session.ActiveProcessID
		if proj.Session.UpdatedAt.After(merged.UpdatedAt) {
			merged.UpdatedAt = proj.Session.UpdatedAt
		}
		proj.Session = merged
	}
	return proj, nil
}

// deriveStoredSession reconstructs session metadata from the process projection.
// Session state is not stored in a separate event; instead it is derived:
// - identity (ID, TenantID) and Tags come from the earliest process
// - Title is the first process's message truncated to 60 runes
// - CreatedAt is the earliest process's CreatedAt
// - UpdatedAt is the latest process's UpdatedAt
// - ActiveProcessID is the ID of the one process (if any) that is not in a terminal state
func deriveStoredSession(processes map[string]StoredProcess) StoredSession {
	if len(processes) == 0 {
		return StoredSession{}
	}
	ordered := make([]StoredProcess, 0, len(processes))
	for _, proc := range processes {
		ordered = append(ordered, proc)
	}
	// Deterministic order (creation time, then id) so nothing derived here —
	// least of all ActiveProcessID — depends on Go's map iteration order.
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
		}
		return ordered[i].ID < ordered[j].ID
	})

	session := StoredSession{
		TenantID:  ordered[0].TenantID,
		ID:        ordered[0].SessionID,
		Title:     sessionTitle(ordered[0].Input),
		CreatedAt: ordered[0].CreatedAt,
		UpdatedAt: ordered[0].UpdatedAt,
		Tags:      cloneTags(ordered[0].Tags),
	}
	for _, proc := range ordered {
		if proc.UpdatedAt.After(session.UpdatedAt) {
			session.UpdatedAt = proc.UpdatedAt
		}
	}
	// ActiveProcessID is the session's foreground process: the earliest
	// non-terminal top-level process. Preferring a root over a delegated child
	// means a crash that leaves a running child and a waiting parent resolves to
	// the parent — so restore never pins the session to a child that the
	// parent's own retry would then collide with.
	for _, proc := range ordered {
		if isActiveStatus(proc.Status) && proc.ParentProcessID == "" {
			session.ActiveProcessID = proc.ID
			break
		}
	}
	if session.ActiveProcessID == "" {
		for _, proc := range ordered {
			if isActiveStatus(proc.Status) {
				session.ActiveProcessID = proc.ID
				break
			}
		}
	}
	return session
}

// isActiveStatus reports whether a process still occupies its session — it is
// neither completed, failed, nor stopped, so it can still make progress.
func isActiveStatus(status ProcessStatus) bool {
	switch status {
	case ProcessQueued, ProcessRunning, ProcessStopping, ProcessYielded, ProcessWaitingTask, ProcessInterrupted:
		return true
	default:
		return false
	}
}

// TaskList returns the projection's task records sorted by creation time, the
// order callers expect from the old TaskStore.List.
func (p Projection) TaskList() []task.Record {
	out := make([]task.Record, 0, len(p.Tasks))
	for _, rec := range p.Tasks {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
