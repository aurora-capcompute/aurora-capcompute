package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/eventlog"
	"github.com/aurora-capcompute/aurora-capcompute/internal/task"
)

// Domain event kinds appended to a session's eventlog stream. Lifecycle payloads
// are state-carried: a process event holds the process's full durable state at that
// point, so folding is last-writer-wins per id. Session state is derived from
// the process projection (no separate session event). Task events are semantic
// (created / resolved / executed). Capability-journal and fork events are
// defined alongside the journal view.
const (
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
	data, err := json.Marshal(payload)
	if err != nil {
		return eventlog.Event{}, fmt.Errorf("encode %s event: %w", kind, err)
	}
	return eventlog.Event{Kind: kind, Time: now.UTC(), Proc: proc, Rev: rev, Data: data}, nil
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
// projection rather than stored in a dedicated event.
func Fold(events []eventlog.Event) (Projection, error) {
	proj := Projection{
		Processes: make(map[string]StoredProcess),
		Tasks:     make(map[string]task.Record),
	}
	for _, ev := range events {
		switch ev.Kind {
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
		// capability.recorded / proc.forked / session.state (legacy, ignored) are
		// handled by the journal view or silently skipped here.
	}
	proj.Session = deriveStoredSession(proj.Processes)
	return proj, nil
}

// deriveStoredSession reconstructs session metadata from the process projection.
// Session state is not stored in a separate event; instead it is derived:
// - identity (ID, TenantID) and Tags come from the earliest process
// - Title is the first process's message truncated to 60 runes
// - CreatedAt is the earliest process's CreatedAt
// - UpdatedAt is the latest process's UpdatedAt
// - ActiveProcessID is the ID of the one process (if any) that is not in a terminal state
func deriveStoredSession(runs map[string]StoredProcess) StoredSession {
	if len(runs) == 0 {
		return StoredSession{}
	}
	var first StoredProcess
	for _, r := range runs {
		if first.ID == "" || r.CreatedAt.Before(first.CreatedAt) {
			first = r
		}
	}
	th := StoredSession{
		TenantID:  first.TenantID,
		ID:        first.SessionID,
		Title:     sessionTitle(first.Message),
		CreatedAt: first.CreatedAt,
		UpdatedAt: first.UpdatedAt,
		Tags:      cloneTags(first.Tags),
	}
	for _, r := range runs {
		if r.UpdatedAt.After(th.UpdatedAt) {
			th.UpdatedAt = r.UpdatedAt
		}
		switch r.Status {
		case ProcessQueued, ProcessRunning, ProcessStopping, ProcessYielded, ProcessWaitingTask, ProcessInterrupted:
			th.ActiveProcessID = r.ID
		}
	}
	return th
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
