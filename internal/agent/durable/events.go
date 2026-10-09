package durable

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/eventlog"
)

// Domain event kinds appended to a session's eventlog stream. Lifecycle payloads
// are state-carried: a process event holds the process's full durable state at that
// point, so folding is last-writer-wins per id. A session.state event carries the
// session's explicit identity — its name (renamable, hence a first-class event
// rather than derived), tags, and creation time; the rest of a session's summary
// (active process, last update) is derived from the process projection. Task
// events are semantic (created / resolved). Capability-journal events
// (syscall.recorded) are defined alongside the journal view.
const (
	evSessionState = "session.state"
	evProcessState = "process.state"
	evTaskCreated  = "task.created"
	evTaskResolved = "task.resolved"
)

// taskEventData carries a task record plus its token hash, which TaskRecord
// deliberately omits from JSON (json:"-") since it is a secret-derived value the
// store must persist out of band.
type taskEventData struct {
	Record    TaskRecord `json:"record"`
	TokenHash []byte     `json:"token_hash,omitempty"`
}

// ProcessStateEvent records a process's full durable state.
func ProcessStateEvent(now time.Time, r Process) (eventlog.Event, error) {
	return EncodeEvent(evProcessState, r.ID, r.Revision, now, r)
}

// SessionStateEvent records a session's explicit identity (name, tags, creation
// time). It is not tied to a process, so it carries no proc/rev.
func SessionStateEvent(now time.Time, s Session) (eventlog.Event, error) {
	return EncodeEvent(evSessionState, "", 0, now, s)
}

func TaskCreatedEvent(now time.Time, record TaskRecord) (eventlog.Event, error) {
	return EncodeEvent(evTaskCreated, record.Scope.ProcessID, record.Scope.Revision, now,
		taskEventData{Record: record, TokenHash: record.TokenHash})
}

func TaskResolvedEvent(now time.Time, record TaskRecord) (eventlog.Event, error) {
	return EncodeEvent(evTaskResolved, record.Scope.ProcessID, record.Scope.Revision, now,
		taskEventData{Record: record, TokenHash: record.TokenHash})
}

func EncodeEvent(kind, proc string, rev uint64, now time.Time, payload any) (eventlog.Event, error) {
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

// Projection is the durable state folded from a session's event stream.
type Projection struct {
	Session Session
	// Processes is in creation order, then id.
	Processes []Process
	// Tasks is in creation order.
	Tasks []TaskRecord
}

// Fold reconstructs a session's durable projection from its event stream. Events
// must be in append order (ascending Seq). Folding is last-writer-wins per id.
// A stream starts with its session.state event: the session exists before
// anything else is appended to it.
func Fold(events []eventlog.Event) (Projection, error) {
	var session Session
	processes := make(map[string]Process)
	tasks := make(map[string]TaskRecord)
	for _, ev := range events {
		switch ev.Kind {
		case evSessionState:
			if err := json.Unmarshal(ev.Data, &session); err != nil {
				return Projection{}, fmt.Errorf("decode session.state: %w", err)
			}
		case evProcessState:
			var r Process
			if err := json.Unmarshal(ev.Data, &r); err != nil {
				return Projection{}, fmt.Errorf("decode proc.state: %w", err)
			}
			processes[r.ID] = r
		case evTaskCreated, evTaskResolved:
			var td taskEventData
			if err := json.Unmarshal(ev.Data, &td); err != nil {
				return Projection{}, fmt.Errorf("decode %s: %w", ev.Kind, err)
			}
			td.Record.TokenHash = td.TokenHash
			tasks[td.Record.ID] = td.Record
		}
		// syscall.recorded belongs to the journal view (foldJournals). Any other
		// kind is skipped.
	}
	proj := Projection{
		// The session.state event carries the session's explicit identity — id,
		// name, tags, creation time. Its last update and active process are
		// derived from its processes below.
		Session: session,
		// The order is deterministic, so nothing derived here — least of all
		// ActiveProcessID — depends on Go's map iteration order.
		Processes: slices.SortedFunc(maps.Values(processes), func(a, b Process) int {
			return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
		}),
		Tasks: slices.SortedFunc(maps.Values(tasks), func(a, b TaskRecord) int {
			return a.CreatedAt.Compare(b.CreatedAt)
		}),
	}
	for _, proc := range proj.Processes {
		if proc.UpdatedAt.After(proj.Session.UpdatedAt) {
			proj.Session.UpdatedAt = proc.UpdatedAt
		}
		// The session's foreground process: the earliest non-terminal one.
		if proj.Session.ActiveProcessID == "" && isActiveStatus(proc.Status) {
			proj.Session.ActiveProcessID = proc.ID
		}
	}
	return proj, nil
}

// isActiveStatus reports whether a process still occupies its session — it is
// neither completed, failed, nor stopped, so it can still make progress.
func isActiveStatus(status ProcessStatus) bool {
	switch status {
	case ProcessQueued, ProcessRunning, ProcessStopping, ProcessWaitingTask, ProcessInterrupted:
		return true
	default:
		return false
	}
}
