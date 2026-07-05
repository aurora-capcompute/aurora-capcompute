package aurora

import "context"

type Runtime interface {
	CreateSession(tags map[string]string) (SessionSnapshot, error)
	ListSessions() []SessionSummary
	Programs() []ProgramArtifact
	SetPrograms(ctx context.Context, programs []ProgramSource) error
	GetSession(sessionID string) (SessionSnapshot, error)
	CreateProcess(sessionID string, message string, manifest Manifest) (ProcessSnapshot, error)
	GetProcess(processID string) (ProcessSnapshot, error)
	Journal(processID string) ([]JournalEntry, error)
	JournalRevisions(processID string) (map[uint64][]JournalEntry, error)
	CallGraph(processID string) (ProcessGraphNode, error)
	SessionGraph(sessionID string) (SessionGraph, error)
	Tasks(processID string) ([]TaskSnapshot, error)
	ResolveTask(taskID string, token string, resolution Resolution) (TaskSnapshot, error)
	Stop(processID string) (ProcessSnapshot, error)
	Retry(processID string, mode RetryMode) (ProcessSnapshot, error)
	Subscribe(sessionID string) (Event, <-chan Event, func(), error)
	// CompactSession rewrites one session's event stream as [snapshot +
	// retained journals] (ROADMAP #16): a compacted stream folds to the same
	// projection; only terminal processes' journals are traded away. It
	// refuses (ErrConflict) while the session has an executing process.
	CompactSession(sessionID string) error
	// CompactSessions compacts every session, skipping busy sessions and
	// sessions where compaction would not shrink the stream.
	CompactSessions(ctx context.Context) error
	Close(ctx context.Context) error
}
