package aurora

import "context"

type Runtime interface {
	CreateSession(tags map[string]string) (SessionSnapshot, error)
	ListSessions() []SessionSummary
	Programs() []ProgramArtifact
	SetPrograms(ctx context.Context, programs []ProgramSource) error
	GetSession(sessionID string) (SessionSnapshot, error)
	CreateRun(sessionID string, message string, manifest Manifest) (RunSnapshot, error)
	GetRun(runID string) (RunSnapshot, error)
	Journal(runID string) ([]JournalEntry, error)
	JournalRevisions(runID string) (map[uint64][]JournalEntry, error)
	CallGraph(runID string) (RunGraphNode, error)
	SessionGraph(sessionID string) (SessionGraph, error)
	Tasks(runID string) ([]TaskSnapshot, error)
	ResolveTask(taskID string, token string, resolution Resolution) (TaskSnapshot, error)
	Stop(runID string) (RunSnapshot, error)
	Retry(runID string, mode RetryMode) (RunSnapshot, error)
	Subscribe(sessionID string) (Event, <-chan Event, func(), error)
	Close(ctx context.Context) error
}
