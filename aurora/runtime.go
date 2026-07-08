package aurora

import "context"

type Runtime interface {
	CreateSession(name string, tags map[string]string) (SessionSnapshot, error)
	RenameSession(sessionID string, name string) (SessionSnapshot, error)
	ListSessions() []SessionSummary
	Programs() []ProgramArtifact
	SetPrograms(ctx context.Context, programs []ProgramSource) error
	GetSession(sessionID string) (SessionSnapshot, error)
	CreateProcess(sessionID string, input string, manifest Manifest) (ProcessSnapshot, error)
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
	Close(ctx context.Context) error
}
