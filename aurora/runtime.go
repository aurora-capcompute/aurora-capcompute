package aurora

import (
	"context"
	"time"
)

type Runtime interface {
	CreateSession(name string, tags map[string]string) (SessionSnapshot, error)
	RenameSession(sessionID string, name string) (SessionSnapshot, error)
	ListSessions() []SessionSummary
	Programs() []ProgramArtifact
	AddProgram(ctx context.Context, program ProgramData) error
	RemoveProgram(ctx context.Context, id string) error
	GetSession(sessionID string) (SessionSnapshot, error)
	CreateProcess(sessionID string, input string, manifest Manifest, deadline time.Duration) (ProcessSnapshot, error)
	GetProcess(processID string) (ProcessSnapshot, error)
	ResolveTask(taskID string, token string, resolution Resolution) (TaskSnapshot, error)
	Stop(processID string) (ProcessSnapshot, error)
	Retry(processID string, mode RetryMode) (ProcessSnapshot, error)
	Close(ctx context.Context) error
}
