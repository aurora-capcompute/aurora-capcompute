package processor

import (
	"context"
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct/program"
	"github.com/aurora-capcompute/aurora-capcompute/internal/sched"
	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

func MakeProcess(
	ctx context.Context,
	tenantID string,
	proc *processState,
	artifact program.Artifact,
	mkDispatcher func(context.Context, ProcessContext) (sys.Dispatcher[ProcessContext], error),
) (*capcompute.Process[ProcessContext], error) {
	if proc == nil {
		return nil, fmt.Errorf("no process to instantiate capcompute process from")
	}
	cred := ProcessContext{
		TenantID:  tenantID,
		SessionID: proc.sessionID,
		ProcessID: proc.id,
		Revision:  proc.revision,
	}

	if artifact.Digest != proc.programDigest {
		return nil, fmt.Errorf(
			"program %q changed (loaded %s, process bound to %s): a process is immutable — its code and interface are fixed; spawn a new process from the new program, or kill this one to settle its effects",
			proc.manifest.Program, artifact.Digest, proc.programDigest)
	}
	chain, err := mkDispatcher(ctx, cred)
	if err != nil {
		return nil, err
	}
	process, err := capcompute.NewProcess(ctx, artifact.Image, capcompute.ProcessSpec[ProcessContext]{
		Entrypoint: "run",
		Cred:       cred,
		Dispatcher: chain,
	})
	if err != nil {
		return nil, err
	}
	return process, nil
}

func ResumeProcess(ctx context.Context, process *capcompute.Process[ProcessContext]) (sched.Result, error) {
	handle, err := capcompute.Resume(ctx, process)
	if err != nil {
		return sched.Result{}, err
	}
	return toResult(<-handle.Results()), nil
}

func ReleaseProcess(process *capcompute.Process[ProcessContext]) {
	_ = process.Close(context.Background())
}
