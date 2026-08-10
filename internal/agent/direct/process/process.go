package process

import (
	"context"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

type Status string

const (
	Completed = Status(capcompute.ResumeCompleted)
	Yielded   = Status(capcompute.ResumeYielded)
	Stopped   = Status(capcompute.ResumeStopped)
	Failed    = Status(capcompute.ResumeFailed)
)

type Result struct {
	Status Status
	Error  error
}

type Handle interface {
	Result() <-chan Result
}

func Spawn[T any](
	ctx context.Context,
	proc T,
	image *capcompute.Program,
	mkDispatcher func(context.Context, T) (sys.Dispatcher[T], error),
) (Handle, error) {
	chain, err := mkDispatcher(ctx, proc)
	if err != nil {
		return nil, err
	}
	process, err := capcompute.NewProcess(ctx, image, capcompute.ProcessSpec[T]{
		Entrypoint: "run",
		Cred:       proc,
		Dispatcher: chain,
	})
	if err != nil {
		return nil, err
	}

	handle, err := capcompute.Resume(ctx, process)
	if err != nil {
		_ = process.Close(context.Background())
		return nil, err
	}

	// The instance is closed as its quantum ends, before the outcome is handed
	// on: an instance never outlives its quantum, so dropping the handle cannot
	// leak one. Buffered, so this finishes whether or not anyone reads.
	out := make(chan Result, 1)
	go func() {
		defer close(out)
		for r := range handle.Results {
			_ = process.Close(context.Background())
			out <- Result{Status: Status(r.Status), Error: r.Err}
		}
	}()
	return processHandle{inner: handle, results: out}, nil
}

type processHandle struct {
	inner   *capcompute.ResumeHandle
	results <-chan Result
}

func (h processHandle) Result() <-chan Result { return h.results }
