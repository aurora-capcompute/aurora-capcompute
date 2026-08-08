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

type processHandle[T any] struct {
	inner   *capcompute.ResumeHandle
	process *capcompute.Process[T]
}

func (h processHandle[T]) Result() <-chan Result {
	return mapChannel(h.inner.Results, func(r capcompute.ResumeResult) Result {
		return Result{Status: Status(r.Status), Error: r.Err}
	})
}

func (h processHandle[T]) Cancel() {
	h.inner.Cancel()
}

// Release closes the instance once its quantum has ended. An instance never
// outlives its quantum: the journal is the durable process, so nothing of the
// guest crosses into the next one.
func (h processHandle[T]) Release() {
	_ = h.process.Close(context.Background())
}

type Handle interface {
	Result() <-chan Result
	Cancel()
	Release()
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

	return processHandle[T]{inner: handle, process: process}, nil
}

func mapChannel[T, U any](in <-chan T, f func(T) U) <-chan U {
	out := make(chan U, 1)
	go func() {
		defer close(out)
		for v := range in {
			out <- f(v)
		}
	}()
	return out
}
