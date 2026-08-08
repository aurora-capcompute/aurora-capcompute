package process

import (
	"context"

	"github.com/aurora-capcompute/capcompute"
	"github.com/aurora-capcompute/capcompute/sys"
)

type Status string

type Result struct {
	Status Status
	Error  error
}

type processHandle struct {
	inner *capcompute.ResumeHandle
}

func (h processHandle) Result() <-chan Result {
	return mapChannel(h.inner.Results, func(r capcompute.ResumeResult) Result {
		return Result{Status: Status(r.Status), Error: r.Err}
	})
}

func (h processHandle) Cancel() {
	h.inner.Cancel()
}

type Handle interface {
	Result() <-chan Result
	Cancel()
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
		return nil, err
	}

	return processHandle{inner: handle}, nil
}

func mapChannel[T, U any](in <-chan T, f func(T) U) <-chan U {
	out := make(chan U)
	go func() {
		defer close(out)
		for v := range in {
			out <- f(v)
		}
	}()
	return out
}
