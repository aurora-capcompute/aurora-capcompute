package agent

import (
	"capcompute/dispatcher"
	"context"
	"encoding/json"
	"fmt"
)

type progressDispatcher struct {
	next     dispatcher.Dispatcher[RunContext]
	publish  func(threadID string, event Event)
	threadID string
	runID    string
}

type progressArgs struct {
	Message string `json:"message"`
}

func newProgressDispatcher(next dispatcher.Dispatcher[RunContext], publish func(string, Event), threadID, runID string) *progressDispatcher {
	return &progressDispatcher{next: next, publish: publish, threadID: threadID, runID: runID}
}

func (d *progressDispatcher) Dispatch(ctx context.Context, key RunContext, call dispatcher.Call) (dispatcher.Outcome, error) {
	if call.Name == "aurora.log" {
		var args progressArgs
		if err := json.Unmarshal(call.Args, &args); err != nil {
			return dispatcher.Failed(fmt.Sprintf("decode aurora.log: %v", err)), nil
		}
		d.publish(d.threadID, Event{
			Type: "progress",
			Data: ProgressEvent{RunID: d.runID, Message: args.Message},
		})
		return dispatcher.Result(json.RawMessage(`{}`)), nil
	}
	return d.next.Dispatch(ctx, key, call)
}

func (d *progressDispatcher) Capabilities() []dispatcher.Capability {
	return dispatcher.Capabilities(d.next)
}

func hasCapability(manifest Manifest, name string) bool {
	for _, cap := range manifest.Capabilities {
		if cap.Name == name {
			return true
		}
	}
	return false
}

type ProgressEvent struct {
	RunID   string `json:"run_id"`
	Message string `json:"message"`
}
