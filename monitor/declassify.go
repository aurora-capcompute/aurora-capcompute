package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/aurora-capcompute/capcompute/sys"
)

// DeclassifyRequest is the args payload of the reserved sys.declassify
// syscall: which labels to lift from the run's taint, and why — the reason is
// required because it is what the approving human reads and what the journal
// preserves.
type DeclassifyRequest struct {
	Labels []string `json:"labels"`
	Reason string   `json:"reason"`
}

// DeclassifyResult is the journaled outcome of an approved declassification.
type DeclassifyResult struct {
	Declassified []string `json:"declassified"`
}

// DeclassifyInputSchema is the shape of sys.declassify's arguments, the schema
// the Validator admits the call against.
var DeclassifyInputSchema = json.RawMessage(`{
	"type": "object",
	"required": ["labels", "reason"],
	"properties": {
		"labels": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
		"reason": {"type": "string", "minLength": 1}
	},
	"additionalProperties": false
}`)

// Declassifier serves sys.declassify: lifting labels from a run's taint, as a
// governed operation. Every request needs a human's approval. The approved
// result is journaled, so a replay applies it again without asking. It sits
// below the layer that turns a yield into a durable task, so the approval
// reaches it. Flow.Guard above removes the labels when the result passes.
type Declassifier[K any] struct {
	next sys.Dispatcher[K]
}

func NewDeclassifier[K any](next sys.Dispatcher[K]) *Declassifier[K] {
	return &Declassifier[K]{next: next}
}

func (d *Declassifier[K]) Dispatch(ctx context.Context, cred K, syscall sys.Syscall, auth sys.Authorization) (sys.SyscallResult, error) {
	if syscall.Name != sys.SyscallDeclassify {
		return d.next.Dispatch(ctx, cred, syscall, auth)
	}
	var request DeclassifyRequest
	if err := json.Unmarshal(syscall.Args, &request); err != nil {
		return sys.FailCode(sys.ErrnoInvalidArgs, fmt.Sprintf("decode declassify args: %v", err)), nil
	}
	// The Validator held the arguments to DeclassifyInputSchema. A schema cannot
	// refuse a reason that is only spaces.
	if strings.TrimSpace(request.Reason) == "" {
		return sys.FailCode(sys.ErrnoInvalidArgs, "declassify: a reason is required"), nil
	}
	if auth.Decision != sys.Approved {
		return sys.Yield(fmt.Sprintf("Approve declassifying %v: %s", request.Labels, request.Reason)), nil
	}

	result, _ := json.Marshal(DeclassifyResult{Declassified: slices.Sorted(slices.Values(request.Labels))})
	return sys.Result(result), nil
}
