package journaled

import (
	"fmt"

	"github.com/aurora-capcompute/capcompute/sys"
)

// Effect is one completed, successful syscall from the journal's execution
// section — the unit saga unwinding may need to undo.
type Effect struct {
	Position int
	Syscall  sys.Syscall
	Result   sys.SyscallResult
}

// OpenCompensation is a compensation intent with no completion at the journal
// tail: an unwind crashed (or yielded) mid-compensation. The caller
// re-dispatches Syscall under the same Key, then commits.
type OpenCompensation struct {
	Compensates int
	Key         string
	Syscall     sys.Syscall
}

// Compensator appends the compensation section of a journal. It owns the
// record mechanics (kinds, hash chain, idempotency keys); the walk order and
// the decision of *what* to compensate live with the caller's unwinder.
type Compensator struct {
	journal Journal
	header  Header
	pending bool
}

// NewCompensator opens a journal for unwinding. The journal must already have
// a header — only a process that executed something can be unwound.
func NewCompensator(journal Journal) (*Compensator, error) {
	header, ok, err := journal.Header()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("compensator: journal has no header")
	}
	return &Compensator{journal: journal, header: header}, nil
}

// Effects returns the completed, successful effects at position >= from that
// have not yet been compensated, newest first — the unwinding order. If the
// journal tail holds an open compensation intent, it is returned as resume;
// the caller must resolve it (re-dispatch under resume.Key, then Commit)
// before compensating anything else.
func (c *Compensator) Effects(from int) (effects []Effect, resume *OpenCompensation, err error) {
	length := c.journal.Length()
	var executed []Effect
	compensated := make(map[int]bool)

	for position := 0; position < length; position++ {
		record, err := c.journal.Load(position)
		if err != nil {
			return nil, nil, err
		}
		switch record.Kind {
		case KindIntent:
			if record.Syscall == nil {
				return nil, nil, CorruptJournalError{Position: position, Reason: "intent record missing syscall"}
			}
			if position+1 >= length {
				continue // open execution intent: indeterminate, never mechanically compensated
			}
			next, err := c.journal.Load(position + 1)
			if err != nil {
				return nil, nil, err
			}
			if next.Kind != KindCompletion {
				continue // abandoned open intent before the compensation section
			}
			if next.Result != nil && next.Result.Status() == sys.StatusResult {
				executed = append(executed, Effect{
					Position: record.Position,
					Syscall:  *record.Syscall,
					Result:   *next.Result,
				})
			}
			position++ // the completion is consumed

		case KindCompensationIntent:
			if record.Syscall == nil || record.Compensates == nil {
				return nil, nil, CorruptJournalError{Position: position, Reason: "compensation intent missing payload"}
			}
			compensated[*record.Compensates] = true
			if position+1 >= length {
				key, err := intentKey(c.header, record)
				if err != nil {
					return nil, nil, err
				}
				resume = &OpenCompensation{
					Compensates: *record.Compensates,
					Key:         key,
					Syscall:     *record.Syscall,
				}
				c.pending = true
				continue
			}
			position++ // the compensation completion is consumed
		}
	}

	for i := len(executed) - 1; i >= 0; i-- {
		effect := executed[i]
		if effect.Position >= from && !compensated[effect.Position] {
			effects = append(effects, effect)
		}
	}
	return effects, resume, nil
}

// Begin appends the compensation intent for one effect — before the inverse
// executes — and returns its idempotency key.
func (c *Compensator) Begin(inverse sys.Syscall, compensates int) (string, error) {
	if c.pending {
		return "", fmt.Errorf("compensator: a compensation is already open")
	}
	recorded := inverse.Copy()
	stored, err := appendChained(c.journal, c.header, Record{
		Kind:        KindCompensationIntent,
		Compensates: &compensates,
		Syscall:     &recorded,
	})
	if err != nil {
		return "", err
	}
	c.pending = true
	return intentKey(c.header, stored)
}

// Commit appends the completion for the open compensation intent.
func (c *Compensator) Commit(result sys.SyscallResult) error {
	if !c.pending {
		return fmt.Errorf("compensator: no open compensation to commit")
	}
	if result.Status() != sys.StatusResult && result.Status() != sys.StatusFailed {
		return fmt.Errorf("cannot commit invalid compensation result %q", result.Status())
	}
	recorded := result.Copy()
	if _, err := appendChained(c.journal, c.header, Record{Kind: KindCompensationCompletion, Result: &recorded}); err != nil {
		return err
	}
	c.pending = false
	return nil
}
