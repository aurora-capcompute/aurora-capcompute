package monitor

// In-memory test doubles for the processor's store interfaces. The processor ships
// interfaces only (Journal, ProcessTable); durable implementations live in
// consumer modules, and tests supply these.

import (
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
)

// testCred is the monitor tests' credential: comparable, so it keys the taint.
type testCred struct{ id string }

// memJournal is an in-memory journaled.Journal.
type memJournal struct {
	records []journaled.Record
}

func newMemJournal() *memJournal { return &memJournal{} }

func (j *memJournal) Load(idx int) (journaled.Record, error) {
	if idx < 0 || idx >= len(j.records) {
		return journaled.Record{}, fmt.Errorf("journal: no record at %d", idx)
	}
	return j.records[idx], nil
}

func (j *memJournal) Append(record journaled.Record) error {
	j.records = append(j.records, record)
	return nil
}

func (j *memJournal) Length() int { return len(j.records) }
