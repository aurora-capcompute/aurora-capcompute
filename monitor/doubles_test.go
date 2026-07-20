package monitor

// In-memory test doubles for the processor's store interfaces. The processor ships
// interfaces only (Journal, ProcessTable); durable implementations live in
// consumer modules, and tests supply these.

import (
	"fmt"

	"github.com/aurora-capcompute/aurora-capcompute/journaled"
)

// memJournal is an in-memory journaled.Journal.
type memJournal struct {
	header    journaled.Header
	hasHeader bool
	records   []journaled.Record
}

// testPID is the monitor tests' credential double.
type testPID struct{ id string }

func (p testPID) PID() string { return p.id }

func newMemJournal() *memJournal { return &memJournal{} }

func (j *memJournal) Header() (journaled.Header, bool, error) { return j.header, j.hasHeader, nil }

func (j *memJournal) SetHeader(header journaled.Header) error {
	j.header = header
	j.hasHeader = true
	return nil
}

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
