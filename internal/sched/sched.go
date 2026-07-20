// Package sched is the scheduler seam: it decides *when* a process gets the
// CPU, while the app decides *what* runs (activation — typically journal
// replay) and the processor decides *how* (Resume). The default implementation
// is a fair-share scheduler with strict priority bands, round-robin across
// owners inside a band, per-owner concurrency quotas enforced as backpressure
// (never rejection), and virtual-actor residency in the Orleans/Golem sense:
// a process is activated on demand, kept warm while it may wake again, and
// the least recently used idle process is deactivated when residency exceeds
// its bound — the journal, not the instance, is the durable process.
package sched

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aurora-capcompute/capcompute"
)

var (
	ErrClosed           = errors.New("sched: scheduler is closed")
	ErrAlreadyScheduled = errors.New("sched: process is already scheduled")
	ErrStopped          = errors.New("sched: stopped before running")
)

// Priority is a strict band: everything runnable in a higher band goes first.
type Priority int

const (
	Low Priority = iota
	Normal
	High
)

// Quota bounds one owner's share (CHALLENGE B's aggregate half, M2.2).
type Quota struct {
	// MaxConcurrent bounds the owner's simultaneously running quanta.
	// 0 = unlimited. Excess work waits in queue — backpressure, not failure.
	MaxConcurrent int
}

// Config wires a Scheduler. Activate and Resume are required.
type Config[ID comparable, K capcompute.PID[ID]] struct {
	// Activate loads or reconstructs the process for a PID — for a durable
	// process, CreateProcess plus journal replay wiring. Called only when the
	// process is not resident.
	Activate func(ctx context.Context, pid ID) (*capcompute.Process[K], error)
	// Resume gives the process one quantum and returns its result stream —
	// usually a thin wrapper over Kernel.Resume.
	Resume func(ctx context.Context, process *capcompute.Process[K]) (<-chan capcompute.ResumeResult, error)
	// Deactivate releases a resident process (close the instance, keep the
	// journal). Called on eviction and when a process terminates. Optional.
	Deactivate func(pid ID, process *capcompute.Process[K])

	// QuotaOf reports an owner's quota. Nil means unlimited. Owners are the
	// fairness/quota aggregation keys (typically tenants) named at Submit.
	QuotaOf func(owner string) Quota

	// MaxConcurrent bounds simultaneously running quanta overall. 0 = 1:
	// uniprocessing is the default posture, concurrency is opt-in.
	MaxConcurrent int
	// MaxResident bounds warm processes (running ones never evict).
	// 0 = unlimited.
	MaxResident int
}

type entry[ID comparable, K capcompute.PID[ID]] struct {
	pid      ID
	owner    string
	priority Priority
	result   chan capcompute.ResumeResult
	// cancel aborts the running quantum; nil while queued.
	cancel context.CancelFunc
}

type resident[K any] struct {
	process *capcompute.Process[K]
	idle    *list.Element // position in the idle LRU; nil while running
}

// Scheduler is the default fair-share scheduler.
type Scheduler[ID comparable, K capcompute.PID[ID]] struct {
	config Config[ID, K]
	// root is the lifetime every quantum derives from. A Submit's context
	// governs admission only — tying a quantum to its submitter's context
	// would let one caller's cancellation kill unrelated queued work.
	root     context.Context
	stopRoot context.CancelFunc

	mu       sync.Mutex
	closed   bool
	entries  map[ID]*entry[ID, K]
	queues   [High + 1]*band[ID, K]
	running  int
	byOwner  map[string]int
	resident map[ID]*resident[K]
	idle     *list.List // of ID, front = most recently used
	quanta   sync.WaitGroup
}

// band is one priority level: per-owner FIFO queues served round-robin.
type band[ID comparable, K capcompute.PID[ID]] struct {
	order  *list.List // of string (owner), front = next to serve
	queues map[string][]*entry[ID, K]
}

func newBand[ID comparable, K capcompute.PID[ID]]() *band[ID, K] {
	return &band[ID, K]{order: list.New(), queues: make(map[string][]*entry[ID, K])}
}

func New[ID comparable, K capcompute.PID[ID]](config Config[ID, K]) (*Scheduler[ID, K], error) {
	if config.Activate == nil || config.Resume == nil {
		return nil, errors.New("sched: Activate and Resume are required")
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 1
	}
	root, stopRoot := context.WithCancel(context.Background())
	scheduler := &Scheduler[ID, K]{
		config:   config,
		root:     root,
		stopRoot: stopRoot,
		entries:  make(map[ID]*entry[ID, K]),
		byOwner:  make(map[string]int),
		resident: make(map[ID]*resident[K]),
		idle:     list.New(),
	}
	for priority := range scheduler.queues {
		scheduler.queues[priority] = newBand[ID, K]()
	}
	return scheduler, nil
}

// Submit queues one quantum for pid on behalf of owner — the fairness and
// quota aggregation key, typically the tenant ("" = anonymous) — and returns
// the channel its result will arrive on. A PID has at most one outstanding
// submission: waking a process that is already queued or running is
// ErrAlreadyScheduled.
func (s *Scheduler[ID, K]) Submit(ctx context.Context, pid ID, owner string, priority Priority) (<-chan capcompute.ResumeResult, error) {
	if priority < Low || priority > High {
		return nil, fmt.Errorf("sched: invalid priority %d", priority)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if _, scheduled := s.entries[pid]; scheduled {
		return nil, ErrAlreadyScheduled
	}

	submitted := &entry[ID, K]{
		pid:      pid,
		owner:    owner,
		priority: priority,
		result:   make(chan capcompute.ResumeResult, 1),
	}
	s.entries[pid] = submitted
	s.enqueue(submitted)
	s.schedule()
	return submitted.result, nil
}

// Close stops admission and waits for running quanta to finish. Queued work
// that never ran receives a stopped result.
func (s *Scheduler[ID, K]) Close() {
	s.mu.Lock()
	s.closed = true
	for _, band := range s.queues {
		for owner, queue := range band.queues {
			for _, queued := range queue {
				queued.result <- capcompute.ResumeResult{Status: capcompute.ResumeStopped, Err: ErrClosed}
				delete(s.entries, queued.pid)
			}
			delete(band.queues, owner)
		}
		band.order.Init()
	}
	s.mu.Unlock()
	s.quanta.Wait()

	s.mu.Lock()
	for pid, warm := range s.resident {
		s.dropResident(pid, warm)
	}
	s.mu.Unlock()
	s.stopRoot()
}

// Stop aborts pid's outstanding submission: a queued quantum is dequeued and
// delivered a stopped result; a running one has its context cancelled — the
// processor kills the guest and the stopped result flows out the normal way.
// Returns false when pid has no outstanding submission.
func (s *Scheduler[ID, K]) Stop(pid ID) bool {
	s.mu.Lock()
	scheduled, ok := s.entries[pid]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if scheduled.cancel != nil {
		cancel := scheduled.cancel
		s.mu.Unlock()
		cancel()
		return true
	}
	s.dequeue(scheduled)
	delete(s.entries, pid)
	s.mu.Unlock()
	scheduled.result <- capcompute.ResumeResult{Status: capcompute.ResumeStopped, Err: ErrStopped}
	return true
}

// dequeue removes a queued entry from its band. Caller holds the lock.
func (s *Scheduler[ID, K]) dequeue(queued *entry[ID, K]) {
	band := s.queues[queued.priority]
	queue := band.queues[queued.owner]
	kept := queue[:0]
	for _, waiting := range queue {
		if waiting != queued {
			kept = append(kept, waiting)
		}
	}
	if len(kept) == 0 {
		delete(band.queues, queued.owner)
		for element := band.order.Front(); element != nil; element = element.Next() {
			if element.Value.(string) == queued.owner {
				band.order.Remove(element)
				break
			}
		}
	} else {
		band.queues[queued.owner] = kept
	}
}

// Resident reports how many processes are currently activated.
func (s *Scheduler[ID, K]) Resident() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.resident)
}

func (s *Scheduler[ID, K]) enqueue(queued *entry[ID, K]) {
	band := s.queues[queued.priority]
	if _, exists := band.queues[queued.owner]; !exists {
		band.order.PushBack(queued.owner)
	}
	band.queues[queued.owner] = append(band.queues[queued.owner], queued)
}

// schedule starts quanta while capacity remains: highest band first, owners
// round-robin within it, skipping owners at their concurrency quota. Every
// quantum derives from the scheduler's root lifetime, never from a caller's
// context. Caller holds the lock.
func (s *Scheduler[ID, K]) schedule() {
	for s.running < s.config.MaxConcurrent {
		next := s.pick()
		if next == nil {
			return
		}
		s.running++
		s.byOwner[next.owner]++
		quantumCtx, cancel := context.WithCancel(s.root)
		next.cancel = cancel
		s.quanta.Add(1)
		go s.runQuantum(quantumCtx, next)
	}
}

func (s *Scheduler[ID, K]) pick() *entry[ID, K] {
	for priority := High; priority >= Low; priority-- {
		band := s.queues[priority]
		for element, visited := band.order.Front(), 0; element != nil && visited < band.order.Len(); visited++ {
			owner := element.Value.(string)
			if s.atQuota(owner) {
				element = element.Next()
				continue
			}
			queue := band.queues[owner]
			picked := queue[0]
			if len(queue) == 1 {
				delete(band.queues, owner)
				next := element.Next()
				band.order.Remove(element)
				element = next
			} else {
				band.queues[owner] = queue[1:]
				band.order.MoveToBack(element)
			}
			return picked
		}
	}
	return nil
}

func (s *Scheduler[ID, K]) atQuota(owner string) bool {
	if s.config.QuotaOf == nil {
		return false
	}
	quota := s.config.QuotaOf(owner)
	return quota.MaxConcurrent > 0 && s.byOwner[owner] >= quota.MaxConcurrent
}

// runQuantum owns one process quantum end to end: activate if cold, resume,
// deliver the result, retire or evict, then let the next quantum start.
func (s *Scheduler[ID, K]) runQuantum(ctx context.Context, running *entry[ID, K]) {
	defer s.quanta.Done()
	defer running.cancel()

	process, err := s.checkout(ctx, running)
	if err != nil {
		s.finish(running, nil, capcompute.ResumeResult{Status: capcompute.ResumeFailed, Err: err})
		return
	}
	results, err := s.config.Resume(ctx, process)
	if err != nil {
		s.finish(running, process, capcompute.ResumeResult{Status: capcompute.ResumeFailed, Err: err})
		return
	}
	s.finish(running, process, <-results)
}

// checkout returns the warm process or activates a cold one, marking it
// non-idle for the duration of the quantum.
func (s *Scheduler[ID, K]) checkout(ctx context.Context, running *entry[ID, K]) (*capcompute.Process[K], error) {
	s.mu.Lock()
	if warm, ok := s.resident[running.pid]; ok {
		if warm.idle != nil {
			s.idle.Remove(warm.idle)
			warm.idle = nil
		}
		s.mu.Unlock()
		return warm.process, nil
	}
	s.mu.Unlock()

	process, err := s.config.Activate(ctx, running.pid)
	if err != nil {
		return nil, fmt.Errorf("activate %v: %w", running.pid, err)
	}

	s.mu.Lock()
	s.resident[running.pid] = &resident[K]{process: process}
	s.mu.Unlock()
	return process, nil
}

// finish releases the quantum's slot, delivers its result, and applies the
// actor lifecycle: a yielded process stays warm (subject to eviction); a
// terminated one is deactivated immediately.
func (s *Scheduler[ID, K]) finish(ran *entry[ID, K], process *capcompute.Process[K], result capcompute.ResumeResult) {
	s.mu.Lock()
	s.running--
	s.byOwner[ran.owner]--
	if s.byOwner[ran.owner] <= 0 {
		delete(s.byOwner, ran.owner)
	}
	delete(s.entries, ran.pid)

	if warm, ok := s.resident[ran.pid]; ok && process != nil {
		if result.Status == capcompute.ResumeYielded {
			warm.idle = s.idle.PushFront(ran.pid)
			s.evictOverflow()
		} else {
			s.dropResident(ran.pid, warm)
		}
	}
	if !s.closed {
		s.schedule()
	}
	s.mu.Unlock()

	ran.result <- result
}

// evictOverflow deactivates least-recently-used idle processes until
// residency fits. Running processes never evict.
func (s *Scheduler[ID, K]) evictOverflow() {
	if s.config.MaxResident <= 0 {
		return
	}
	for len(s.resident) > s.config.MaxResident && s.idle.Len() > 0 {
		oldest := s.idle.Back()
		pid := oldest.Value.(ID)
		s.dropResident(pid, s.resident[pid])
	}
}

func (s *Scheduler[ID, K]) dropResident(pid ID, warm *resident[K]) {
	if warm.idle != nil {
		s.idle.Remove(warm.idle)
	}
	delete(s.resident, pid)
	if s.config.Deactivate != nil {
		s.config.Deactivate(pid, warm.process)
	}
}
