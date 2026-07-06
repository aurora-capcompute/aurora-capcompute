# aurora-capcompute

Implementation-neutral Aurora orchestration runtime on the
[`capcompute`](https://github.com/aurora-capcompute/capcompute) kernel.

The module owns session and process lifecycle, the intent/completion replay
journal over the event log, durable approval tasks, retries, delegation to
child agents, process scheduling, event subscriptions, and execution of
caller-supplied
Wasm programs. All durable state is a fold of a single append-only event log —
the runtime keeps no mutable row store.

**A final product is an assembly, not part of this module.** The core stays
free of anything product-specific; this module ships interfaces and
orchestration only. It does not provide:

- LLM, internet, Kubernetes, Helm, MCP, or other capability drivers.
- Dispatcher registries or capability-specific manifest settings.
- Concrete stores: no in-memory or SQLite event log, leases, or process table.
- Communication channels (chat bridges, HTTP APIs) — how a distribution talks
  to its users is that distribution's concern, never the runtime's.
- Filesystem or remote program loaders, a CLI, or environment-based wiring.

A distribution is a `main()` that picks its ingredients: this runtime, a store
module (e.g. `aurora-stores`), driver modules (e.g. `aurora-dispatchers`), and
its own channels and control plane.

## Required dependencies

`aurora.NewRuntime` requires all implementation dependencies:

```go
runtime, err := aurora.NewRuntime(ctx, aurora.Config{
    Programs:     programProvider,
    Dispatchers:  dispatcherProvider,
    Log:          eventLog,
    Leases:       leases,
    ProcessTable: processTable, // capcompute.ProcessTable[string, aurora.ProcessContext]
    TaskSecret:   taskSecret,
})
```

Construction fails when any required dependency is missing. The runtime owns
and closes compiled kernels and guest processes. Callers retain ownership of
injected stores and providers.

## The kernel chain

Every process's syscalls flow through the kernel's canonical monitor chain,
assembled by `capcompute.Stack.ForProcess` — never by hand:

```
Validator → FlowMonitor → [replay over the process's journal] →
Labeler → Declassifier → savepoints → lifecycle → delegation → tasks → progress → drivers
```

- **Complete mediation** — the Validator admits only granted capability names
  (schema-checked args); the grant set is exactly the chain's published
  surface, the runtime's own protocol calls (`sys.input`, `sys.output`,
  `sys.log`, `sys.compensate`, `sys.abort`) included, hidden from the
  program's menu but granted explicitly.
- **Journal** — each syscall is journaled as an intent before it executes and
  a completion before the guest observes it, hash-chained, in the session's
  event stream (`syscall.recorded` events; a `journal.header` event pins the
  writer identity per revision, so replaying under a different program digest is
  refused up front). Retries fork the journal copy-on-write into a new
  revision; a failed process resumes right after the outermost open `sys.begin`
  savepoint so the program's whole declared unit re-executes.
- **Rollback** — a guest registers an effect's undo with `sys.compensate` (a
  deferred syscall journaled with concrete guest-supplied args) and rolls the
  open section back with `sys.abort{reason, retry_seconds}`: the runtime
  executes the registered compensations newest-first (journaled,
  idempotency-keyed, crash-resumable), then re-runs the section after the
  delay — parked on a durable retry timer — or finishes the process as
  `compensated`. A compensation that fails semantically fails the process with
  the rollback report; the journal is the remediation map.
- **Approval** — a yielded syscall becomes a durable task and leaves its
  intent open; resolving the task re-drives the intent under its original
  idempotency key with the stored resolution as the dispatch Authorization.
  This is the approval-injection seam the kernel deliberately leaves to the
  runtime.
- **Scheduling** — root processes are quanta of the kernel's fair-share
  scheduler (per-tenant round-robin, quotas via `Config.QuotaOf`,
  virtual-actor residency with reactivation by replay). Delegated child
  processes execute inside
  their parent's quantum — the kernel's sync-spawn posture — so delegation
  cannot deadlock the concurrency cap. The runtime's event-sourced retry
  machinery is the supervision layer; `sched.Supervisor` is deliberately not
  layered underneath it.

## Program provider

A program provider supplies immutable Wasm bytes:

```go
type ProgramProvider interface {
    DefaultID() string
    List(context.Context) ([]aurora.ProgramSource, error)
}
```

The runtime copies the bytes, computes SHA-256 digests, and immutably binds
each process to the (name, digest) it was created from — a process is an audit
target, so it never resumes or restarts under different bytes. Filesystem,
object-store, embedded, and remote loaders belong in application or adapter
modules. Programs can be hot-swapped at runtime with `Runtime.SetPrograms`;
swapped bytes serve new processes, while in-flight processes of the old digest
are stranded (killable, auditable — never silently migrated).

## Dispatcher provider

A dispatcher provider owns capability-specific settings and implementation:

```go
type DispatcherProvider interface {
    Normalize(name string, settings json.RawMessage) (json.RawMessage, error)
    NewDispatcher(
        context.Context,
        aurora.ProcessContext,
        aurora.Manifest,
    ) (sys.Dispatcher[aurora.RunContext], error)
}
```

The core validates and normalizes manifests through this provider. For each
process, it completes the returned driver chain with the monitor stack above.

## Storage contracts

State is event-sourced. The application supplies one append-only log; the
runtime appends domain events and folds them back into projections on restore.

```go
type EventLog interface {
    Append(ctx context.Context, scope LogScope, events ...LogEvent) (head uint64, err error)
    Read(ctx context.Context, scope LogScope, after uint64) ([]LogEvent, error)
    Streams(ctx context.Context, tenantID string) ([]LogScope, error)
}
```

One stream per session carries every process, task, journal-record, and
journal-header event. There is no mutable row store: sessions, processes,
tasks, and the replay journal are all projections of the log. Cross-instance coordination
uses a separate `Leases` interface — an ephemeral fencing token with a TTL,
kept out of a session's immutable history. Guest instances are looked up
through the kernel's `capcompute.ProcessTable[string, aurora.ProcessContext]`
seam; the journal, not the instance, is the durable process.

Concrete implementations (in-memory, SQLite) live in the `aurora-dist`
distribution (they folded there from the deprecated `aurora-stores`); this
module's tests carry local doubles.

## Manifest helpers

Manifest validation requires the same dispatcher provider used by the runtime:

```go
validated, err := aurora.ValidateManifest(manifest, dispatcherProvider)
```

Aurora defines only the generic grant envelope (`syscall`, `settings`, and
`programs` — nested manifests — for `core.spawn`); nothing is named, and each
driver publishes its canonical capability names. The provider decides which
syscalls and settings are valid.

## Verification

```sh
go vet ./...
go test -race ./...
```

The runtime integration tests build the Rust agent program from the sibling
`aurora-brains` checkout (`cargo build --target wasm32-wasip1`) and skip when
the toolchain is unavailable.
