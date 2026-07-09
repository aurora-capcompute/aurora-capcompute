# aurora-capcompute

**The engine that runs durable, crash‑proof AI agents.** `aurora-capcompute` is a
Go library that turns the [`capcompute`](https://github.com/aurora-capcompute/capcompute)
kernel into a full agent runtime: it runs Wasm agent programs as long‑lived
**processes** inside **sessions**, and makes every action they take recorded,
resumable, reversible, and approval‑gated.

> New here? The first two sections tell you what this is and where it fits. If you
> just want to *run* Aurora, you don't start here — you run
> [aurora-dist](https://github.com/aurora-capcompute/aurora-dist). This repo is the
> library that server is built from.

---

## What is this, in plain words?

[`capcompute`](https://github.com/aurora-capcompute/capcompute) (the kernel) knows
how to run one sandboxed Wasm program and mediate its syscalls. But a *real* agent
needs much more: it has to survive crashes and pick up exactly where it left off,
retry safely, roll back half‑finished work, pause for a human to approve a
sensitive action, delegate to sub‑agents, and keep a full audit trail — all without
you writing that plumbing yourself.

`aurora-capcompute` is that plumbing. It owns **sessions and processes**, the
**replay journal**, **retries**, **rollback (sagas)**, **durable approval tasks**,
**delegation to child agents**, **scheduling**, and **event subscriptions**. Its
trick: there is **no database of mutable rows**. All durable state is a *fold of a
single append‑only event log per session* (event sourcing) — so the state is always
reconstructible, auditable, and replayable.

**It ships interfaces and orchestration only.** By design it does *not* include LLM
or internet drivers, concrete databases, chat bridges, HTTP APIs, or a CLI. A real
product is an *assembly* — a `main()` that plugs in the concrete pieces. That
assembly is [aurora-dist](https://github.com/aurora-capcompute/aurora-dist).

## Where this fits in the Aurora system

```
        you (a human)
              │
   aurora-cli / aurora-slack-connector      ← clients you talk to
              │  HTTP /v1
         aurora-dist                         ← the server (one binary you run)
              │  assembled from…
   ┌──────────┴──────────┐
 aurora-capcompute    aurora-dispatchers     ← orchestration runtime + capability drivers
 ◀ YOU ARE HERE
   └──────────┬──────────┘
              │  both built on
         capcompute                          ← the kernel (the foundation)

   aurora-brains  →  the Wasm agent "programs" that run inside
```

- **[capcompute](https://github.com/aurora-capcompute/capcompute)** — the kernel
  below this: sandboxing, the syscall gate, the journal, replay.
- **aurora-capcompute (this repo)** — the orchestration runtime *on top* of the
  kernel: sessions, retries, approvals, delegation, scheduling.
- **[aurora-dispatchers](https://github.com/aurora-capcompute/aurora-dispatchers)** —
  the concrete drivers you inject (`core.internet`, `core.openaiApi`, …).
- **[aurora-brains](https://github.com/aurora-capcompute/aurora-brains)** — the
  Wasm agent programs that run as processes inside this runtime.
- **[aurora-dist](https://github.com/aurora-capcompute/aurora-dist)** — the `main()`
  that wires this runtime to concrete stores + drivers + an HTTP API.

## What it does for you (features)

| Feature | What it means |
| --- | --- |
| **Sessions & processes** | `CreateSession`, `CreateProcess`, `Stop`, `Retry`, `RenameSession`, list/read — the full agent lifecycle |
| **Replay journal** | Every syscall is hash‑chained into the log as an *intent* then a *completion*, so a crashed process re‑drives deterministically |
| **Tamper‑evidence** | A `journal.header` pins the program's identity per revision; replaying under changed code is refused |
| **Retries** | Resume the same revision, or restart into a fresh copy‑on‑write revision; bounded abort‑retry budget |
| **Rollback / sagas** | Guests register undo actions (`sys.compensate`) and unwind with `sys.abort`; compensations run newest‑first, idempotent, crash‑resumable |
| **Human‑in‑the‑loop** | A yielded syscall becomes a durable **task** with a secret resolution token; `ResolveTask` re‑drives the original intent |
| **Delegation** | `sys.spawn` starts granted sub‑programs as tracked child processes, with attenuated authority |
| **Fair scheduling** | Per‑tenant round‑robin quanta, quotas, virtual‑actor residency (reactivated by replay) |
| **Subscriptions** | `Subscribe(sessionID)` streams live events (snapshots, process/task updates, journal, progress) |
| **Capability security** | Only granted, schema‑checked syscalls are admitted; the runtime fails closed if a driver over‑advertises what it can do |
| **Program contracts** | Each program ships a manifest (description + input/output JSON Schemas), validated at registration and on every call |
| **Hot‑swap** | `SetPrograms` reconciles the loaded Wasm set at runtime; in‑flight processes stay bound to their original code identity |

## Quick start (5 minutes)

This is a **library** — there's no binary, no config file, no port. "Setup" means
verifying the module and running its tests (which exercise a real Wasm agent).

**Prerequisites:** Go 1.26+. Optional, for the integration tests: a Rust toolchain
with the `wasm32-wasip1` target and a sibling `aurora-brains` checkout — the tests
build a real agent from it and **skip** if it's missing.

```sh
git clone https://github.com/aurora-capcompute/aurora-capcompute
cd aurora-capcompute

go vet ./...
go test -race ./...             # full suite
go test -race ./internal/agent/... # just the runtime engine
```

To let the integration tests run a real agent:

```sh
rustup target add wasm32-wasip1
# put an aurora-brains checkout beside this repo; the test builds it with:
#   cargo build --target wasm32-wasip1   →   release/agent.wasm (+ echo.wasm)
```

To actually run a live Aurora server, you don't use this repo directly — build and
run [aurora-dist](https://github.com/aurora-capcompute/aurora-dist), then point
[aurora-cli](https://github.com/aurora-capcompute/aurora-cli) at it.

## Example: constructing the runtime

The entry point is a function call, not a command. You inject every implementation
dependency — construction fails if any required one is missing:

```go
runtime, err := aurora.NewRuntime(ctx, aurora.Config{
    Programs:     programProvider,   // supplies each agent's Wasm bytes + interface manifest
    Dispatchers:  dispatcherProvider,// capability drivers (from aurora-dispatchers)
    Log:          eventLog,          // the append-only event store (in-memory or SQLite)
    Leases:       leases,            // cross-instance fencing tokens
    ProcessTable: processTable,      // capcompute.ProcessTable[string, aurora.ProcessContext]
    TaskSecret:   taskSecret,        // non-empty []byte, keys the task resolution tokens
})
if err != nil {
    return err
}

// Then drive it:
sess, _ := runtime.CreateSession(ctx, /* … */)
proc, _ := runtime.CreateProcess(ctx, sess.ID, input, manifest) // manifest.Version must be 4
events, _ := runtime.Subscribe(ctx, sess.ID)                    // watch it run
// … and runtime.ResolveTask(...) when a human approves a pending task.
```

A **program provider** supplies each program's immutable Wasm bytes plus its
interface manifest (a description and JSON Schemas for input/output). The runtime
computes a content identity (SHA‑256 over the Wasm *and* its manifest) and binds
each process to it forever — a process never resumes under changed code.

A **dispatcher provider** owns capability‑specific settings and builds the driver
chain for each process. Aurora defines only the generic grant envelope (`syscall`,
`settings`, nested `programs`); each driver publishes its own capability names.

## How it works: the kernel chain

Every process's syscalls flow through a fixed monitor chain (assembled by
`capcompute.Stack.ForProcess`, never by hand):

```
Validator → FlowMonitor → [replay over the journal] →
Labeler → Declassifier → savepoints → lifecycle → delegation → tasks → progress → drivers
```

- **Complete mediation** — the Validator admits only granted, schema‑checked
  syscall names; the runtime's own protocol calls (`sys.input`, `sys.output`,
  `sys.log`, `sys.compensate`, `sys.abort`, …) are granted explicitly but hidden
  from the program's menu.
- **Journal** — each syscall is journaled as an intent before it runs and a
  completion before the guest observes it, hash‑chained per session. Retries fork
  the journal copy‑on‑write; a failed process resumes right after its outermost
  open `sys.begin` savepoint.
- **Rollback** — a guest registers undo with `sys.compensate` and unwinds with
  `sys.abort{reason, retry_seconds}`; compensations run newest‑first, journaled and
  idempotency‑keyed, then the section retries after the delay or finishes as
  `compensated`.
- **Approval** — a yielded syscall becomes a durable task with its intent left
  open; resolving it re‑drives the intent under its original idempotency key.
- **Scheduling** — root processes are quanta of a fair‑share scheduler; delegated
  children run inside their parent's quantum so delegation can't deadlock.

## Configuration (the injected `Config`)

No env vars, no files, no ports — everything is the injected struct.

- **Required:** `Dispatchers`, `Log`, `Leases`, `ProcessTable`, `TaskSecret`
  (non‑empty). `Programs` may be nil (empty registry).
- **Optional knobs:** `TenantID`, `InstanceID`, `EventSize` (default 32),
  `TaskTTL` (24h), `LeaseTTL` (1h), `MaxConcurrentProcesses` (16),
  `MaxResidentProcesses` (64), `MaxAbortRetries` (10),
  `ProcessMemoryPages` (4096 = 256 MiB), `ResumeQuantumTimeout` (2 min),
  `QuotaOf` (per‑tenant quotas).
- **Key constants:** `ManifestVersion = 4`, `DefaultProgramID = "aurora-default@1"`.

Concrete stores (in‑memory, SQLite) live in
[aurora-dist](https://github.com/aurora-capcompute/aurora-dist); this module's tests
carry local doubles.

## Project layout

```
aurora/                 the PUBLIC API — import only this
  aurora.go             NewRuntime, ValidateManifest
  runtime.go            the Runtime interface (sessions, processes, tasks, reads)
  types.go              Config and re-exported types
internal/agent/         the runtime engine (Go's internal/ rule hides it)
  runtime.go            lifecycle + scheduler wiring
  manifest.go           the grant model + ValidateManifest
  program.go            program registry + JSON-Schema validation
  lifecycle.go          sys.input/output/log/compensate/abort
  delegation.go         sys.spawn (child agents)
  compensate.go         saga rollback execution
  restore.go            rebuild state by replaying event streams
  eventlog/             the append-only Log interface (no concrete store)
  host/                 per-process dispatcher stack over capcompute.Stack
  task/                 durable approval-task store + state machine
```

## Verification

```sh
go vet ./...
go test -race ./...
```

## Related repos

- [capcompute](https://github.com/aurora-capcompute/capcompute) — the kernel this runtime is built on
- [aurora-dispatchers](https://github.com/aurora-capcompute/aurora-dispatchers) — capability drivers you inject as `Dispatchers`
- [aurora-brains](https://github.com/aurora-capcompute/aurora-brains) — the Wasm agent programs that run inside
- [aurora-dist](https://github.com/aurora-capcompute/aurora-dist) — the assembly that turns this into a runnable server
- [aurora-cli](https://github.com/aurora-capcompute/aurora-cli) — the terminal client
