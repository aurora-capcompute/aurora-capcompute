# aurora-capcompute

`aurora-capcompute` is the Go runtime that turns the
[`capcompute`](https://github.com/aurora-capcompute/capcompute) processor into an
agent runtime. It runs Wasm agent programs as **processes** inside
**sessions**. It journals every syscall, so a process resumes after a crash, and
it parks a call that needs a human on a durable task.

To run Aurora, use [aurora-dist](https://github.com/aurora-capcompute/aurora-dist).
This repo is the library that the server is built from.

## What it owns

- **Sessions and processes:** create, stop, retry, rename, and one read of the
  whole session.
- **The journal and replay:** each syscall is an intent record before it runs
  and a completion record before the guest sees the result.
- **Savepoints and abort:** `sys.begin`/`sys.commit` bracket a section.
  `sys.abort`, or a failure inside an open section, runs the section again.
- **Tasks:** an approval or a timer becomes a durable task. A sweep fires timers,
  expires old approvals, and wakes parked processes.
- **The reference monitor:** grants, argument schemas, flow labels,
  declassification.
- **Scheduling:** a fixed worker pool with a deadline per quantum.

There is no table of mutable rows. All durable state is a fold of one
append-only event stream per session.

The module ships interfaces and orchestration only. Drivers, stores, HTTP and
connectors come from the assembly (aurora-dist).

```
   aurora-cli / aurora-slack-connector      clients
              │  HTTP /v1
         aurora-dist                         the server binary
              │
   ┌──────────┴──────────┐
 aurora-capcompute    aurora-dispatchers     runtime (this repo) + drivers
   └──────────┬──────────┘
         capcompute                          the processor

   aurora-brains                             the Wasm programs that run inside
```

## Use

```go
runtime, err := aurora.NewRuntime(ctx, aurora.Config{
    Dispatchers: provider,   // builds each process's grant table (aurora-dispatchers)
    Programs:    programs,   // Wasm bytes + interface, compiled once at boot
    Log:         eventLog,   // the append-only event store
    TaskSecret:  taskSecret, // keys the task resolution tokens
})
if err != nil {
    return err
}

sess, _ := runtime.CreateSession("", nil)
proc, _ := runtime.CreateProcess(sess.ID, input, manifest) // manifest version 4
read, _ := runtime.GetSession(sess.ID)                     // journals and tasks
// runtime.ResolveTask(...) when a human approves a pending task.
```

- A **program** is its Wasm bytes plus its interface: a description and JSON
  Schemas for its input and its answer. Its identity is a SHA-256 digest of all
  three. A process is bound to that digest for life and never runs under
  changed code. The runtime checks the input at `CreateProcess` and the answer
  at `sys.output`.
- A **manifest** grants syscalls. The runtime reads only `syscall` and `hidden`
  of each grant. Every other key is the driver's configuration.
- A **dispatcher provider** builds the grant table for each process. The runtime
  refuses a table that offers more than the manifest granted.

## Config

| Field | Default | Meaning |
| --- | --- | --- |
| `Dispatchers` | required | Builds each process's grant table |
| `Log` | required | The event log |
| `TaskSecret` | required | Keys task resolution tokens |
| `Programs` | none | Compiled at boot. To change a program, restart. |
| `Now` | `time.Now` | The clock |
| `TaskTTL` | 24h | When an unanswered approval expires |
| `MaxConcurrentProcesses` | 16 | Worker pool size |
| `QuantumDeadline` | 2 min | Wall-clock bound on one quantum |

Fixed bounds: 256 MiB of guest memory, and at most 10 aborts of a section. The
manifest version is 4.

## Docs

- [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md): the dispatcher chain, the
  replay boundary, a crash and an approval, the event-log fold.
- [`docs/DISPATCHERS.md`](docs/DISPATCHERS.md): one capability from a manifest
  line to a TCP connection, and why a guest can do nothing else.
- [capcompute `docs/ARCHITECTURE.md`](https://github.com/aurora-capcompute/capcompute/blob/main/docs/ARCHITECTURE.md):
  the OS model and its laws.

## Layout

```
aurora/            the public API: NewRuntime, Runtime, re-exported types
capability/        the grant table, routing, approval prompts
monitor/           Validator, flow labels, Declassifier, Wrap (the chain order)
replay/            serve from the tape, or journal intent → run → completion
journaled/         the tape over a journal; Verify
sim/               crash-at-every-append simulation tests
internal/agent/    the runtime
  dispatcher.go    builds one process's chain
  executor.go      one quantum
  pool.go          the worker pool
  programs.go      program compile, schemas, identity
  lifecycle.go     sys.input, sys.output, sys.abort
  abort.go         section re-run
  restore.go       rebuild state from the event streams
  task/            the durable approval layer
  manifest/        the grant model
  eventlog/        the Log interface
```

## Test

```sh
go vet ./...
go test -race ./...
```

The runtime tests build the `agent` program from a sibling `aurora-brains`
checkout with `cargo build --release --target wasm32-wasip1`. They skip when
`cargo` is not installed.
