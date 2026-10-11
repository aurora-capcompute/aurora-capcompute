# Walkthrough

A tour from the processor to the public API, and from a manifest grant to a
driver. Read it once, start to finish, and the code is easy to navigate after.
The [README](../README.md) is the overview, and
[capcompute's ARCHITECTURE](https://github.com/aurora-capcompute/capcompute/blob/main/docs/ARCHITECTURE.md)
is the OS model. This document does not repeat them.

## Two spines

Two structures run along different axes. Learn them separately.

1. **The dispatcher chain (the request path).** A syscall travels down a fixed
   stack of layers, and its result travels back up. Every security, durability
   and protocol behavior is one layer. The order is the design.
2. **The event-log fold (the state model).** There is no mutable row store.
   Sessions, processes and tasks are projections of one append-only event
   stream per session. A restart folds the streams again.

The chain is what happens during a syscall. The fold is what is true between
syscalls.

## Layer 0: the processor

capcompute does little, and its limits are most of what you need to know:

- `NewProgram` compiles a Wasm image and refuses ambient authority.
- `NewProcess` creates a process. Input, credential and dispatcher are
  explicit.
- `Resume` runs one quantum, until the guest completes, yields, fails or stops.
- One host function is the only way out. `Resume` binds it to the process's
  credential and dispatcher.
- The WASI clock and random source are deterministic, so replay is exact.

capcompute does **not** own the journal, replay, the monitor, scheduling,
approval, sessions or retries. This repo owns all of them. The interface
between the two repos is capcompute's `sys` package:

```go
type Dispatcher[K any] interface {
    Dispatch(ctx context.Context, cred K, syscall Syscall, auth Authorization) (SyscallResult, error)
}
```

`cred` is who calls (host-side only), `syscall` is what is asked, and `auth` is
what a human approved for this call. A result is `result`, `yield` or `failed`.
A failure is an errno that the guest can act on, not a crash.

## The chain

Every layer is a `Dispatcher` that wraps another. `internal/agent/chain.go`
builds the chain for each quantum, and `monitor.Wrap` (`monitor/stack.go`) owns
the part around the replay boundary. Outermost first:

```
Validator            grants + argument schemas       ┐ above replay: derived again
Flow.Track           the taint, and where it came from ┘ on every pass, never journaled
──────────────────────────────────────────────────────── the replay boundary
replay.Dispatcher    serve from the tape, or journal intent → run → completion
────────────────────────────────────────────────────────
Flow.Stamp           labels on results               ┐ below replay: journaled once,
savepoints           sys.begin / sys.commit          │ served from the tape after
world                sys.now / sys.random            │
lifecycle            sys.input / sys.output / sys.abort
task                 a yield from below → a durable task
progress             sys.log
timer                sys.timer
capability.Dispatcher  routes (syscall, operation) to an entry; approval,
                     also for a call the taint would cross
drivers              the application's capabilities
```

### Why the replay boundary is there

Layers **above** replay must reach the same decision on every pass, and they
never enter the journal. Validation follows from the grant set, and the taint
folds from the results, so replay reaches the same state without a record.
Layers **below** replay produce facts: stamped labels, approvals, times. Those
are journaled once and served from the tape after. A layer on the wrong side
breaks a law without a visible error. `monitor.Wrap` exists so that nobody
builds this order by hand.

### The layers

- **`monitor.Validator`**: the name must be in the grant table (else `denied`),
  and the arguments must pass the entry's schema (else `invalid_args`). A
  refusal is a result. The guest sees an errno and continues.
- **`monitor.Flow`**: one object with two decorators. `Flow.Track` (above
  replay) hands the process's taint down with each call, and adds every
  result's labels to it, with the call that produced them. The guest is
  opaque, so the taint never shrinks.
- **`replay.Dispatcher`**: if the tape has this syscall, it serves the recorded
  result and calls no driver. Else it appends an **intent**, dispatches, and
  appends a **completion** before it returns. That order is the two write-ahead
  laws.
- **`journaled.Tape`**: the record format. A record is a position and a kind
  plus an opaque payload. A journal belongs to one process, and the process is
  bound to one program digest. `journaled.Verify` checks the structure. The
  journal is not tamper-evident.
- **`Flow.Stamp`**: puts `syscall:<name>` and the entry's declared labels on
  every result, failures too. Below replay, so the labels are in the journal.
- **savepoints**: serves `sys.begin`/`sys.commit` with a constant result, above
  the task layer, so a marker never becomes a task.
- **world**: serves `sys.now` and `sys.random`. The values are journaled once
  and replay as recorded.
- **lifecycle**: `sys.input` (the input, history and capability menu),
  `sys.output` (the answer, checked against the program's schema) and
  `sys.abort`.
- **`task.Dispatcher`**: turns a yield from any layer below it into a durable
  task (see Trace 3).
- **progress, timer**: `sys.log` journals a progress line. `sys.timer` yields,
  and its task fires at its time.
- **`capability.Dispatcher`**: reads the operation from the arguments and
  routes to the entry. An entry that requires approval yields here, with a
  prompt that shows the call. So does a call whose entry forbids a label the
  process carries: its prompt also names the labels and the calls that
  produced them. The approval lets that one call through. The taint stays.

The runtime's own syscalls (`sys.input`, `sys.output`, `sys.log`, `sys.abort`)
pass the Validator like any other. They are hidden from the program's menu.
There is no bypass.

## Trace 1: an ordinary syscall

The guest calls `core.scratch` with operation `get`.

1. The guest sends an ABI v4 envelope through the host function. The processor
   decodes a `sys.Syscall` and calls this process's chain.
2. **Validator**: is `core.scratch` granted, and do the arguments match the
   schema? If not, a `denied` or `invalid_args` result goes back. No driver runs.
3. **Flow.Track** attaches the process's taint to the call.
4. **replay**: the tape has no record at this position, so it appends an intent.
5. The call goes down through the protocol layers to the driver.
6. **Flow.Stamp** labels the result.
7. **replay** appends the completion, with the labels, and only then returns.
8. **Flow.Track** adds the labels to the process's taint.
9. The guest receives the result.

The guest never sees an outcome that is not durable: step 7 comes before step 9.

## Trace 2: a crash

The host stops between steps 5 and 7. The effect happened, and the completion
was not written.

On restart the process runs again from its entrypoint. Each syscall it repeats
is served from the tape, so it moves fast through finished work. At the intent
with no completion, the tape returns `replay.OpenIntentError`, and replay runs
the call again. Effects are at least once: an effect that happened before the
crash happens again. Drivers get no idempotency key. The runtime promises only
this: a call runs again only when the crash fell between its execution and its
completion record.

## Trace 3: an approval

An entry requires approval, so `capability.Dispatcher` returns `yield` with a
prompt.

The **task layer** records a task with an HMAC-derived token and leaves the
replay intent open. The process parks as `waiting_for_task`. The quantum ends,
and no thread waits.

Later a client calls `ResolveTask` with the token and a decision. The runtime
resumes the process. Replay moves fast to the open intent, and the task layer
sends the original call down again, with the stored decision as its
`Authorization`. The driver now sees an approved call and does the work. The
completion is journaled.

A timer is the same path: `sys.timer` yields, and the sweep completes the task
at its time. An approval that nobody answers within `TaskTTL` expires, and the
guest gets errno `expired`. The sweep runs every second and wakes every process
that waits on a task that is no longer pending.

The processor always passes an empty `Authorization`. Turning a human decision
into a dispatch is the runtime's job.

## From a grant to a table

A manifest grant names a syscall and carries a configuration that only its
driver reads. `Manifest.LeafSyscalls()` separates the grants the runtime serves
itself (`sys.timer`) from the grants a driver serves. The
runtime serves the whole `sys.*` family to every process, so a manifest names
`sys.timer` only to tune it (its maximum duration, or `hidden`).

The assembly lists its driver registrations at compile time (in aurora-dist's
`dist.New`). A driver that is not registered does not exist: there is no
plugin path and no lookup by name at run time. A registration has two methods:

```go
Matches(syscall string) bool
Configure(ctx, config, services registry.Services) (capability.Family, error)
```

`Configure` parses the grant and returns a `capability.Family`: one entry per
case of the syscall (for `core.internet`, one per method and domain). Each entry
carries its schema, labels, forbidden labels, approval flag and handler. A
handler is reached only through its entry, so what a call may do is a property
of the table. Secrets resolve here, so a missing secret fails when the process
starts. `registry.Services` carries only the secret resolver and the audit key,
with no identity, so a grant cannot name another session's data.

`Registry.Build` adds each family to one `*capability.Table`. `Table.Add`
refuses a duplicate (syscall, operation). Then `newDispatcher` checks the table:

```go
if err := reconcileGrants(table.Descriptors(), spec); err != nil {
    return nil, err
}
```

`reconcileGrants` fails closed when the provider offers a capability that the
manifest did not grant. Offering less is allowed.

The Validator's grant set **is** this table, and the routing dispatcher is
built from the same table. Each runtime layer that serves its own syscall adds
it to the table as it is built (`sys.now` and `sys.random` in
`newWorldDispatcher`, `sys.log` in `newProgressDispatcher`, `sys.timer` in
`newTimerDispatcher`, the agent protocol in `newLifecycleDispatcher`). Such a
syscall is **reserved**: admitted and on the menu, but routed to no entry. A
layer that fails to catch its own syscall lets it fall to the routing
dispatcher, which denies it. So what is permitted and what was built cannot
drift apart.

## Why a guest can do nothing else

Four independent walls must all fail for a guest to act outside its grants:

1. **No ambient authority.** The guest is Wasm with no syscalls, sockets or file
   descriptors. `capcompute.NewProgram` refuses an image with `AllowedHosts` or
   `AllowedPaths` (`ErrAmbientAuthority`), or with its own memory cap
   (`ErrImageMemoryOverride`). The processor builds the module config, with a
   deterministic clock and random source and no environment.
2. **One door.** The processor registers one host function, `syscall` in the
   `extism:host/compute` namespace. There is no second entry point, no shared
   memory that the host writes, and no callback.
3. **Deny by default.** The Validator denies any name that the table does not
   have. The table is the one the chain was built from, `reconcileGrants` keeps
   it inside the manifest, and the credential never enters guest memory. A
   guest cannot name another process, because it cannot name its own.
   `sys.begin` and `sys.commit` skip the grant lookup: they reach no driver.
4. **The grant is narrower than the capability.** Only the granted (syscall,
   operation) pairs are in the table, so an ungranted method is denied by
   absence. The driver checks its own policy again: `internet.Client` checks
   the allowlist on every request and redirect, and its dial guard refuses
   loopback, private, link-local and CGNAT addresses after DNS. A driver can
   narrow a grant, never widen it.

Flow policy and approval belong to the entry, not the driver. A driver adds
only provenance that the entry cannot know, such as a stored value's own labels.

What this does **not** guarantee:

- **Driver bugs are in scope.** The chain guarantees that a guest reaches only
  `core.internet`, not that the internet client has no bugs. Its guards and
  their tests live in the driver.
- **The host process is trusted.** Nothing defends against a compromised
  Aurora binary.
- **A host command is not confined.** `core.command` controls the command line,
  not what the binary does. See the aurora-dispatchers README.
- **The journal is not tamper-evident.** `journaled.Verify` checks structure
  only.
- **Denial of service is bounded, not prevented.** Memory is capped and a
  quantum has a deadline, but a guest can use all of its budget.

## The event-log fold

`internal/agent/eventlog` is an append-only log with one ordered stream per
session and opaque payloads. All durable state is a fold of those streams:

- sessions and processes (`state.go`, `restore.go`, `snapshots.go`).
- tasks (`taskstore.go`).
- the journals (`journal.go`).

No row store can drift, and a projection that changes shape needs no
migration. `restore.go` folds every stream at boot. `durable/events.go` defines
what can be appended.

## Revisions and retries

`sys.begin`/`sys.commit` are **redo scopes**. A section can run again but is
never undone. A section that must be safe to run again is the program's
contract.

`sys.abort` abandons the open section. The runtime forks the journal at the
section's `sys.begin` and runs the section again, at most 10 times. With no
open section, the process fails. A fork makes a new **revision**. The fork is
copy-on-write over the journal, and the revision is part of the process's
identity (`ProcessContext{SessionID, ProcessID, Revision}`), so a retry never
continues the instance it replaced.

`Retry` offers the same at a coarser grain. `RetryResume` continues from where
the journal stopped. `RetryRestart` starts a fresh revision from position 0.

## Scheduling

The pool (`internal/agent/pool.go`) is a fixed set of workers. Each runs one
quantum to its end, then takes the next. The worker count is the concurrency
bound. A quantum (`runQuantum` in `executor.go`) checks that the process still
has its program, builds the chain, and resumes the guest.

The deadline starts when a worker takes the quantum, so queue time does not
count. The pool is first come first served, with no priorities or quotas.

There is **no residency**. Every quantum starts a fresh instance and releases it
at the end. A warm instance would keep guest state outside the journal. The
cost is one instantiation per quantum.

## The public surface

`aurora/` re-exports `internal/agent`. `aurora.Runtime` is the whole API:
sessions, processes, the session read, task resolution, stop and retry. The
runtime owns no drivers, stores or channels. An assembly (aurora-dist) injects
them.

## Where to look

| Question | File |
|---|---|
| the grants | `internal/agent/manifest/manifest.go` |
| the table and routing | `capability/table.go`, `capability/dispatcher.go` |
| which drivers exist | aurora-dist `internal/dist/dist.go`, `provider.go` |
| how a driver is built | aurora-dispatchers `internet/registration.go` |
| the chain order | `internal/agent/chain.go`, `monitor/stack.go` |
| complete mediation | `monitor/validate.go` |
| flow policy | `monitor/flow.go`, `monitor/taints.go`, `capability/dispatcher.go` |
| replay | `replay/replay.go` |
| the record format | `journaled/tape.go` |
| abort and re-run | `internal/agent/recovery.go` |
| one quantum | `internal/agent/executor.go` |
| restore after restart | `internal/agent/restore.go` |
| scheduling | `internal/agent/pool.go` |
| the public API | `aurora/runtime.go` |

## How it is tested

- `sim/` is a deterministic simulation harness. It models what survives a
  crash (the journal and an external effect store), runs a scripted guest
  through the chain, and crashes at every journal append. Each time it checks
  that replay converges, that an effect repeats only when the crash cut off its
  completion, and that the journal structure holds.
- The abort and savepoint tests in `internal/agent` cover abort, retry and crash
  orders.
- capcompute's adversary suite builds a hostile guest and tests the processor's
  isolation and ABI from the guest's side.
- The walls: `monitor/validate_test.go`, `monitor/stack_test.go`
  (`TestWrapEnforcesCanonicalOrder`), `internal/agent/reconcile_test.go`,
  `monitor/provenance_test.go` (`TestFlowTaintSurvivesCrashReplay`), and the
  aurora-dispatchers `internet` tests for allowlists, redirects, byte limits,
  dial guards and credential stripping.
