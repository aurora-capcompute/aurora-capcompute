# Walkthrough: how aurora-capcompute works

A guided tour of the system from the bottom (the processor) to the top (the
public API), meant to be read once, start to finish, so that the code is
navigable afterwards.

This is the *deep* tour. The [README](../README.md) is the orientation, and
[capcompute's `docs/ARCHITECTURE.md`](https://github.com/aurora-capcompute/capcompute/blob/main/docs/ARCHITECTURE.md)
is the OS model and its five invariants. Neither is repeated here.

---

## Two spines

Almost every confusion about this codebase comes from mixing up two structures
that run along different axes. Learn them separately and the rest falls out.

**Spine 1 — the dispatcher chain (the request path).** One syscall from a guest
travels down a fixed stack of decorators and its result travels back up. Every
security, durability, and protocol behaviour is a layer on that stack. Order is
the design.

**Spine 2 — the event-log fold (the state model).** There is no mutable row
store. All durable runtime state — sessions, processes, tasks — is a
*projection* folded from one append-only event stream per session. Restart
replays the streams and rebuilds the projections.

Spine 1 is what happens during a syscall. Spine 2 is what is true between them.

---

## Layer 0: capcompute, the processor

capcompute is deliberately small, and knowing where its responsibility *stops*
is most of what you need:

- `NewProgram` compiles a Wasm image and refuses ambient authority (no allowed
  hosts or paths).
- `NewProcess` instantiates a process — explicit input, credential, and
  dispatcher; nothing inherited.
- `Resume` gives a process the CPU for one cooperative quantum, until it
  completes, yields, fails, or is stopped.
- One host function is the only way out of the sandbox. `Resume` plants a
  dispatch closure — already bound to that process's credential and dispatcher
  — in the call context, so the gate serves exactly the process holding the CPU.
- The WASI clock and RNG are pinned so a fresh instance observes the identical
  sequence. That is what makes replay exact.

**capcompute does *not* own** the journal, replay, the monitor chain,
scheduling, approval, sessions, or retries. Every one of those lives in *this*
repo. If you remember one boundary, remember that one.

The shared vocabulary lives in capcompute's `sys` package and is the whole
interface between the two repos:

```go
type Dispatcher[K any] interface {
    Dispatch(ctx context.Context, cred K, syscall Syscall, auth Authorization) (SyscallResult, error)
    Capabilities() []Capability
}
```

`cred` is *who* is calling (host-side, never guest-supplied), `syscall` is
*what* is asked, `auth` is *what has been granted for this specific call*. A
`SyscallResult` is one of `result`, `yield`, or `failed` — a failure is a
classified errno the guest can react to, not a crash.

---

## Spine 1: the chain

Everything in this repo is a `Dispatcher` that wraps another `Dispatcher`. The
architecture *is* the nesting order, which is why it is assembled in code and
never by hand — `monitor/stack.go` and `internal/agent/host/host.go` own it.

Outermost (first to see a syscall) to innermost:

```
Validator            grants + arg schemas                  ┐ above replay:
FlowMonitor          taint vs. declared Forbid             ┘ re-derived every pass, never journaled
─────────────────────────────────────────────────────────── the replay boundary
replay.Dispatcher    serve from tape, or intent→run→completion
───────────────────────────────────────────────────────────
Labeler              stamps provenance on results          ┐ below replay:
Declassifier         sys.declassify                        │ journaled once,
savepoints           sys.begin / sys.commit                │ served from the tape
world                sys.now / sys.random                  │ thereafter
lifecycle            sys.input / sys.output / sys.compensate / sys.abort
spawn router         sys.spawn            (only when granted)
task                 durable approval
progress             sys.log
timer                sys.timer            (only when granted)
application drivers  the actual capabilities
```

### Why the replay boundary is where it is

This is the single most load-bearing decision in the repo, and `stack.go`
states it plainly: layers **above** replay must re-derive their decision
identically on every pass and must never enter the journal; layers **below**
replay produce outcomes that must be journaled exactly once and served from the
tape thereafter.

So validation and flow denials sit above: they follow from the grant set and the
current taint, so a replay reaches the same verdict without recording anything.
Stamped labels and approved declassification crossings sit below: they are
facts about what happened, they belong in the audit trail, and they need the
tape's idempotency keys.

Put one layer on the wrong side and you silently break a law. That is precisely
why `Stack.ForProcess` exists and why nothing assembles this by hand.

### The layers, in one line each

- **`monitor.Validator`** — complete mediation. The syscall name must be in the
  cred's grant set (else `denied`) and the args must validate against the
  capability's `InputSchema` (else `invalid_args`). Refusals are results, not
  errors: the guest sees an errno and continues.
- **`monitor.FlowMonitor` + `Taints`** — information-flow control. A process
  accumulates taint from every label it observes; a capability declaring
  `Forbid` refuses when the process is carrying a forbidden label. Because the
  guest is opaque, flow is judged conservatively: once observed, anything the
  process emits may derive from it.
- **`replay.Dispatcher`** — the durability core. If the tape already has this
  syscall recorded, serve the recorded result and never touch a driver.
  Otherwise: append an **intent**, dispatch, append a **completion**, then let
  the guest see it. That ordering is two invariants —
  *journal-before-execute* and *journal-before-observe*.
- **`journaled.Tape` / `Journal`** — where the tape lives. Records are a fixed
  envelope (position, kind, `prev_hash`) plus an opaque payload, hash-chained
  for tamper evidence. A `Header` (ABI version, program digest, process) makes
  replay refuse a journal written by a different writer up front, rather than
  failing later as a confusing divergence. `journaled.Verify` runs the chain
  check *before* any record is served, so tamper-evidence is fail-closed.
- **`monitor.Labeler`** — stamps `syscall:<name>` plus the capability's declared
  source classes onto every result. Sitting below replay means provenance lands
  in the journal for free.
- **`monitor.Declassifier`** — serves `sys.declassify`, the explicit,
  approved crossing of a label boundary. Journaled, because an approved crossing
  is a fact, not a re-derivable decision.
- **savepoints** — serves `sys.begin` / `sys.commit` with a constant
  side-effect-free result, so replay matching stays deterministic. Above the
  task and routing layers so a marker never becomes a human task.
- **world** — serves `sys.now` and `sys.random`. Below replay, so the values are
  journaled once and replay verbatim; this is what makes "the clock is a
  capability" true in practice.
- **lifecycle** — the program-facing protocol: `sys.input` (the run's payload
  plus history and the capability menu), `sys.output` (its answer),
  `sys.compensate`, `sys.abort`.
- **spawn router** — serves `sys.spawn` when the manifest grants it, routing to
  a delegated child. A child runs *inside its parent's quantum*, which is why
  delegation can never deadlock the scheduler's concurrency cap.
- **`task.Dispatcher`** — durable approval, described below.
- **progress / timer / drivers** — `sys.log` publishes a progress line to live
  subscribers; `sys.timer` yields and becomes a durable timer task; the drivers
  are the application's actual capabilities and are injected, never owned here.

Note that the runtime's own protocol calls are *granted explicitly* — they pass
the Validator like anything else — but are hidden from the program's discoverable
menu. There is no bypass lane.

---

## Trace 1: an ordinary syscall

A program calls a granted capability, say `core.memory.read`.

1. The guest encodes an ABI v4 JSON envelope and traps through capcompute's one
   host function. The processor unmarshals a `sys.Syscall` and calls the closure
   `Resume` planted — which is this process's chain.
2. **Validator**: is `core.memory.read` in this cred's grant set, and do the args
   match its schema? If not, a `denied`/`invalid_args` result goes straight back
   up. No driver is touched.
3. **FlowMonitor**: does this capability forbid any label the process is already
   carrying? If so, refused here.
4. **replay**: is this syscall the next recorded entry on the tape? On a first
   run it is not, so the tape appends an **intent** record and returns an
   idempotency key.
5. The call descends through the protocol layers to the driver, which does the
   real work.
6. On the way back up, **Labeler** stamps `syscall:core.memory.read` plus the
   capability's declared source classes onto the result.
7. **replay** appends the **completion** record — carrying those labels — and
   only then returns.
8. **FlowMonitor** observes the result's labels into the process's taint.
9. The result marshals back through the gate as JSON. The guest sees it.

The guest never observes an outcome that is not already durable. That is the
whole point of step 7 preceding step 9.

## Trace 2: a crash, and the resume

The host dies between steps 5 and 7 — the effect happened, the completion was
never written.

On restart the process is re-driven from the top: the program re-executes from
its entrypoint, and every syscall it repeats is served from the tape rather than
re-dispatched, so it fast-forwards through work already done. When it reaches
the position with an intent and no completion, the tape raises
`replay.OpenIntentError`, and the **open-intent policy** decides: retry under the
*original idempotency key* (the default — the driver can deduplicate), or
surface it for review. A capability declared non-idempotent can be routed to the
second answer.

This is why the intent carries an identity of `(process, revision, position,
call-hash)`. It is not just a marker that something started; it is the key a
driver uses to recognise the retry.

## Trace 3: an approval

A syscall needs a human. The driver returns `yield`.

The **task layer** catches it and turns the yield into a persisted task record
with an HMAC-derived token, leaving the replay intent *open*. The process parks;
the quantum ends; nothing holds a thread.

Later someone calls `ResolveTask` with the token and a resolution. The runtime
re-drives the process; replay fast-forwards to the open intent; and the task
layer replays the original syscall down the chain — this time with the stored
resolution as its `Authorization`. The driver now sees an approved call and does
the work, and the completion is journaled.

capcompute deliberately does not own this: the processor's gate always passes a
zero `Authorization`. Promoting a human decision into a dispatch is the
runtime's job, keyed by the intent the replay layer journaled.

---

## Spine 2: the event-log fold

Now the other axis. Between syscalls, what is true?

`internal/agent/eventlog` is a generic append-only log — domain-agnostic,
opaque payloads, one ordered stream per session. Everything durable the runtime
knows is a fold over those streams:

- session and process state (`store.go`, `snapshots.go`)
- tasks (`tasks.go`)
- the capability journal views (`journalview.go`, `callgraph.go`)

There is no mutable row store to drift out of sync, and no migration to write
when a projection changes shape. `restore.go` rebuilds in-memory state on
startup by replaying every stream from the beginning. Live watchers get the same
events through `Subscribe`.

Read the runtime this way and its file layout stops being arbitrary: `events.go`
defines what can be appended, `restore.go` folds it back, and the `*Locked`
helpers in `snapshots.go` project it into the immutable snapshots the public API
hands out.

---

## Rollback, revisions, and retries

Savepoints (`sys.begin`/`sys.commit`) are **redo scopes**: they can only
re-execute their contents, never undo them. Undo is separate, guest-authored,
and explicit.

Right after an effect, a guest registers its inverse with `sys.compensate` — a
deferred syscall journaled with concrete args but *not executed*. If the section
must be abandoned, the guest calls `sys.abort`. The runtime then walks the
registered compensations newest-first, each journaled as its own
intent/completion pair with an idempotency key, so a crash mid-rollback resumes
the rollback rather than restarting it. Replay refuses to run past a
compensation record (`ProcessUnwoundError`): a rolled-back tail never replays as
if live.

After unwinding, the abort's retry policy applies — fork the journal at the
section's begin and re-run after the declared delay, or finish as
`compensated`. A fork mints a new **revision**: forks are copy-on-write over the
journal, and the revision is part of the process identity (`pid@revision`), which
is what keeps a retried attempt's idempotency keys distinct from the attempt it
replaced.

`Retry` from the public API offers the same thing at a coarser grain:
`RetryResume` continues from where the journal stopped; `RetryRestart` starts a
fresh revision.

---

## Scheduling and residency

`internal/sched` decides *when* a process gets the CPU; the app decides *what*
runs (activation — typically journal replay); the processor decides *how*
(`Resume`). It is fair-share with strict priority bands, round-robin across
owners inside a band, and per-owner quotas applied as **backpressure, never
rejection**.

Residency is virtual-actor style: a process is activated on demand, kept warm
while it may wake again, and the least recently used idle process is deactivated
when residency exceeds its bound. Deactivation is cheap and safe because *the
journal, not the instance, is the durable process*.

Root processes are scheduler quanta. Delegated children are not — they run
inside the parent's quantum, so a parent waiting on a child cannot consume a
second concurrency slot and deadlock.

---

## The public surface

`aurora/` is a thin re-export of `internal/agent`. `aurora.Runtime` is the whole
API: sessions, processes, journal and call-graph reads, tasks, stop/retry, and
`Subscribe`.

The runtime owns no capabilities, dispatchers, stores, or channels. Programs,
dispatchers, the event log, leases, and the process table are injected through
`Config`. A shipping product is an *assembly* — a `main()` composing this runtime
with concrete stores, drivers, and whatever channels it speaks. `aurora-dist` is
that assembly.

---

## Where to look

| You want | Look at |
|---|---|
| the chain order and why | `monitor/stack.go`, `internal/agent/host/host.go` |
| complete mediation | `monitor/validate.go` |
| taint / flow policy | `monitor/provenance.go` |
| the replay protocol | `replay/replay.go` |
| the record format, hash chain | `journaled/tape.go` |
| rollback | `journaled/compensator.go`, `internal/agent/compensate.go` |
| what a quantum does | `internal/agent/execution.go` |
| state rebuilt after restart | `internal/agent/restore.go` |
| scheduling and residency | `internal/sched/sched.go` |
| the public API | `aurora/runtime.go` |

## How it is verified

The invariants are tested as invariants, not incidentally.

`sim/` is a deterministic simulation harness in the FoundationDB/Antithesis
style: it models the parts of the world that survive a crash — the journal and
the external effect store — drives a scripted guest through the full chain, and
injects a crash at *every* journal append position, asserting four things each
time: replay converges, effects happen exactly once under their idempotency
keys, the hash chain stays intact, and saga unwinding is correct.

The rollback matrices in `internal/agent` cover abort/retry/crash
interleavings. And capcompute's own adversarial suite builds a genuinely
hostile guest with the standard Go toolchain, proving the processor's isolation
and ABI boundary from the guest's side of the trap.
