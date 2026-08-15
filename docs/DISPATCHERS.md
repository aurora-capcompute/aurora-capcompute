# Walkthrough: how a dispatcher is assembled, connected, run — and why nothing escapes it

This traces one capability, `core.internet`, from a line in a manifest to a TCP
connection, and then answers the harder question: what in the code makes it true
that a guest can do *nothing* except what its dispatchers do.

It spans three repos. Read [WALKTHROUGH.md](WALKTHROUGH.md) first if you want the
whole system; this is the one vertical slice.

| repo | role in this story |
|---|---|
| `capcompute` | the processor: the sandbox, the single host function |
| `aurora-capcompute` | the runtime: manifests, the monitor chain, the journal |
| `aurora-dispatchers` | the drivers: `internet`, `httptemplate`, `scratch`, `command`, `filesystem`, `openaillm` — plus `builtin`, the index they plug into |
| `aurora-dist` | the assembly: which drivers are compiled in at all |

---

## 0. The shape of the answer

A capability is not a function the guest calls. It is a **link in a chain that was
built before the guest started**, and the guest's only way to reach it is a single
wasm host function that takes one JSON envelope.

Four things must all be true for a call to happen, and each is enforced in a
different place by different code:

1. the driver was **compiled into the distribution** (`aurora-dist`),
2. the process's **manifest granted** that syscall (`aurora-capcompute`),
3. the assembled chain **advertises** it, and the Validator finds it in the grant
   set (`monitor`),
4. the driver's **own policy** admits this particular call (`aurora-dispatchers`).

Miss any one and the call fails closed.

---

## 1. Assembly — from a manifest grant to a driver

### 1.1 What a program asks for

A manifest is a list of grants. A leaf grant names a syscall and carries an opaque
config that only the driver behind it understands:

```json
{
  "program": "researcher@1",
  "syscalls": [
    { "syscall": "core.internet",
      "capabilities": [ { "domain": "api.example.com", "methods": ["GET"] } ] }
  ]
}
```

`Syscall.Config` is `json.RawMessage` — the runtime deliberately cannot read it
([manifest.go:96](../internal/agent/manifest/manifest.go:96)). Everything outside
`syscall` and `hidden` is the family's config.

`Manifest.LeafSyscalls()` ([manifest.go:161](../internal/agent/manifest/manifest.go:161))
splits the grants the runtime serves itself (`sys.input`, `sys.log`, `sys.timer`, …)
from the ones a driver must serve. Only the latter reach the provider.

### 1.2 What the distribution is willing to build

`aurora-dist` picks the registration set at compile time. `registry.Default()`
(`aurora-dispatchers/registry/registry.go`) is `InternetRegistration`
and `MemoryRegistration`; credentialed drivers like `openaillm` are added
explicitly by the assembly. **A driver that is not registered does not exist** —
there is no plugin path, no lookup by name at runtime, no dynamic loading.

A `Registration` is three methods:

```go
Matches(syscall string) bool
Normalize(syscall string, config json.RawMessage) (json.RawMessage, error)
Configure(ctx, config, services Services) (builtin.Contribution, error)
```

`InternetRegistration.Matches` is literally `syscall == internet.Capability`
(`aurora-dispatchers/registry/internet.go:75`).

### 1.3 Building the driver

`Configure` (`aurora-dispatchers/registry/internet.go:85`)
parses the grant's config into an `internet.Policy` — the (method, domain)
allowlist — builds a client bound to that policy, and appends **two** things to
the output:

- an `internet.Handler` — the thing that can actually make requests,
- one `sys.Capability{Name: "core.internet", InputSchema: …}` — the thing that
  *declares* it can.

That pairing is the whole trick, and §4.3 is where it pays off.

Note what happens at build time, not call time: host-held credentials are
resolved here (`buildInjections`), so a grant referencing a missing secret fails
when the process starts rather than mid-run. The guest never sees the values, and
an injection is bound to a specific https-or-loopback origin.

### 1.4 The leaf dispatcher

`provider.NewDispatcher` (`aurora-dist/internal/dist/provider.go:34`)
runs every matching registration and wraps the result:

```go
return builtin.New[aurora.ProcessContext](config), nil
```

`Configure` returns a `Contribution` — the discriminator property, one `Entry`
per case of the ADT, and the capability they add up to. It never sees the table;
`Registry.Build` folds every family's contribution into one
`map[Key]Entry`, refusing a duplicate `(syscall, operation)` rather than letting
the first one win. That is the **bottom** of the chain: there is nothing below
it.

One detail worth pausing on: the provider overwrites `services.SessionID`,
`ProcessID` and `Tenant` from the *credential*, never from the manifest
(`aurora-dist/internal/dist/provider.go:52`). A grant
cannot name another tenant's memory because the grant is not consulted about
identity at all.

---

## 2. Connection — building one process's chain

This happens once per quantum, in `host.Factory.NewDispatcher`
([host.go:109](../internal/agent/host/host.go:109)).

### 2.1 The runtime's own layers

`Runtime.Drivers` ([runtime.go:271](../internal/agent/runtime.go:271)) asks the
provider for the leaf chain, then does the check that keeps the manifest
authoritative:

```go
if err := reconcileGrants(base.Capabilities(), spec); err != nil {
    return nil, err
}
```

`reconcileGrants` ([runtime.go:120](../internal/agent/runtime.go:120)) fails closed
if the provider advertises a capability the manifest did not grant. Without it a
buggy or hostile provider could widen a process's authority past its manifest —
the confused-deputy gap. Under-advertising is fine (the guest just can't call it);
over-advertising is refused.

Then `sys.timer` is layered on if granted, and the `progressDispatcher` (serving
`sys.log`) wraps the result.

### 2.2 The full stack

`monitor.Stack.ForProcess` ([stack.go:42](../monitor/stack.go:42)) assembles the
canonical order — in code, not prose, so it cannot be got wrong by hand:

```
Validator → FlowMonitor → [replay tape] → Labeler → Declassifier → drivers
```

Above the replay boundary sit decisions that must re-derive identically on every
pass and never enter the journal (validation, flow denials). Below it sit
outcomes that must be journaled exactly once (stamped labels, approved
declassifications).

`drivers` there is itself a stack, built by the Factory before it hands the whole
thing to `ForProcess`. Written out once, innermost last, this is what a syscall
actually walks:

```
Validator            grant lookup + input schema      ← denies here
FlowMonitor          taint vs. the grant's Forbid set
replay (tape)        serve from journal, or journal the intent
Labeler              stamp result labels
Declassifier         approved label crossings
savepointDispatcher  sys.begin / sys.commit markers
worldDispatcher      sys.now / sys.random (journaled, so they replay)
wrapProtocol         sys.input / sys.output / sys.abort
task.Dispatcher      durable approval — yields, resumes on resolution
progressDispatcher   sys.log
timerDispatcher      sys.timer, if granted
builtin.Dispatcher   (syscall, operation) → entry; approval, then handler ← the bottom
```

Everything from `savepointDispatcher` down is below replay, so its outcomes are
journaled once and served from the tape thereafter — which is why an approval is
a durable fact rather than a question asked twice.

### 2.3 Where the grant set comes from

This is the line that makes §4.3 airtight
([host.go:160](../internal/agent/host/host.go:160)):

```go
stack := monitor.Stack[ID, K]{
    Grants: func(K) []sys.Capability { return withSavepoints.Capabilities() },
    ...
}
```

The Validator's grant set is **the assembled chain's own `Capabilities()`** — not a
list parsed from the manifest, not a config file. The set of what is permitted is
derived from the set of what was built. They cannot drift, because they are the
same value.

---

## 3. Run — one `core.internet` call

The guest calls the host function with `{"abi":4,"name":"core.internet","args":{"method":"GET","url":"https://api.example.com/x"}}`.

1. **`dispatchSyscall`** (`capcompute/host.go:39`)
   reads the bytes out of guest memory, decodes the envelope, and calls the
   dispatcher the processor was handed. It has no idea what `core.internet` is.
2. **Validator** ([validate.go:46](../monitor/validate.go:46)) looks the name up in
   the grant set. Not found → `ErrnoDenied`, and the driver is never reached. Found
   → the args are validated against the capability's `InputSchema` before anything
   downstream sees them.
3. **FlowMonitor** checks the call's taint against the grant's `Forbid` set — a
   tainted argument cannot reach a capability that forbids that label.
4. **replay tape** — if this syscall is already in the journal at this position, the
   recorded result is served and *the driver is never called again*. Otherwise the
   intent is journaled **before** the call (journal-before-execute).
5. **Labeler / Declassifier / task.Dispatcher** — below replay, so their outcomes are
   journaled once. An approval-gated call yields here and returns as a durable task.
6. **`builtin.Dispatcher`** reads the discriminator (`method` for `core.internet`)
   out of the args and indexes `(core.internet, "GET")`. A miss is a denial naming
   the granted operations; a hit whose entry requires approval yields here, below
   the tape, so the yield is journaled once.
7. **`internet.Handler.DispatchCall`** (`aurora-dispatchers/internet/handler.go:78`)
   resolves the per-method policy, attaches host-held credentials if the (method,
   host) matches an injection, and calls the client.
8. **`internet.Client.Do`** (`aurora-dispatchers/internet/internet.go:355`)
   re-checks `Policy.Check(method, target)` — the allowlist is enforced *here*, in the
   driver, not upstream — bounds the request body, and dials. The SSRF guard refuses
   at dial time if the resolved address is loopback/private/link-local/CGNAT, so an
   allowlisted public domain that resolves (or rebinds) to `169.254.169.254` still
   fails. Redirects are capped, and injected credential headers are stripped the
   moment a hop leaves their origin.

The result travels back up: journaled as a completion **before the guest observes
it**, labeled, and returned through the same host function.

---

## 4. Why nothing else is possible

Four independent walls. Each would have to fail for a guest to act outside its
dispatchers.

### 4.1 The guest has no ambient authority to begin with

The program is wasm on wazero. It has no syscalls of its own, no sockets, no file
descriptors — not because they are blocked, but because the host never provides
them.

`capcompute.NewProgram` (`capcompute/processor.go:149`)
refuses the image outright if it asks for any:

- non-empty `AllowedHosts` → `ErrAmbientAuthority` ("network access must be a
  dispatched capability")
- non-empty `AllowedPaths` → `ErrAmbientAuthority`
- `memory.max_pages` set by the image → `ErrImageMemoryOverride`, because the memory
  cap is the host's to set, and an image that sets it last would silently win

Guest module config is host-owned and not caller-supplied: `guestModuleConfig()`
pins a deterministic clock and a fixed-seed RNG, and passes no env. So even the
guest's notion of *time* is not ambient — it is a pinned sequence that replays
identically.

### 4.2 There is exactly one door

The processor registers a single host function, named `syscall`, in the
`extism:host/compute` namespace — `hostFunction()`
(`capcompute/host.go:26`).
One import, one signature (`ptr → ptr`), one JSON envelope in and out.

There is no second entry point, no shared memory region the host writes to, and
no callback the guest can register. The entire host surface is that function.

### 4.3 The door is deny-by-default, and the grant set cannot be forged

The Validator ([validate.go:46](../monitor/validate.go:46)) is the reference
monitor. Its rule is: if `FindCapability(grants(cred), syscall.Name)` misses,
`ErrnoDenied`. Not an error, not a passthrough — a denial the guest observes as a
failed syscall.

Three properties make that hold:

- **The grant set is derived, not declared.** `Grants` returns
  `withSavepoints.Capabilities()` — the assembled chain's own advertisement
  ([host.go:160](../internal/agent/host/host.go:160)). Nothing can be in the grant
  set that is not in the chain.
- **The chain cannot exceed the manifest.** `reconcileGrants`
  ([runtime.go:120](../internal/agent/runtime.go:120)) refuses to build a process
  whose provider advertised more than the manifest granted.
- **The credential is host-side.** `ProcessContext` is passed by the runtime into
  `Resume` and never crosses into guest memory
  (`capcompute/processor.go:63`).
  A guest cannot name another process's identity because it cannot name its own.

Note the two exemptions at [validate.go:47](../monitor/validate.go:47): `sys.begin`
and `sys.commit` bypass the grant lookup. They are savepoint markers that reach no
driver and perform no effect.

### 4.4 The grant is narrower than the capability

Being granted `core.internet` does not grant *the internet*. Two things narrow it,
both after the Validator has said yes:

- **The entry.** Only the `(syscall, operation)` pairs the manifest granted are in
  the table, so a method outside the grant is denied by absence.
- **The driver.** `internet.Client.Do` re-checks the (method, domain) allowlist at
  `aurora-dispatchers/internet/internet.go:364` and applies the SSRF guard at dial
  time. A driver may narrow, never widen.

Flow policy and approval are *not* the driver's: they ride the entry, are
published on the capability, and are enforced by the monitor above the tape and
by `builtin.Dispatch` below it. What a driver still stamps is provenance that is
not a property of the case — a stored value's own labels, or which credential
injection matched.

### What this does *not* guarantee

Worth stating plainly, so the guarantee isn't over-read:

- **A driver's own bugs are in scope.** The chain guarantees a guest reaches only
  `core.internet`; it does not guarantee `internet.Client` is correct. That is why
  the SSRF guard, redirect cap and credential-stripping live in the driver and are
  tested there.
- **The host process is trusted.** Nothing here defends against the Aurora binary
  itself being compromised.
- **The log is not tamper-evident.** The journal's hash chain was removed
  (2026-08-15). A durable store that rewrites a record in place will not be
  detected; `journaled.Verify` now checks structure only.
- **Denial of service is bounded, not prevented.** Memory is capped per process and
  a quantum has a wall-clock deadline, but a guest can still burn its whole budget.

---

## 5. Where to look

| question | file |
|---|---|
| what grants exist | `internal/agent/manifest/manifest.go` |
| which drivers are compiled in | `aurora-dispatchers/registry/registry.go` |
| how a driver is built | `aurora-dispatchers/registry/internet.go` |
| what a driver's handler does | `aurora-dispatchers/internet/handler.go` |
| how the leaf chain is assembled | `aurora-dist/internal/dist/provider.go` |
| how one process's chain is built | `internal/agent/host/host.go` |
| the chain's order | `monitor/stack.go` |
| deny-by-default | `monitor/validate.go` |
| the sandbox | `capcompute/processor.go`, `capcompute/ambient.go` |
| the one host function | `capcompute/host.go` |

## 6. How it is verified

Each wall has a test that fails if it comes down:

- **4.1** — `capcompute`'s integration tests: an image declaring `allowed_hosts` or
  `allowed_paths` is refused; an infinite guest is stopped at its deadline.
- **4.3** — `monitor/validate_test.go`: `TestValidatorDeniesUngrantedCapability`,
  `TestValidatorRejectsArgsFailingInputSchema`, and
  `TestValidatorPassesReservedSyscallsWithoutGrant` (the `sys.begin`/`sys.commit`
  exemption is deliberate, not an oversight).
- **4.3** — `internal/agent/reconcile_test.go`:
  `TestProcessDriversRejectsOverAdvertisingProvider`, and its twin admitting a
  faithful one.
- **the order** — `monitor/stack_test.go`: `TestStackEnforcesCanonicalOrder`, plus
  `monitor/provenance_test.go`, where tainted arguments stay denied across a crash
  and a replay.
- **4.4** — `aurora-dispatchers/internet/handler_test.go` and `inject_test.go`: the
  sink guard, approval, and that a host-held credential is never guest-readable or
  overridable. `internet/internet_test.go`: disallowed domain and
  method, non-HTTP scheme, redirect to a disallowed domain, redirect count cap,
  request/response byte limits, private-network and CGNAT dial guards, and
  `TestInjectedCredentialStrippedOnCrossOriginRedirect`.
