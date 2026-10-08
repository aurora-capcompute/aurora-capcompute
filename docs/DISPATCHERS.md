# Dispatchers: from a manifest line to a connection

This document follows one capability, `core.internet`, from a manifest grant to
a TCP connection. Then it shows what in the code makes a guest unable to do
anything except what its dispatchers do. [WALKTHROUGH.md](WALKTHROUGH.md)
covers the whole system. This is one vertical slice.

| Repo | Role here |
|---|---|
| `capcompute` | the processor: isolation and the one host function |
| `aurora-capcompute` | the runtime: manifests, the monitor chain, the journal, and `capability`, the table drivers plug into |
| `aurora-dispatchers` | the drivers (`internet`, `httptemplate`, `scratch`, `command`, `openaillm`) and `registry`, which builds them |
| `aurora-dist` | the assembly: which drivers exist at all |

## The answer in short

A capability is not a function the guest calls. It is a link in a chain that
the runtime builds before the guest starts. The guest reaches it only through
one host function that takes one JSON envelope. A call happens only when all
four of these hold, each in different code:

1. The driver is compiled into the distribution (aurora-dist).
2. The process's manifest grants the syscall (aurora-capcompute).
3. The grant table has the call's operation, and the Validator admits it
   (`monitor`).
4. The driver's own policy admits this call (aurora-dispatchers).

If any one fails, the call fails closed.

## 1. Assembly

### The grant

A manifest is a list of grants. A grant names a syscall and carries a
configuration that only its driver reads:

```json
{
  "version": 4,
  "program": "researcher",
  "syscalls": [
    { "syscall": "core.internet",
      "capabilities": [ { "domain": "api.example.com", "methods": ["GET"] } ] }
  ]
}
```

`manifest.Syscall.Config` is raw JSON. The runtime reads only `syscall` and
`hidden`. `Manifest.LeafSyscalls()` separates the grants the runtime serves
itself (`sys.timer`, `sys.declassify`) from the grants a driver serves. Only
the second kind reaches the provider.

### The registrations

aurora-dist lists its registrations at compile time (`newProvider` in
`internal/dist/dist.go`): `internet`, `httptemplate`, `command`, `openaillm`,
and `scratch`, which it builds for each process over that session's store.
A driver that is not registered does not exist. There is no plugin path and no
lookup by name at run time.

A registration has two methods:

```go
Matches(syscall string) bool
Configure(ctx, config, services registry.Services) (capability.Family, error)
```

`internet.Registration.Configure` parses the grant into an `internet.Policy`
(the method and domain allowlist), builds one handler for it, and returns a
`capability.Family`: one `capability.Entry` per (method, domain) case. Each
entry carries its schema, labels, forbidden labels, approval flag and handler.
The table indexes entries, and a handler is reached only through an entry. So
what a call may do is a property of the table, not of the handler code.

Secrets resolve at build time. A grant that names a missing secret fails when
the process starts, not in the middle of a run. The guest never sees the value,
and an injected credential is bound to one https (or loopback) origin.

`registry.Services` carries only the secret resolver and the audit key. It has
no identity, so a grant cannot name another session's data.

### The table

`provider.NewDispatcher` (aurora-dist `internal/dist/provider.go`) gives every
leaf grant to `Registry.Build`, which runs the matching registration and adds
each family to one `*capability.Table`. `Table.Add` refuses a duplicate
(syscall, operation) instead of letting the first one win.

## 2. Connection: one process's chain

`Runtime.newDispatcher` (`internal/agent/dispatcher.go`) builds the chain once
per quantum. First it asks the provider for the grant table and checks it:

```go
if err := reconcileGrants(table.Descriptors(), spec); err != nil {
    return nil, err
}
```

`reconcileGrants` fails closed when the provider offers a capability that the
manifest did not grant. Without it, a faulty provider could widen a process's
authority (the confused-deputy gap). Offering less than the grant is allowed.

Then the runtime builds the routing dispatcher from that table, stacks its own
layers on it, and calls `monitor.Wrap(r.taints, tape, table, chain)`. The full
order is in [WALKTHROUGH.md](WALKTHROUGH.md#the-chain).

### One table for both questions

The Validator's grant set **is** the process's grant table: not a list from the
manifest, and not a second copy. The routing dispatcher is built from the same
table. Each runtime layer that serves a syscall of its own adds that syscall to
the table as it is built (`sys.now` and `sys.random` in `newWorldDispatcher`,
`sys.log` in `newProgressDispatcher`, `sys.timer` in `newTimerDispatcher`, the
agent protocol in `newLifecycleDispatcher`). So what is permitted and what was
built cannot drift apart.

A layer **reserves** its syscall: it is admitted and on the menu, but it routes
to no entry. A layer that fails to catch its own syscall lets it fall to the
routing dispatcher, which denies it.

## 3. Run: one `core.internet` call

The guest sends
`{"abi":4,"name":"core.internet","args":{"method":"GET","url":"https://api.example.com/x"}}`.

1. **The host function** (`capcompute/host.go`) reads the envelope from guest
   memory and calls the process's chain. It does not know what `core.internet`
   is.
2. **Validator** (`monitor/validate.go`): a name outside the table gets
   `denied`. Arguments that fail the entry's schema get `invalid_args`.
3. **Flow.Guard**: the process's taint against the entry's forbidden labels.
4. **Replay**: a recorded call is served from the tape, and the driver is not
   called. Else the intent is journaled first.
5. **The layers below replay** pass the call on. A layer that yields becomes a
   durable task.
6. **`capability.Dispatcher`** reads the operation (`method` for
   `core.internet`) and finds `(core.internet, GET)`. A miss is a denial that
   names the granted operations. An entry that requires approval yields here.
7. **`internet.Handler`** applies the method's policy, adds a host-held
   credential if the origin matches an injection, and calls the client.
8. **`internet.Client.Do`** checks the allowlist again, bounds the request body,
   and dials. The dial guard refuses loopback, private, link-local and CGNAT
   addresses, so an allowlisted domain that resolves to `169.254.169.254` still
   fails. Redirects are capped, and an injected credential is removed when a
   redirect leaves its origin.

The result goes back up. It is journaled as a completion before the guest sees
it, and it carries its labels.

## 4. Why nothing else is possible

Four independent walls. All four must fail for a guest to act outside its
dispatchers.

### 4.1 No ambient authority

The program is Wasm on wazero. It has no syscalls, sockets or file descriptors,
because the host never gives it any. `capcompute.NewProgram` refuses an image
that asks:

- `AllowedHosts` or `AllowedPaths` not empty: `ErrAmbientAuthority`.
- `memory.max_pages` set by the image: `ErrImageMemoryOverride`. The memory cap
  is the host's.

The processor builds the guest module config. It sets a deterministic clock and
random source and no environment. So even time is not ambient.

### 4.2 One door

The processor registers one host function, `syscall` in the
`extism:host/compute` namespace. One import, one signature, one JSON envelope in
and out. There is no second entry point, no shared memory that the host writes,
and no callback.

### 4.3 Deny by default, and no forged grants

The Validator denies any name that `table.Descriptor` does not find. The guest
sees a failed syscall. Three facts keep this true:

- The grant set is the table that the chain was built from.
- `reconcileGrants` refuses a table that exceeds the manifest.
- The credential (`ProcessContext`) is host-side and never enters guest memory.
  A guest cannot name another process, because it cannot name its own.

`sys.begin` and `sys.commit` skip the grant lookup. They are markers that reach
no driver and have no effect.

### 4.4 The grant is narrower than the capability

A grant of `core.internet` does not grant the internet. Two things narrow it
after the Validator:

- **The entry.** Only the granted (syscall, operation) pairs are in the table.
  A method outside the grant is denied because it is absent.
- **The driver.** The client checks the allowlist again and guards the dial. A
  driver can narrow a grant, never widen it.

Flow policy and approval belong to the entry, not the driver. The monitor
enforces them above the tape, and `capability.Dispatcher` below it. A driver
adds only provenance that the entry cannot know, such as a stored value's own
labels or which credential matched.

### What this does not guarantee

- **Driver bugs are in scope.** The chain guarantees that a guest reaches only
  `core.internet`, not that `internet.Client` is correct. So the dial guard,
  the redirect cap and credential removal live in the driver, with tests there.
- **The host process is trusted.** Nothing here defends against a compromised
  Aurora binary.
- **What a host command does is not confined.** `core.command` controls the
  command line, not the binary's behavior after it starts. See capcompute's
  ARCHITECTURE, *Host commands*.
- **The journal is not tamper-evident.** A store that rewrites a record is not
  detected. `journaled.Verify` checks structure only.
- **Denial of service is bounded, not prevented.** Memory is capped and a
  quantum has a deadline, but a guest can use all of its budget.

## Where to look

| Question | File |
|---|---|
| the grants | `internal/agent/manifest/manifest.go` |
| which drivers exist | aurora-dist `internal/dist/dist.go` |
| how a driver is built | aurora-dispatchers `internet/registration.go` |
| the table and the routing dispatcher | `capability/capability.go` |
| what a handler does | aurora-dispatchers `internet/handler.go` |
| how leaf grants become a table | aurora-dist `internal/dist/provider.go` |
| one process's chain | `internal/agent/dispatcher.go` |
| the chain order | `monitor/stack.go` |
| deny by default | `monitor/validate.go` |
| isolation | capcompute `processor.go`, `ambient.go` |
| the host function | capcompute `host.go` |

## Tests for each wall

- **4.1:** capcompute's integration and adversary tests. An image with
  `allowed_hosts` or `allowed_paths` is refused, and a looping guest stops at
  its deadline.
- **4.3:** `monitor/validate_test.go` (`TestValidatorRejectsArgsFailingInputSchema`,
  `TestValidatorPassesReservedSyscallsWithoutGrant`),
  `monitor/stack_test.go` (`TestWrapEnforcesCanonicalOrder`), and
  `internal/agent/reconcile_test.go` (`TestReconcileGrants`).
- **Flow across a crash:** `monitor/provenance_test.go`
  (`TestFlowTaintSurvivesCrashReplay`).
- **4.4:** aurora-dispatchers `internet/handler_test.go`, `inject_test.go` and
  `internet_test.go`: disallowed domains and methods, non-HTTP schemes,
  redirects, byte limits, the dial guards, and
  `TestInjectedCredentialStrippedOnCrossOriginRedirect`.
