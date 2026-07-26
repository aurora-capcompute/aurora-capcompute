// Package errs is the runtime's error taxonomy: the three sentinels every layer
// classifies a failure by, in one place because they are shared vocabulary
// rather than any single package's own. A caller decides what to do from these
// — retry, refuse, report — so they must be the same values wherever the failure
// is raised: the program registry, the manifest validator, and the session and
// process state machine all wrap them, and errors.Is answers across all three.
package errs

import "errors"

var (
	// NotFound is a named thing that does not exist: an unknown session,
	// process, or task id.
	NotFound = errors.New("not found")
	// Conflict is a request that is well-formed but disallowed by the current
	// state: resuming a process whose program changed underneath it, registering
	// a program id that is taken, renaming a session to a handle in use.
	Conflict = errors.New("lifecycle conflict")
	// Invalid is a request that is malformed on its own terms, independent of
	// state: a manifest granting an unserved capability, a program missing its
	// wasm bytes, an input its program's schema rejects.
	Invalid = errors.New("invalid request")
)
