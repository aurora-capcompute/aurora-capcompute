package agent

import "github.com/aurora-capcompute/aurora-capcompute/internal/agent/direct"

type ProgramID string

func (p ProgramID) String() string { return string(p) }

// ProgramData is a program as an app hands it over: the wasm bytes and the
// interface that ships beside them — a one-line description plus the JSON Schema
// documents of its input message and its answer. Conversational programs declare
// `{"type":"string"}`; structured programs declare object schemas.
type ProgramData = direct.Data[ProgramID]

// Program is a registered program as a caller may see it.
type Program = direct.View[ProgramID]
